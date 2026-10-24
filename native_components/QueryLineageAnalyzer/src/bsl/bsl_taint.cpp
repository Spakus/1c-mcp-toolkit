#include "bsl/bsl_taint.h"

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "strict/check_query.h"

namespace lineage::bsl {

namespace {

using Json = nlohmann::json;

constexpr int kMaxPasses = 6;    // passes until the query parameters bound by the code are stable
constexpr int kMaxRounds = 10;   // walks of the whole body in one pass until the collection state is stable

bool IsAsciiLetter(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
bool IsDigit(char c) { return c >= '0' && c <= '9'; }

// A token starts at s[open] == '['; on success `end` is the index after its ']'.
bool TokenAt(const std::string& s, size_t open, size_t& end) {
    if (open >= s.size() || s[open] != '[') return false;
    size_t i = open + 1;
    const size_t letters = i;
    while (i < s.size() && IsAsciiLetter(s[i])) ++i;
    if (i == letters || i >= s.size() || s[i] != '-') return false;
    const size_t digits = ++i;
    while (i < s.size() && IsDigit(s[i])) ++i;
    if (i - digits < 5 || i >= s.size() || s[i] != ']') return false;
    end = i + 1;
    return true;
}

std::string AsciiUpper(std::string s) {
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

strict::ParamOrigin ParamOriginOf(Origin label) {
    switch (label) {
        case Origin::Open:
        case Origin::Client: return strict::ParamOrigin::Client;
        case Origin::ProtectedDirect: return strict::ParamOrigin::TokenProtected;
        default: return strict::ParamOrigin::TokenUnknown;
    }
}

using Params = std::map<std::string, strict::ParamOrigin>;   // spelling -> origin

Params ParamsOf(const LabelState& state, const Expr* site) {
    Params out;
    const auto it = state.params.find(site);
    if (it == state.params.end()) return out;
    for (const auto& kv : it->second) {
        for (const std::string& spelling : kv.second.spellings) out[spelling] = ParamOriginOf(kv.second.label);
    }
    return out;
}

// CheckQuery over the texts of each Запрос site, cached per text and parameter set.
class QueryChecker {
public:
    QueryChecker(const strict::FieldPolicy& policy, std::map<const Expr*, std::vector<QueryTextUse>> sites,
                 size_t* work)
        : policy_(policy), sites_(std::move(sites)), work_(work) {}

    const std::map<const Expr*, std::vector<QueryTextUse>>& Sites() const { return sites_; }

    // Each check is charged to the analysis budget; over it the query is not checked at all (Q_LIMIT).
    const strict::QueryCheckResult& Check(const std::string& text, const Params& params) {
        std::string params_key;
        for (const auto& kv : params) {
            params_key += kv.first + '=' + std::to_string(static_cast<int>(kv.second)) + '\n';
        }
        const std::string key = params_key + '\n' + text;
        auto it = checks_.find(key);
        if (it != checks_.end()) return it->second;
        *work_ += text.size();
        if (*work_ > kMaxCodeWork) {
            strict::QueryCheckResult over;
            strict::QueryReason reason;
            reason.code = "Q_LIMIT";
            over.reasons.push_back(reason);
            return checks_.emplace(key, std::move(over)).first->second;
        }
        return checks_.emplace(key, strict::CheckQueryWithPolicy(text, PolicyWith(params_key, params))).first->second;
    }

    // The columns of a site: the worst label across its texts. Null when a text did not parse, a column has no
    // name, or the texts disagree on the column names.
    std::shared_ptr<const ColumnSet> Columns(const Expr* site, const Params& params) {
        const auto it = sites_.find(site);
        if (it == sites_.end() || it->second.empty()) return nullptr;
        std::shared_ptr<ColumnSet> merged;
        for (const QueryTextUse& use : it->second) {
            const strict::QueryCheckResult& r = Check(use.text, params);
            if (!r.parsed) return nullptr;
            ColumnSet set;
            for (const strict::ColumnLabel& c : r.columns) {
                if (c.name.empty()) return nullptr;
                ColumnInfo info;
                info.origin = c.origin;
                info.refs = c.refs;
                const std::string name = AllowlistKey(c.name);
                const auto existing = set.columns.find(name);
                if (existing == set.columns.end()) {
                    set.columns.emplace(name, std::move(info));
                } else {
                    MergeInto(existing->second, info);
                }
            }
            if (!merged) {
                merged = std::make_shared<ColumnSet>(std::move(set));
                continue;
            }
            if (merged->columns.size() != set.columns.size()) return nullptr;
            for (auto& kv : merged->columns) {
                const auto other = set.columns.find(kv.first);
                if (other == set.columns.end()) return nullptr;
                MergeInto(kv.second, other->second);
            }
        }
        return merged;
    }

private:
    // One policy copy per distinct parameter set, shared by every text checked with it.
    const strict::FieldPolicy& PolicyWith(const std::string& params_key, const Params& params) {
        auto it = policies_.find(params_key);
        if (it == policies_.end()) {
            auto policy = std::make_unique<strict::FieldPolicy>(policy_);
            policy->SetParams(params);
            it = policies_.emplace(params_key, std::move(policy)).first;
        }
        return *it->second;
    }

    // Targets survive only when both sides are references (as for ОБЪЕДИНИТЬ in the query checker).
    static void MergeInto(ColumnInfo& into, const ColumnInfo& other) {
        into.origin = JoinOrigin(into.origin, other.origin);
        if (into.refs.empty() || other.refs.empty()) {
            into.refs.clear();
            return;
        }
        for (const std::string& r : other.refs) {
            bool have = false;
            for (const std::string& h : into.refs) have = have || h == r;
            if (!have) into.refs.push_back(r);
        }
    }

    const strict::FieldPolicy& policy_;
    std::map<const Expr*, std::vector<QueryTextUse>> sites_;
    size_t* work_;
    std::map<std::string, std::unique_ptr<strict::FieldPolicy>> policies_;
    std::map<std::string, strict::QueryCheckResult> checks_;
};

void AddReason(CodeAnalysis& a, const std::string& code, const Pos& pos) {
    for (const CodeReason& r : a.reasons) {
        if (r.code == code && r.pos.offset == pos.offset) return;
    }
    a.reasons.push_back(CodeReason{code, pos});
}

std::set<const Expr*> TextExprs(const CodeAnalysis& a) {
    std::set<const Expr*> out;
    for (const QueryTextUse& use : a.query_texts) out.insert(use.text_expr);
    return out;
}

CodeAnalysis Drive(const Body& body, const strict::FieldPolicy& policy, const TokenTable& tokens) {
    size_t work = 0;   // one budget for every walk below
    TypeCheckOptions base;
    base.policy = &policy;
    base.tokens = &tokens;
    base.work = &work;

    // The query texts depend on the Запрос types only, never on labels: one walk collects them.
    LabelState scratch;
    const CodeAnalysis texts = AnalyzeCodeWalk(body, base, scratch);
    std::map<const Expr*, std::vector<QueryTextUse>> sites;
    for (const QueryTextUse& use : texts.query_texts) sites[use.site].push_back(use);
    QueryChecker checker(policy, std::move(sites), &work);

    // Outer passes: the query parameters (and with them the column labels) are fixed for a pass, and every pass
    // starts from a fresh state, so labels from columns checked with not-yet-known parameters do not survive.
    // Inner rounds: the walk is repeated until the collection contents and parameter bindings are stable.
    std::map<const Expr*, Params> seeds;
    LabelState state;
    CodeAnalysis result;
    bool stable = false;
    for (int pass = 0; pass < kMaxPasses && !stable; ++pass) {
        TypeCheckOptions options = base;
        options.columns_for_query = [&checker, &seeds](const Expr* site) {
            const auto it = seeds.find(site);
            return checker.Columns(site, it == seeds.end() ? Params() : it->second);
        };
        state = LabelState();
        bool settled = false;
        for (int round = 0; round < kMaxRounds && !settled; ++round) {
            const LabelState in = state;
            result = AnalyzeCodeWalk(body, options, state);
            settled = state == in;
        }
        std::map<const Expr*, Params> bound;
        for (const auto& site : state.params) bound[site.first] = ParamsOf(state, site.first);
        stable = settled && bound == seeds;
        seeds = std::move(bound);
    }
    if (!stable) AddReason(result, "C_LIMIT", Pos{});
    if (TextExprs(result) != TextExprs(texts)) AddReason(result, "C_INTERNAL", Pos{});

    // Every text of every site, with the parameters the code binds on that site.
    for (const auto& site : checker.Sites()) {
        const Params params = ParamsOf(state, site.first);
        for (const QueryTextUse& use : site.second) {
            const strict::QueryCheckResult& r = checker.Check(use.text, params);
            for (const strict::QueryReason& reason : r.reasons) AddReason(result, reason.code, use.text_expr->pos);
            result.missing_tables.insert(r.missing_tables.begin(), r.missing_tables.end());
            if (r.verdict != "safe" && r.reasons.empty() && r.missing_tables.empty()) {
                AddReason(result, "Q_INTERNAL", use.text_expr->pos);
            }
            if (!r.canonical.empty()) result.query_canonical[use.text_expr] = r.canonical;
        }
    }
    result.verdict =
        result.reasons.empty() && result.missing_tables.empty() ? CodeVerdict::Safe : CodeVerdict::Confirm;
    return result;
}

}  // namespace

bool IsTokenFormat(const std::string& s) {
    size_t end = 0;
    return TokenAt(s, 0, end) && end == s.size();
}

TokenUse ClassifyTokenLiteral(const std::string& value, const TokenTable* tokens, TokenBinding* binding) {
    const std::string upper = AsciiUpper(value);
    if (tokens) {
        const auto it = tokens->find(upper);
        if (it != tokens->end()) {
            if (binding) *binding = it->second;
            return TokenUse::Bound;
        }
    }
    if (IsTokenFormat(value)) return TokenUse::Unknown;
    for (size_t p = value.find('['); p != std::string::npos; p = value.find('[', p + 1)) {
        size_t end = 0;
        if (TokenAt(value, p, end)) return TokenUse::InString;
    }
    if (tokens) {
        for (const auto& kv : *tokens) {
            if (upper.find(kv.first) != std::string::npos) return TokenUse::InString;
        }
    }
    return TokenUse::None;
}

bool ParseTokenTable(const std::string& policy_json, TokenTable& out) {
    out.clear();
    TokenTable table;
    try {
        const Json root = Json::parse(policy_json, nullptr, false);
        if (root.is_discarded() || !root.is_object()) return false;
        const auto tokens = root.find("tokens");
        if (tokens == root.end()) return true;   // no tokens issued
        if (!tokens->is_object()) return false;
        std::set<long long> indexes;
        for (auto it = tokens->begin(); it != tokens->end(); ++it) {
            const Json& entry = it.value();
            if (!IsTokenFormat(it.key()) || !entry.is_object() || entry.size() != 2) return false;
            const auto index = entry.find("index");
            const auto origin = entry.find("origin");
            if (index == entry.end() || origin == entry.end()) return false;
            if (!index->is_number_integer() || !origin->is_string()) return false;
            const long long n = index->get<long long>();
            if (n < 0 || n > 1000000 || !indexes.insert(n).second) return false;
            const std::string o = origin->get<std::string>();
            TokenBinding b;
            b.index = static_cast<int>(n);
            if (o == "protected") {
                b.origin = Origin::ProtectedDirect;
            } else if (o == "unknown") {
                b.origin = Origin::Unknown;
            } else {
                return false;
            }
            if (!table.emplace(AsciiUpper(it.key()), b).second) return false;
        }
        out = std::move(table);
        return true;
    } catch (...) {
        return false;
    }
}

CodeAnalysis AnalyzeCode(const Body& body, const strict::FieldPolicy& policy, const TokenTable& tokens) {
    try {
        return Drive(body, policy, tokens);
    } catch (...) {
        CodeAnalysis r;
        r.reasons.push_back(CodeReason{"C_INTERNAL", Pos{}});
        return r;
    }
}

}  // namespace lineage::bsl
