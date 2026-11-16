#include "bsl/bsl_taint.h"
#include "mixed_script.h"

#include <cstddef>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "bsl/bsl_allowlist.h"
#include "bsl/bsl_tokenizer.h"
#include "strict/check_query.h"
#include "utf_utils.h"

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

strict::ParamOrigin ParamOriginOf(Origin label, bool computed) {
    switch (label) {
        case Origin::Open:
        case Origin::Client: return computed ? strict::ParamOrigin::ClientComputed : strict::ParamOrigin::Client;
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
        for (const std::string& spelling : kv.second.spellings) out[spelling] = ParamOriginOf(kv.second.label, kv.second.computed);
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
        const strict::FieldPolicy* policy = PolicyWith(params_key, params);
        if (!policy) {
            strict::QueryCheckResult invalid;
            strict::QueryReason reason;
            reason.code = "Q_POLICY_INVALID";
            invalid.reasons.push_back(reason);
            return checks_.emplace(key, std::move(invalid)).first->second;
        }
        return checks_.emplace(key, strict::CheckQueryWithPolicy(text, *policy)).first->second;
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
                info.name = c.name;
                info.origin = c.origin;
                info.refs = c.refs;
                info.refs_known = c.refs_known;
                info.fields = c.attr.fields;
                info.unattributed = c.attr.unattributed;
                const std::string name = AllowlistKey(c.name);
                const auto existing = set.columns.find(name);
                if (existing == set.columns.end()) {
                    set.columns.emplace(name, std::move(info));
                } else {
                    if (NormalizeIdentifierKey(existing->second.name) != NormalizeIdentifierKey(info.name)) {
                        existing->second.name_collision = true;
                    }
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
                if (NormalizeIdentifierKey(kv.second.name) != NormalizeIdentifierKey(other->second.name) ||
                    other->second.name_collision) {
                    kv.second.name_collision = true;
                }
                MergeInto(kv.second, other->second);
            }
        }
        return merged;
    }

private:
    // One policy copy per distinct parameter set, shared by every text checked with it. Null when two spellings
    // that collide as parameter names carry different origins (FieldPolicy::SetParams). ParamsOf never yields
    // that today: it gives every spelling of one binding the binding's origin, and a binding groups spellings by
    // AllowlistKey, which folds at least what the parameter name normalization folds.
    const strict::FieldPolicy* PolicyWith(const std::string& params_key, const Params& params) {
        auto it = policies_.find(params_key);
        if (it == policies_.end()) {
            auto policy = std::make_unique<strict::FieldPolicy>(policy_);
            if (!policy->SetParams(params)) policy.reset();
            it = policies_.emplace(params_key, std::move(policy)).first;
        }
        return it->second.get();
    }

    // Targets survive only when both sides are references (as for ОБЪЕДИНИТЬ in the query checker).
    static void MergeInto(ColumnInfo& into, const ColumnInfo& other) {
        into.origin = JoinOrigin(into.origin, other.origin);
        into.fields.insert(other.fields.begin(), other.fields.end());
        into.unattributed = into.unattributed || other.unattributed;
        if (into.refs.empty() || other.refs.empty()) {
            const bool lost = !into.refs.empty() || !other.refs.empty();   // a reference on one side only
            into.refs_known = into.refs_known && other.refs_known && !lost;
            into.refs.clear();
            return;
        }
        into.refs_known = into.refs_known && other.refs_known;
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

void AddReason(CodeAnalysis& a, const std::string& code, const Pos& pos, const std::string& op = std::string(),
               const std::string& field = std::string()) {
    for (const CodeReason& r : a.reasons) {
        if (r.code == code && r.pos.offset == pos.offset && r.op == op && r.field == field) return;
    }
    a.reasons.push_back(CodeReason{code, pos, op, field});
}

std::set<const Expr*> TextExprs(const CodeAnalysis& a) {
    std::set<const Expr*> out;
    for (const QueryTextUse& use : a.query_texts) out.insert(use.text_expr);
    return out;
}

// ---- Risk classes ---------------------------------------------------------------------------------------

constexpr unsigned kRiskProtection = 1, kRiskDeferred = 2, kRiskWrite = 4, kRiskCredentials = 8, kRiskUnknown = 16;
constexpr size_t kMaxRisksPerClass = 50;   // the gate shows markers, not every occurrence

struct RiskEntry {
    std::string key;
    RiskMatch match;
    unsigned bit;
};

unsigned RiskBit(RiskClass c) {
    switch (c) {
        case RiskClass::Protection: return kRiskProtection;
        case RiskClass::Deferred: return kRiskDeferred;
        case RiskClass::Write: return kRiskWrite;
        case RiskClass::Credentials: return kRiskCredentials;
    }
    return kRiskProtection;
}

const char* RiskCode(unsigned bit) {
    switch (bit) {
        case kRiskDeferred: return "R_DEFERRED";
        case kRiskWrite: return "R_WRITE";
        case kRiskCredentials: return "R_CREDENTIALS";
        case kRiskUnknown: return "R_UNKNOWN_EFFECT";
        default: return "R_PROTECTION";
    }
}

const std::vector<RiskEntry>& RiskEntries() {
    static const std::vector<RiskEntry> entries = [] {
        std::vector<RiskEntry> v;
        for (const RiskRule& r : kRiskRules) v.push_back(RiskEntry{AllowlistKey(r.name), r.match, RiskBit(r.cls)});
        return v;
    }();
    return entries;
}

bool RuleMatches(const RiskEntry& e, const std::string& key) {
    switch (e.match) {
        case RiskMatch::Exact: return key == e.key;
        case RiskMatch::Prefix: return key.compare(0, e.key.size(), e.key) == 0;
        case RiskMatch::Contains: return key.find(e.key) != std::string::npos;
    }
    return false;
}

struct AllowedNames {
    std::set<std::string> globals, news, methods;
};

const AllowedNames& Allowed() {
    static const AllowedNames names = [] {
        AllowedNames n;
        for (const GlobalRule& r : kGlobalRules) {
            n.globals.insert(AllowlistKey(r.ru));
            n.globals.insert(AllowlistKey(r.en));
        }
        for (const NewRule& r : kNewRules) {
            n.news.insert(AllowlistKey(r.ru));
            n.news.insert(AllowlistKey(r.en));
        }
        for (const MethodRule& r : kMethodRules) {
            n.methods.insert(AllowlistKey(r.ru));
            n.methods.insert(AllowlistKey(r.en));
        }
        return n;
    }();
    return names;
}

// A name of kPureReaders (AllowlistKey form, exact). The caller must also check the call shape: a plain call, no argument.
bool IsPureReader(const std::string& key) {
    static const std::set<std::string> keys = [] {
        std::set<std::string> k;
        for (const char* n : kPureReaders) k.insert(AllowlistKey(n));
        return k;
    }();
    return keys.count(key) != 0;
}

// Classes of one name (AllowlistKey already applied). An allowlisted method name (УстановитьПараметр) is exempt from
// the Prefix rows: it is the allowlist's own, on its own receiver type; on any other receiver the unknown-effect
// risk applies.
unsigned RiskMaskOfKey(const std::string& key) {
    unsigned mask = 0;
    const bool allowed = Allowed().methods.count(key) != 0;
    for (const RiskEntry& e : RiskEntries()) {
        if ((mask & e.bit) != 0 || !RuleMatches(e, key)) continue;
        if (allowed && e.match == RiskMatch::Prefix) continue;
        mask |= e.bit;
    }
    return mask;
}

// A name that may hide behind a script mix: any non-ASCII, non-Cyrillic character, or Latin together with Cyrillic.
bool NeedsFold(const std::string& key) {
    bool ascii = false, cyrillic = false;
    for (wchar_t u : Utf8ToUtf16Units(key)) {
        if (u < 0x80) {
            if (u >= L'A' && u <= L'Z') ascii = true;
        } else if (u >= 0x0400 && u <= 0x04FF) {
            cyrillic = true;
        } else {
            return true;
        }
    }
    return ascii && cyrillic;
}

class RiskCollector {
public:
    explicit RiskCollector(std::vector<CodeReason>& out) : out_(out) {}

    void Name(const std::string& name, const Pos& pos, bool mixed = false) {
        if (name.empty()) return;
        const std::string key = AllowlistKey(name);
        unsigned mask = Cached(key);
        if (mixed || NeedsFold(key)) {
            mask |= Cached(AllowlistKey(FoldHomoglyphs(key, true)));
            mask |= Cached(AllowlistKey(FoldHomoglyphs(key, false)));
        }
        Add(mask, pos);
    }

    void Add(unsigned mask, const Pos& pos) {
        for (unsigned bit = 1; bit <= kRiskUnknown; bit <<= 1) {
            if ((mask & bit) == 0 || counts_[bit] >= kMaxRisksPerClass) continue;
            ++counts_[bit];
            out_.push_back(CodeReason{RiskCode(bit), pos});
        }
    }

private:
    unsigned Cached(const std::string& key) {
        const auto it = memo_.find(key);
        if (it != memo_.end()) return it->second;
        return memo_[key] = RiskMaskOfKey(key);
    }

    std::vector<CodeReason>& out_;
    std::map<std::string, unsigned> memo_;
    std::map<unsigned, size_t> counts_;
};

void CollectExprNames(const Expr* root, RiskCollector& risks) {
    std::vector<const Expr*> stack{root};
    while (!stack.empty()) {
        const Expr* e = stack.back();
        stack.pop_back();
        if (!e) continue;
        const bool named = e->kind == Expr::K::Var || e->kind == Expr::K::Member || e->kind == Expr::K::Call ||
                           e->kind == Expr::K::MethodCall || e->kind == Expr::K::New;
        const std::string key = AllowlistKey(e->text);
        const bool pure_reader = e->kind == Expr::K::Call && e->args.empty() && IsPureReader(key);
        if (named && !pure_reader) risks.Name(e->text, e->pos);
        // Syntactic pass, independent of the type walk: a callee or "Новый" type that is on no allowlist table.
        if ((e->kind == Expr::K::Call && !Allowed().globals.count(key)) ||
            (e->kind == Expr::K::New && !Allowed().news.count(key)) ||
            (e->kind == Expr::K::MethodCall && !Allowed().methods.count(key))) {
            risks.Add(kRiskUnknown, e->pos);
        }
        for (const ExprP& a : e->args) stack.push_back(a.get());
    }
}

void CollectBodyNames(const Body& root, RiskCollector& risks) {
    std::vector<const Body*> stack{&root};
    while (!stack.empty()) {
        const Body* b = stack.back();
        stack.pop_back();
        for (const StmtP& st : b->stmts) {
            if (!st) continue;
            if (!st->var.empty()) risks.Name(st->var, st->pos);
            for (const ExprP& e : st->exprs) CollectExprNames(e.get(), risks);
            for (const Body& blk : st->blocks) stack.push_back(&blk);
        }
    }
}

// A byte of an identifier in the key text: ASCII letters, digits, '_' and the lead bytes of Cyrillic (U+0400-047F).
// Any other non-ASCII character counts as a boundary (fail closed: it cannot hide a word).
bool IsIdentByte(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == 0xD0 ||
           c == 0xD1;
}

// Invisible characters that split a word for a reader but not for the platform.
bool IsInvisibleCodePoint(unsigned long u) {
    return u == 0x00AD || u == 0x034F || u == 0x061C || u == 0x180E || (u >= 0x200B && u <= 0x200F) ||
           (u >= 0x202A && u <= 0x202E) || (u >= 0x2060 && u <= 0x206F) || u == 0x2800 || u == 0x3164 ||
           u == 0xFE0F || u == 0xFEFF || (u >= 0xE0001 && u <= 0xE007F) ||
           (u < 0x20 && u != 10 && u != 13 && u != 9);
}

// Drops them (a blank would split the word). Handles UTF-16 units (Windows) and code points (Linux) alike.
std::wstring DropInvisible(const std::wstring& in) {
    std::wstring out;
    for (size_t i = 0; i < in.size(); ++i) {
        const unsigned long u = static_cast<unsigned long>(in[i]);
        if (u == 0xDB40 && i + 1 < in.size() && static_cast<unsigned long>(in[i + 1]) >= 0xDC00 &&
            static_cast<unsigned long>(in[i + 1]) <= 0xDC7F) {   // U+E0000..E007F as a surrogate pair
            ++i;
            continue;
        }
        if (!IsInvisibleCodePoint(u)) out.push_back(in[i]);
    }
    return out;
}

void ScanRawKey(const std::string& text, RiskCollector& risks);

// Last resort for text the tokenizer refuses (an Unknown token): every rule is searched for in the whole normalised
// text, strings and comments included, with word boundaries for Exact / Prefix. Positions are unknown (1:1).
void ScanRawText(const std::string& utf8, RiskCollector& risks) {
    const std::string base = AllowlistKey(Utf16UnitsToUtf8(DropInvisible(Utf8ToUtf16Units(utf8))));
    ScanRawKey(base, risks);
    ScanRawKey(FoldHomoglyphs(base, true), risks);
    ScanRawKey(FoldHomoglyphs(base, false), risks);
}

void ScanRawKey(const std::string& text, RiskCollector& risks) {
    for (const RiskEntry& e : RiskEntries()) {
        for (size_t p = text.find(e.key); p != std::string::npos; p = text.find(e.key, p + 1)) {
            const bool left = p == 0 || !IsIdentByte(static_cast<unsigned char>(text[p - 1]));
            const size_t end = p + e.key.size();
            const bool right = end >= text.size() || !IsIdentByte(static_cast<unsigned char>(text[end]));
            if (e.match == RiskMatch::Contains || (left && (e.match == RiskMatch::Prefix || right))) {
                risks.Add(e.bit, Pos{});
                break;
            }
        }
    }
}

std::vector<CodeReason> ScanBodyRisks(const Body& body) {
    std::vector<CodeReason> out;
    RiskCollector risks(out);
    CollectBodyNames(body, risks);
    return out;
}

CodeAnalysis Drive(const Body& body, const strict::FieldPolicy& policy, const TokenTable& tokens, bool oracle_open) {
    size_t work = 0;   // one budget for every walk below
    TypeCheckOptions base;
    base.policy = &policy;
    base.tokens = &tokens;
    base.work = &work;
    base.oracle_open = oracle_open;

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
            for (const strict::QueryReason& reason : r.reasons) {
                AddReason(result, reason.code, use.text_expr->pos, reason.op, reason.field);
            }
            result.missing_tables.insert(r.missing_tables.begin(), r.missing_tables.end());
            if (r.verdict != "safe" && r.reasons.empty() && r.missing_tables.empty()) {
                AddReason(result, "Q_INTERNAL", use.text_expr->pos);
            }
            if (!r.canonical.empty()) result.query_canonical[use.text_expr] = r.canonical;
        }
    }
    // Protected sources of the whole code (CodeAnalysis::source_fields): coarse on purpose, every protected column of
    // every query the code runs, not only the ones the walk read; a site whose columns are unknown is unattributed.
    for (const auto& site : checker.Sites()) {
        const std::shared_ptr<const ColumnSet> columns = checker.Columns(site.first, ParamsOf(state, site.first));
        if (!columns) {
            result.source_unattributed = true;
            continue;
        }
        for (const auto& c : columns->columns) {
            if (!IsTainted(c.second.origin)) continue;
            result.source_fields.insert(c.second.fields.begin(), c.second.fields.end());
            result.source_unattributed = result.source_unattributed || c.second.unattributed;
        }
    }
    // The walk did not complete: nothing it saw can be trusted, so the code may do anything.
    for (const CodeReason& r : result.reasons) {
        if (r.code == "C_LIMIT" || r.code == "C_INTERNAL" || r.code == "Q_INTERNAL") {
            result.risks.push_back(CodeReason{"R_UNKNOWN_EFFECT", r.pos});
        }
    }
    // R_UNKNOWN_EFFECT comes from the walk, the other risks from the names. They are shown to the operator but no
    // longer decide the verdict: the runtime sandbox rolls writes back; what it does not cover is
    // ScanDeniedEffects.
    MergeRisks(result.risks, ScanBodyRisks(body));
    result.verdict = result.reasons.empty() && result.missing_tables.empty() ? CodeVerdict::Safe : CodeVerdict::Confirm;
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

std::vector<CodeReason> ScanRisksInSource(const std::string& utf8) {
    std::vector<CodeReason> raw;
    try {
        RiskCollector risks(raw);
        const std::vector<Token> tokens = Tokenize(utf8);
        bool refused = utf8.size() > kMaxSourceBytes;
        for (size_t i = 0; i < tokens.size(); ++i) {
            const Token& t = tokens[i];
            const Pos pos{t.pos, t.line, t.col};
            const bool after_dot = i > 0 && tokens[i - 1].kind == Bt::Dot;
            const bool after_new = i > 0 && tokens[i - 1].kind == Bt::Keyword && tokens[i - 1].kw == Bk::New;
            if (t.kind == Bt::Unknown) refused = true;
            const bool call = i + 1 < tokens.size() && tokens[i + 1].kind == Bt::LParen;
            const std::string key = AllowlistKey(t.text);
            // A pure reader written as a plain call with no argument: `Имя ( )` and nothing else.
            const bool pure_reader = t.kind == Bt::Identifier && !t.mixed_script && !after_dot && !after_new && call &&
                                     i + 2 < tokens.size() && tokens[i + 2].kind == Bt::RParen && IsPureReader(key);
            if ((t.kind == Bt::Identifier || t.kind == Bt::Keyword) && !pure_reader) {
                risks.Name(t.text, pos, t.mixed_script);
            }
            // Syntactic mirror of the tree pass: a callee or "Новый" type that is on no allowlist table.
            const bool name = t.kind == Bt::Identifier || (t.kind == Bt::Keyword && after_dot);
            if (name && call && !after_new &&
                !(after_dot ? Allowed().methods.count(key) : Allowed().globals.count(key))) {
                risks.Add(kRiskUnknown, pos);
            }
            if (t.kind == Bt::Keyword && t.kw == Bk::New) {
                const Token* type = i + 1 < tokens.size() ? &tokens[i + 1] : nullptr;
                if (!type || type->kind != Bt::Identifier || !Allowed().news.count(AllowlistKey(type->text))) {
                    risks.Add(kRiskUnknown, pos);   // an unknown type, or a type given as an expression
                }
            }
            // Новый("Тип"): the parser refuses a type name given as a string (C_DYNAMIC_NEW); the gate still shows it.
            if (t.kind == Bt::Keyword && t.kw == Bk::New && i + 2 < tokens.size() &&
                tokens[i + 1].kind == Bt::LParen && tokens[i + 2].kind == Bt::String) {
                risks.Name(tokens[i + 2].value, pos);
            }
        }
        if (refused) ScanRawText(utf8, risks);
    } catch (...) {
        raw.assign(1, CodeReason{"R_PROTECTION", Pos{}});   // unreadable text: show the strongest marker
    }
    std::vector<CodeReason> out;
    MergeRisks(out, raw);
    return out;
}

namespace {

struct DenyPattern {
    std::string key;       // the name; of a qualified entry, the manager
    bool prefix = false;   // `key` is a prefix; of a qualified entry, `method` is
    bool qualified = false;
    std::string method;    // qualified entry: the method
    // Qualified entry: every RU / EN spelling of the manager and of the method (SynonymsOf), `key` / `method` included.
    std::vector<std::string> key_alts, method_alts;
};

// RU / EN spellings of the same platform name, for qualified entries: manager roots and methods of the allowlist plus
// the common write / call verbs and storages below. A name outside the table stands for itself (a configuration
// module, a method the table does not list); a prefix method (`Name*`) is matched in the spelling it was written in.
struct NamePair {
    const char* ru;
    const char* en;
};

constexpr NamePair kExtraNamePairs[] = {
    {"Записать", "Write"}, {"ЗаписатьВсё", "WriteAll"}, {"Удалить", "Delete"}, {"Провести", "Post"},
    {"ОтменитьПроведение", "UndoPosting"}, {"УстановитьПометкуУдаления", "SetDeletionMark"},
    {"Сохранить", "Save"}, {"Загрузить", "Load"}, {"Получить", "Get"}, {"Создать", "Create"},
    {"НайтиПоНаименованию", "FindByDescription"}, {"СоздатьЭлемент", "CreateItem"},
    {"СоздатьГруппу", "CreateFolder"}, {"РегистрыСведений", "InformationRegisters"},
    {"РегистрыНакопления", "AccumulationRegisters"}, {"РегистрыБухгалтерии", "AccountingRegisters"},
    {"РегистрыРасчета", "CalculationRegisters"}, {"Константы", "Constants"}, {"Обработки", "DataProcessors"},
    {"Отчеты", "Reports"}, {"ХранилищеОбщихНастроек", "CommonSettingsStorage"},
    {"ХранилищеСистемныхНастроек", "SystemSettingsStorage"}, {"ФоновыеЗадания", "BackgroundJobs"},
    {"РегламентныеЗадания", "ScheduledJobs"}};

const std::vector<std::vector<std::string>>& SynonymGroups() {
    static const std::vector<std::vector<std::string>> groups = [] {
        std::vector<std::vector<std::string>> out;
        const auto add = [&out](const char* ru, const char* en) {
            const std::string a = AllowlistKey(ru), b = AllowlistKey(en);
            for (const auto& g : out) {
                if (g[0] == a || g[1] == a) return;
            }
            out.push_back({a, b});
        };
        for (const GlobalProperty& p : kGlobalProperties) add(p.ru, p.en);
        for (const MethodRule& m : kMethodRules) add(m.ru, m.en);
        for (const NewRule& n : kNewRules) add(n.ru, n.en);
        for (const NamePair& p : kExtraNamePairs) add(p.ru, p.en);
        return out;
    }();
    return groups;
}

// `key` (an AllowlistKey) and its other spelling, when the table knows it.
std::vector<std::string> SynonymsOf(const std::string& key) {
    for (const auto& g : SynonymGroups()) {
        if (g[0] == key || g[1] == key) return g;
    }
    return {key};
}

std::vector<DenyPattern> CompileDeny(const std::vector<std::string>& patterns) {
    std::vector<DenyPattern> out;
    for (std::string p : patterns) {
        DenyPattern d;
        if (!p.empty() && p.back() == '*') {
            d.prefix = true;
            p.pop_back();
        }
        const size_t dot = p.find('.');
        if (dot != std::string::npos) {
            d.qualified = true;
            d.method = AllowlistKey(p.substr(dot + 1));
            p.resize(dot);
            if (d.method.empty()) continue;
        }
        d.key = AllowlistKey(p);
        if (d.key.empty()) continue;
        if (d.qualified) {
            d.key_alts = SynonymsOf(d.key);
            d.method_alts = d.prefix ? std::vector<std::string>{d.method} : SynonymsOf(d.method);
        }
        out.push_back(std::move(d));
    }
    return out;
}

// The keys a name stands for: itself, and (a mixed-script name, or one with a look-alike letter) its homoglyph folds.
std::vector<std::string> FoldedKeys(const std::string& name, bool mixed) {
    const std::string key = AllowlistKey(name);
    std::vector<std::string> out{key};
    if (mixed || NeedsFold(key)) {
        out.push_back(AllowlistKey(FoldHomoglyphs(key, true)));
        out.push_back(AllowlistKey(FoldHomoglyphs(key, false)));
    }
    return out;
}

bool KeyIs(const std::vector<std::string>& keys, const std::string& pattern, bool prefix) {
    for (const std::string& k : keys) {
        if (prefix ? k.compare(0, pattern.size(), pattern) == 0 : k == pattern) return true;
    }
    return false;
}

bool DenyMatchesName(const std::vector<DenyPattern>& deny, const std::string& name, bool mixed) {
    const std::vector<std::string> keys = FoldedKeys(name, mixed);
    for (const DenyPattern& d : deny) {
        if (!d.qualified && KeyIs(keys, d.key, d.prefix)) return true;
    }
    return false;
}

// `manager . method` in the tokens: both names matched like a plain name.
bool AnyKeyIs(const std::vector<std::string>& keys, const std::vector<std::string>& patterns, bool prefix) {
    for (const std::string& p : patterns) {
        if (KeyIs(keys, p, prefix)) return true;
    }
    return false;
}

bool DenyMatchesPairNames(const std::vector<DenyPattern>& deny, const std::string& manager, bool manager_mixed,
                          const Token& method) {
    const std::vector<std::string> managers = FoldedKeys(manager, manager_mixed);
    const std::vector<std::string> methods = FoldedKeys(method.text, method.mixed_script);
    for (const DenyPattern& d : deny) {
        if (d.qualified && AnyKeyIs(managers, d.key_alts, false) && AnyKeyIs(methods, d.method_alts, d.prefix)) {
            return true;
        }
    }
    return false;
}

bool DenyMatchesPair(const std::vector<DenyPattern>& deny, const Token& manager, const Token& method) {
    return DenyMatchesPairNames(deny, manager.text, manager.mixed_script, method);
}

bool IsManager(const std::vector<DenyPattern>& deny, const std::string& name, bool mixed) {
    const std::vector<std::string> keys = FoldedKeys(name, mixed);
    for (const DenyPattern& d : deny) {
        if (d.qualified && AnyKeyIs(keys, d.key_alts, false)) return true;
    }
    return false;
}

// ПолучитьОбщийМодуль("X") / ОбщийМодуль("X") at token `i`: the index of its closing parenthesis, or 0.
size_t CommonModuleByString(const std::vector<Token>& tokens, size_t i) {
    static const std::set<std::string> names = {AllowlistKey("ПолучитьОбщийМодуль"), AllowlistKey("ОбщийМодуль"),
                                                "GETCOMMONMODULE", "COMMONMODULE"};
    if (i + 3 >= tokens.size() || tokens[i].kind != Bt::Identifier || names.count(AllowlistKey(tokens[i].text)) == 0) {
        return 0;
    }
    return tokens[i + 1].kind == Bt::LParen && tokens[i + 2].kind == Bt::String && tokens[i + 3].kind == Bt::RParen
               ? i + 3
               : 0;
}

bool IsNameToken(const Token& t) { return t.kind == Bt::Identifier || t.kind == Bt::Keyword; }

// The manager of a qualified entry mentioned other than as `Manager . name`: carried under another name (assigned,
// passed, parenthesised), so the pair the entry looks for would never appear.
bool DenyAliasesManager(const std::vector<DenyPattern>& deny, const std::vector<Token>& tokens, size_t i) {
    const bool called = i + 2 < tokens.size() && tokens[i + 1].kind == Bt::Dot && IsNameToken(tokens[i + 2]);
    if (called) return false;
    return IsManager(deny, tokens[i].text, tokens[i].mixed_script);
}

bool IsBlankByte(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

// "MANAGER . METHOD" in a normalised text, with blanks around the dot.
bool QualifiedInRawKey(const DenyPattern& d, const std::string& text) {
    for (size_t p = text.find(d.key); p != std::string::npos; p = text.find(d.key, p + 1)) {
        if (p > 0 && IsIdentByte(static_cast<unsigned char>(text[p - 1]))) continue;
        size_t at = p + d.key.size();
        while (at < text.size() && IsBlankByte(text[at])) ++at;
        if (at >= text.size() || text[at] != '.') continue;
        ++at;
        while (at < text.size() && IsBlankByte(text[at])) ++at;
        if (text.compare(at, d.method.size(), d.method) != 0) continue;
        const size_t end = at + d.method.size();
        if (d.prefix || end >= text.size() || !IsIdentByte(static_cast<unsigned char>(text[end]))) return true;
    }
    return false;
}

// The manager of a qualified entry as a whole word that is not followed by a dot (see DenyAliasesManager).
bool ManagerAliasInRawKey(const DenyPattern& d, const std::string& text) {
    for (size_t p = text.find(d.key); p != std::string::npos; p = text.find(d.key, p + 1)) {
        if (p > 0 && IsIdentByte(static_cast<unsigned char>(text[p - 1]))) continue;
        size_t at = p + d.key.size();
        if (at < text.size() && IsIdentByte(static_cast<unsigned char>(text[at]))) continue;
        while (at < text.size() && IsBlankByte(text[at])) ++at;
        if (at >= text.size() || text[at] != '.') return true;
    }
    return false;
}

bool DenyInRawKey(const std::vector<DenyPattern>& deny, const std::string& text) {
    for (const DenyPattern& d : deny) {
        if (d.qualified) {
            for (const std::string& manager : d.key_alts) {
                for (const std::string& method : d.method_alts) {
                    DenyPattern one = d;   // one spelling of the pair at a time
                    one.key = manager;
                    one.method = method;
                    if (QualifiedInRawKey(one, text)) return true;
                }
                DenyPattern one = d;
                one.key = manager;
                if (ManagerAliasInRawKey(one, text)) return true;
            }
            continue;
        }
        for (size_t p = text.find(d.key); p != std::string::npos; p = text.find(d.key, p + 1)) {
            const bool left = p == 0 || !IsIdentByte(static_cast<unsigned char>(text[p - 1]));
            const size_t end = p + d.key.size();
            const bool right = end >= text.size() || !IsIdentByte(static_cast<unsigned char>(text[end]));
            if (left && (d.prefix || right)) return true;
        }
    }
    return false;
}

bool DenyInRawText(const std::vector<DenyPattern>& deny, const std::string& utf8) {
    const std::string base = AllowlistKey(Utf16UnitsToUtf8(DropInvisible(Utf8ToUtf16Units(utf8))));
    return DenyInRawKey(deny, base) || DenyInRawKey(deny, FoldHomoglyphs(base, true)) ||
           DenyInRawKey(deny, FoldHomoglyphs(base, false));
}

}  // namespace

std::vector<CodeReason> ScanDeniedEffects(const std::string& utf8, const std::vector<std::string>& patterns,
                                          const std::string& parse_error_code) {
    std::vector<CodeReason> out;
    try {
        const std::vector<DenyPattern> deny = CompileDeny(patterns);
        if (deny.empty()) return out;
        const std::vector<Token> tokens = Tokenize(utf8);
        bool refused = utf8.size() > kMaxSourceBytes || parse_error_code == "C_EVAL" ||
                       parse_error_code == "C_DYNAMIC_NEW";
        std::string joined;   // "Фоновые" + "Задания": the strings of an executed text, joined
        for (size_t i = 0; i < tokens.size(); ++i) {
            const Token& t = tokens[i];
            if (t.kind == Bt::Unknown) refused = true;
            if (t.kind == Bt::String) joined += t.value;
            if (!IsNameToken(t) || out.size() >= kMaxRisksPerClass) continue;
            const bool pair = i + 2 < tokens.size() && tokens[i + 1].kind == Bt::Dot && IsNameToken(tokens[i + 2]) &&
                              DenyMatchesPair(deny, t, tokens[i + 2]);
            // ПолучитьОбщийМодуль("Менеджер").Метод(...): the module is the manager of a qualified entry
            if (const size_t close = CommonModuleByString(tokens, i)) {
                const Token& module = tokens[i + 2];
                if (IsManager(deny, module.value, false)) {
                    const bool called = close + 2 < tokens.size() && tokens[close + 1].kind == Bt::Dot &&
                                        IsNameToken(tokens[close + 2]);
                    if (!called || DenyMatchesPairNames(deny, module.value, false, tokens[close + 2])) {
                        out.push_back(CodeReason{"C_EFFECT_DENIED", Pos{t.pos, t.line, t.col}});
                    }
                }
            }
            if (pair || DenyMatchesName(deny, t.text, t.mixed_script) || DenyAliasesManager(deny, tokens, i)) {
                out.push_back(CodeReason{"C_EFFECT_DENIED", Pos{t.pos, t.line, t.col}});
            }
        }
        if (out.empty() && refused && (DenyInRawText(deny, utf8) || DenyInRawText(deny, joined))) {
            out.push_back(CodeReason{"C_EFFECT_DENIED", Pos{}});
        }
    } catch (...) {
        out.assign(1, CodeReason{"C_EFFECT_DENIED", Pos{}});   // unreadable text: fail closed
    }
    return out;
}

namespace {

bool IsEvalIdentifier(const Token& t) {
    if (t.kind != Bt::Identifier) return false;
    const std::string key = NormalizeIdentifierKey(t.text);
    return key == NormalizeIdentifierKey("Вычислить") || key == "EVAL";
}

// The tokens between the parenthesis at `open` and its partner, or up to the first comma at depth 0 when
// `first_only`; false when there is no partner.
bool ArgumentTokens(const std::vector<Token>& tokens, size_t open, bool first_only, size_t& from, size_t& to) {
    int depth = 0;
    from = open + 1;
    for (size_t i = open; i < tokens.size(); ++i) {
        const Bt kind = tokens[i].kind;
        if (kind == Bt::LParen) {
            ++depth;
        } else if (kind == Bt::RParen) {
            if (--depth == 0) {
                to = i;
                return true;
            }
        } else if (kind == Bt::Comma && depth == 1 && first_only) {
            to = i;
            return true;
        } else if (kind == Bt::End) {
            return false;
        }
    }
    return false;
}

// String literals joined with '+', parentheses allowed: a text the code wrote.
bool ConstantText(const std::vector<Token>& tokens, size_t from, size_t to) {
    bool text = false;
    for (size_t i = from; i < to; ++i) {
        const Token& t = tokens[i];
        if (t.kind == Bt::String) text = true;
        else if (t.kind != Bt::LParen && t.kind != Bt::RParen && !(t.kind == Bt::Op && t.text == "+")) return false;
    }
    return text;
}

}  // namespace

std::vector<CodeReason> ScanComputedExecution(const std::string& utf8) {
    std::vector<CodeReason> out;
    try {
        const std::vector<Token> tokens = Tokenize(utf8);
        for (size_t i = 0; i < tokens.size() && out.size() < kMaxRisksPerClass; ++i) {
            const Token& t = tokens[i];
            // After a dot Выполнить is a method (Запрос.Выполнить()), not the statement.
            const bool member = i > 0 && tokens[i - 1].kind == Bt::Dot;
            const bool execute = t.kind == Bt::Keyword && t.kw == Bk::Execute && !member;
            const bool eval = IsEvalIdentifier(t);
            const bool dynamic_new = t.kind == Bt::Keyword && t.kw == Bk::New && i + 1 < tokens.size() &&
                                     tokens[i + 1].kind == Bt::LParen;
            if (!execute && !eval && !dynamic_new) continue;
            size_t from = 0, to = 0;
            const bool called = i + 1 < tokens.size() && tokens[i + 1].kind == Bt::LParen;
            if (called && ArgumentTokens(tokens, i + 1, dynamic_new, from, to) && ConstantText(tokens, from, to)) continue;
            if (eval && !called) continue;   // a variable named Вычислить: the parser refuses it as C_EVAL
            out.push_back(CodeReason{"C_EFFECT_DENIED", Pos{t.pos, t.line, t.col}});
        }
    } catch (...) {
        out.assign(1, CodeReason{"C_EFFECT_DENIED", Pos{}});   // unreadable text: fail closed
    }
    return out;
}

std::vector<CodeReason> RefusedCodeRisks(const std::string& utf8, const std::string& parse_error_code,
                                         const Pos& error_pos) {
    std::vector<CodeReason> out = ScanRisksInSource(utf8);
    // No tree: nothing is known about the code. The marker sits where the parser stopped (the refusal's own position),
    // not at 1:1, where it would read as a second risk of the first token.
    std::vector<CodeReason> more{CodeReason{"R_UNKNOWN_EFFECT", error_pos}};
    try {
        if (parse_error_code == "C_EVAL" || parse_error_code == "C_DYNAMIC_NEW") {
            more.push_back(CodeReason{"R_PROTECTION", Pos{}});
            // The text of an evaluated string or a dynamic type name is code: search every string literal, and all of
            // them joined ("За" + "пись").
            RiskCollector risks(more);
            std::string joined;
            for (const Token& t : Tokenize(utf8)) {
                if (t.kind != Bt::String) continue;
                ScanRawText(t.value, risks);
                joined += t.value;
            }
            ScanRawText(joined, risks);
        }
    } catch (...) {
        more.push_back(CodeReason{"R_PROTECTION", Pos{}});
    }
    MergeRisks(out, more);
    return out;
}

void MergeRisks(std::vector<CodeReason>& into, const std::vector<CodeReason>& more) {
    for (const CodeReason& r : more) {
        bool have = false;
        for (const CodeReason& h : into) have = have || (h.code == r.code && h.pos.offset == r.pos.offset);
        if (!have) into.push_back(r);
    }
}

CodeAnalysis AnalyzeCode(const Body& body, const strict::FieldPolicy& policy, const TokenTable& tokens,
                         bool oracle_open) {
    try {
        return Drive(body, policy, tokens, oracle_open);
    } catch (...) {
        CodeAnalysis r;
        r.reasons.push_back(CodeReason{"C_INTERNAL", Pos{}});
        r.risks.push_back(CodeReason{"R_UNKNOWN_EFFECT", Pos{}});
        try {
            MergeRisks(r.risks, ScanBodyRisks(body));
        } catch (...) {
            r.risks.push_back(CodeReason{"R_PROTECTION", Pos{}});
        }
        return r;
    }
}

}  // namespace lineage::bsl
