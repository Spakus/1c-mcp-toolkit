#include "strict/check_query.h"

#include <cstddef>
#include <vector>

#include <nlohmann/json.hpp>

#include "strict/analyzer.h"
#include "strict/ast_dump.h"
#include "strict/canonical_printer.h"
#include "strict/field_policy.h"
#include "strict/origin.h"
#include "strict/strict_parser.h"

namespace lineage::strict {

namespace {

using Json = nlohmann::json;

const char* const kInternalFallback = "{\"api\":1,\"verdict\":\"confirm\",\"reasons\":[{\"code\":\"Q_INTERNAL\"}]}";

Json MakeReason(const std::string& code, const Pos* pos) {
    Json reason = Json::object();
    reason["code"] = code;
    if (pos) {
        reason["line"] = pos->line;
        reason["col"] = pos->col;
        reason["offset"] = pos->offset;
    }
    return reason;
}

std::string Dump(const Json& json) {
    return json.dump(-1, ' ', false, Json::error_handler_t::replace);
}

Json Skeleton() {
    Json out = Json::object();
    out["api"] = 1;
    out["verdict"] = "confirm";
    out["reasons"] = Json::array();
    out["canonical"] = "";
    out["columns"] = Json::array();
    out["missing_tables"] = Json::array();
    return out;
}

std::string Reject(const std::string& code, const Pos* pos) {
    Json out = Skeleton();
    out["reasons"].push_back(MakeReason(code, pos));
    return Dump(out);
}

// Names the platform will give the columns of the last statement; the analyzer's own names are the fallback.
std::vector<std::string> FinalColumnNames(const Batch& batch, const AnalysisResult& analysis) {
    std::vector<std::vector<std::string>> per_statement;
    if (StatementResultNames(batch, per_statement) && !per_statement.empty() &&
        per_statement.back().size() == analysis.columns.size()) {
        return per_statement.back();
    }
    std::vector<std::string> names;
    for (const ColumnLabel& column : analysis.columns) names.push_back(column.name);
    return names;
}

// The result of a batch is the last statement's; any other select without ПОМЕСТИТЬ (or a final УНИЧТОЖИТЬ)
// would return a result the labels do not describe.
bool HasUnlabelledResult(const Batch& batch) {
    const size_t count = batch.statements.size();
    for (size_t i = 0; i < count; ++i) {
        const Statement& st = batch.statements[i];
        const bool is_last = i + 1 == count;
        if (st.kind == Statement::K::Drop) {
            if (is_last) return true;
        } else if (!is_last && (!st.select || st.select->into.empty())) {
            return true;
        }
    }
    return false;
}

QueryReason MakeQueryReason(const std::string& code, const Pos* pos) {
    QueryReason r;
    r.code = code;
    if (pos) {
        r.has_pos = true;
        r.pos = *pos;
    }
    return r;
}

QueryCheckResult Analyze(const std::string& query_utf8, const FieldPolicy& policy) {
    QueryCheckResult out;
    const ParseResult parsed = ParseBatchStrict(query_utf8);
    if (!parsed.ok) {
        out.reasons.push_back(
            MakeQueryReason(parsed.error.code.empty() ? "Q_PARSE_ERROR" : parsed.error.code, &parsed.error.pos));
        return out;
    }

    const AnalysisResult analysis = AnalyzeQuery(parsed.batch, policy);
    for (const Reason& reason : analysis.reasons) out.reasons.push_back(MakeQueryReason(reason.code, &reason.pos));
    out.missing_tables = analysis.missing_tables;

    bool safe = analysis.verdict == Verdict::Safe && analysis.reasons.empty() && analysis.missing_tables.empty() &&
                analysis.resolution_issues.empty();

    if (HasUnlabelledResult(parsed.batch)) {
        safe = false;
        out.reasons.push_back(MakeQueryReason("Q_BATCH_RESULT", nullptr));
    }

    const PrintResult printed = PrintCanonicalChecked(parsed.batch);
    if (printed.ok) {
        out.canonical = printed.text;
    } else {
        safe = false;
        out.reasons.push_back(
            MakeQueryReason(printed.error.code.empty() ? "Q_PRINT_FAILED" : printed.error.code, &printed.error.pos));
    }

    out.parsed = true;
    const std::vector<std::string> names = FinalColumnNames(parsed.batch, analysis);
    for (size_t i = 0; i < analysis.columns.size(); ++i) {
        ColumnLabel column = analysis.columns[i];
        if (i < names.size()) column.name = names[i];
        out.columns.push_back(std::move(column));
    }

    if (safe) {
        out.verdict = "safe";
    } else if (!analysis.missing_tables.empty()) {
        out.verdict = "incomplete";
    } else {
        out.verdict = "confirm";
    }
    return out;
}

std::string ToJson(const QueryCheckResult& r) {
    Json out = Skeleton();
    for (const QueryReason& reason : r.reasons) {
        out["reasons"].push_back(MakeReason(reason.code, reason.has_pos ? &reason.pos : nullptr));
    }
    for (const std::string& table : r.missing_tables) out["missing_tables"].push_back(table);
    out["canonical"] = r.canonical;
    for (const ColumnLabel& label : r.columns) {
        Json column = Json::object();
        column["name"] = label.name;
        column["origin"] = OriginName(label.origin);
        column["direct"] = label.origin == Origin::ProtectedDirect;
        out["columns"].push_back(column);
    }
    out["verdict"] = r.verdict;
    return Dump(out);
}

std::string Check(const std::string& query_utf8, const std::string& policy_json) {
    const FieldPolicy::Parsed policy = FieldPolicy::FromJson(policy_json);
    if (!policy.ok) return Reject("Q_POLICY_INVALID", nullptr);
    return ToJson(Analyze(query_utf8, policy.policy));
}

}  // namespace

QueryCheckResult CheckQueryWithPolicy(const std::string& query_utf8, const FieldPolicy& policy) {
    try {
        return Analyze(query_utf8, policy);
    } catch (...) {
        QueryCheckResult r;
        r.reasons.push_back(MakeQueryReason("Q_INTERNAL", nullptr));
        return r;
    }
}

std::string CheckQueryImpl(const std::string& query_utf8, const std::string& policy_json) {
    try {
        return Check(query_utf8, policy_json);
    } catch (...) {
        return kInternalFallback;
    }
}

}  // namespace lineage::strict
