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

std::string Check(const std::string& query_utf8, const std::string& policy_json) {
    const FieldPolicy::Parsed policy = FieldPolicy::FromJson(policy_json);
    if (!policy.ok) return Reject("Q_POLICY_INVALID", nullptr);

    const ParseResult parsed = ParseBatchStrict(query_utf8);
    if (!parsed.ok) return Reject(parsed.error.code.empty() ? "Q_PARSE_ERROR" : parsed.error.code, &parsed.error.pos);

    const AnalysisResult analysis = AnalyzeQuery(parsed.batch, policy.policy);
    Json out = Skeleton();
    for (const Reason& reason : analysis.reasons) out["reasons"].push_back(MakeReason(reason.code, &reason.pos));
    for (const std::string& table : analysis.missing_tables) out["missing_tables"].push_back(table);

    bool safe = analysis.verdict == Verdict::Safe && analysis.reasons.empty() && analysis.missing_tables.empty() &&
                analysis.resolution_issues.empty();

    if (HasUnlabelledResult(parsed.batch)) {
        safe = false;
        out["reasons"].push_back(MakeReason("Q_BATCH_RESULT", nullptr));
    }

    const PrintResult printed = PrintCanonicalChecked(parsed.batch);
    if (printed.ok) {
        out["canonical"] = printed.text;
    } else {
        safe = false;
        out["reasons"].push_back(MakeReason(printed.error.code.empty() ? "Q_PRINT_FAILED" : printed.error.code,
                                            &printed.error.pos));
    }

    const std::vector<std::string> names = FinalColumnNames(parsed.batch, analysis);
    for (size_t i = 0; i < analysis.columns.size(); ++i) {
        Json column = Json::object();
        column["name"] = i < names.size() ? names[i] : analysis.columns[i].name;
        column["origin"] = OriginName(analysis.columns[i].origin);
        column["direct"] = analysis.columns[i].origin == Origin::ProtectedDirect;
        out["columns"].push_back(column);
    }

    if (safe) {
        out["verdict"] = "safe";
    } else if (!analysis.missing_tables.empty()) {
        out["verdict"] = "incomplete";
    } else {
        out["verdict"] = "confirm";
    }
    return Dump(out);
}

}  // namespace

std::string CheckQueryImpl(const std::string& query_utf8, const std::string& policy_json) {
    try {
        return Check(query_utf8, policy_json);
    } catch (...) {
        return kInternalFallback;
    }
}

}  // namespace lineage::strict
