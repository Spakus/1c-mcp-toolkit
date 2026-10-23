#pragma once
#include <cstring>
#include <string>

#include "strict/analyzer.h"
#include "strict/field_policy.h"
#include "strict/strict_parser.h"

// Helpers of the strict-checker suites. Task 24 adds CheckCodeForTest, HasCodeReason and HasRisk.

namespace lineage::strict {

// Parses strictly, then analyzes. A parse error becomes a result carrying the Q_PARSE_* reason.
inline AnalysisResult AnalyzeForTest(const FieldPolicy& policy, const std::string& query) {
    const ParseResult parsed = ParseBatchStrict(query);
    if (!parsed.ok) {
        AnalysisResult r;
        r.reasons.push_back(Reason{parsed.error.code, parsed.error.pos});
        return r;
    }
    return AnalyzeQuery(parsed.batch, policy);
}

inline bool HasReason(const AnalysisResult& r, const char* code) {
    for (const Reason& reason : r.reasons) {
        if (reason.code == code) return true;
    }
    return false;
}

inline bool HasIssue(const AnalysisResult& r, const char* code) {
    for (const ResolveIssue& issue : r.resolution_issues) {
        if (issue.code == code) return true;
    }
    return false;
}

}  // namespace lineage::strict
