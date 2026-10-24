#pragma once
#include <cstring>
#include <string>

#include "strict/analyzer.h"
#include "strict/field_policy.h"
#include "bsl/bsl_parser.h"
#include "bsl/bsl_types.h"
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

// Parses client code and runs the type/allowlist pass. A parse error becomes a result carrying the parser's reason
// code (C_EVAL, C_RESERVED, ...). The policy is not consulted yet: Task 25 hands query texts to CheckQuery with it.
inline bsl::CodeAnalysis CheckCodeForTest(const FieldPolicy&, const std::string& code,
                                          const bsl::TypeCheckOptions& options = bsl::TypeCheckOptions()) {
    const bsl::ParseResult parsed = bsl::ParseBsl(code);
    if (!parsed.ok) {
        bsl::CodeAnalysis r;
        r.reasons.push_back(bsl::CodeReason{parsed.error.code, parsed.error.pos});
        return r;
    }
    return bsl::AnalyzeCodeTypes(parsed.body, options);
}

inline bool HasCodeReason(const bsl::CodeAnalysis& r, const char* code) {
    for (const bsl::CodeReason& reason : r.reasons) {
        if (reason.code == code) return true;
    }
    return false;
}

inline bool HasRisk(const bsl::CodeAnalysis& r, const char* code) {
    for (const bsl::CodeReason& risk : r.risks) {
        if (risk.code == code) return true;
    }
    return false;
}

}  // namespace lineage::strict
