#pragma once
#include <set>
#include <string>
#include <vector>

#include "strict/field_policy.h"
#include "strict/origin.h"
#include "strict/scope.h"
#include "strict/strict_ast.h"

// Strict analysis of a parsed query batch: name resolution (scopes, aliases, temporary tables, subqueries) and
// the origin label of every output column of the batch's last statement. Task 16/17 add expression labels and
// the rule engine on top of the same walk.

// Contract for the rule engine (Task 17): ANY column or expression labelled Origin::Unknown must lead to Confirm,
// whether or not a resolution issue was recorded. Resolution assumes the policy lists every field of every table;
// a name that an outer query resolves while an inner policy table does not list it is reported as ambiguous.

// Notes for Tasks 17/18 (not yet enforced by labels):
//  (a) a subquery's result must carry taint from its ГДЕ / JOIN ON / СГРУППИРОВАТЬ / ИМЕЮЩИЕ conditions;
//      SubqueryOrigin here folds in only the returned columns, so the rule engine must add the conditions.
//  (b) КОЛИЧЕСТВО / СУММА over open fields are Open, but with a protected filter, join or grouping they leak
//      through the row set: they must not auto-pass.
//  (c) the host must classify EVERY parameter in the policy: a client parameter named differently can still carry
//      a token. Task 17 states this assumption; an unlisted parameter is Unknown here.

namespace lineage::strict {

struct Reason {
    std::string code;
    Pos pos;
};

struct ColumnLabel {
    std::string name;                   // final result name ("" for a wildcard item)
    Origin origin = Origin::Unknown;
    Pos pos;
    std::vector<std::string> refs;      // target tables when the column holds a reference
};

struct AnalysisResult {
    std::vector<Reason> reasons;                 // public reason codes (parse failure here; rules in Task 17)
    std::vector<ColumnLabel> columns;            // output columns of the last statement
    std::set<std::string> missing_tables;        // tables/targets used but absent from the policy
    std::vector<ResolveIssue> resolution_issues; // everything name resolution could not prove
};

AnalysisResult AnalyzeQuery(const Batch& batch, const FieldPolicy& policy);

}  // namespace lineage::strict
