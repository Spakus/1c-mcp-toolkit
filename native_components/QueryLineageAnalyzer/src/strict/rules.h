#pragma once
#include <map>
#include <vector>

#include "strict/analyzer.h"
#include "strict/field_policy.h"
#include "strict/scope.h"
#include "strict/strict_ast.h"

// Rule engine of the strict checker (Task 17): which operations over protected values need confirmation.
// It runs after name resolution and labelling, over the labels the analyzer recorded for every expression node.
// Reason codes are fixed and public, carry no values, and point into the client's own text.
//
// Task 18 adds clause-specific and implicit channels (WHERE / JOIN / GROUP BY / HAVING taint, subquery taint,
// aggregates over open fields with protected filters, virtual-table parameter conditions). Until then a virtual
// table parameter that is anything but a constant, a client parameter or a plain date function is Q_VT_PARAM.

namespace lineage::strict {

// Labels recorded by the analyzer, keyed by AST node (the batch outlives the table).
struct LabelTable {
    std::map<const Expr*, FieldLabel> expr;                       // label of every walked expression
    std::map<const Select*, std::vector<Column>> select_columns;  // result columns of a select (after ОБЪЕДИНИТЬ)
};

// Appends rule and resolution reasons to `result` and sets the verdict.
void ApplyRules(const Batch& batch, const FieldPolicy& policy, const LabelTable& labels, AnalysisResult& result);

}  // namespace lineage::strict
