#pragma once
#include <functional>
#include <map>
#include <set>
#include <vector>

#include "strict/analyzer.h"
#include "strict/field_policy.h"
#include "strict/scope.h"
#include "strict/strict_ast.h"
#include "utf_utils.h"

// Rule engine of the strict checker: which operations over protected values need confirmation.
// It runs after name resolution and labelling, over the labels the analyzer recorded for every expression node.
// Reason codes are fixed and public, carry no values, and point into the client's own text.
//
// Implicit channels: a select whose row set is filtered, joined or grouped by protected data
// ("rows_protected") must not feed an aggregate (Q_AGGREGATE_ROWSET: a COUNT / SUM over open fields would expose
// the cardinality of the protected condition), and a subquery with such a row set is tainted as a whole when it
// is used as a value. Virtual-table parameters are labelled by the analyzer against the base table of the
// register and checked with the condition rules; a protected slot that is not condition-shaped is Q_VT_PARAM.

namespace lineage::strict {

// Labels recorded by the analyzer, keyed by AST node (the batch outlives the table).
struct LabelTable {
    std::map<const Expr*, FieldLabel> expr;                       // label of every walked expression
    std::map<const Select*, std::vector<Column>> select_columns;  // result columns of a select (after ОБЪЕДИНИТЬ)
    std::map<const Select*, bool> rows_protected;    // the select's own row set depends on a protected condition
    std::map<const Select*, bool> result_protected;  // ... or that of any ОБЪЕДИНИТЬ part (the whole result)
    std::set<const Expr*> outer_refs;   // field paths of a subquery that do not resolve in its own sources
};

// Label of an expression node as the analyzer recorded it (Unknown when it has none).
using LabelFn = std::function<Origin(const Expr*)>;

// The operand an emptiness test reads: the field itself, or the field under ВЫРАЗИТЬ(<field> КАК СТРОКА[(n)]), the only
// legal way to test an unlimited-length string in 1C. A cast to a string keeps an empty value empty and a non-empty
// one non-empty, so it discloses the same bit.
inline const Expr* EmptinessOperand(const Expr& x) {
    if (x.kind != Expr::K::Cast || x.args.size() != 1 || !x.args[0]) return &x;
    const std::string type = NormalizeIdentifierKey(x.type_name);
    return type == "СТРОКА" || type == "STRING" ? x.args[0].get() : &x;
}

// An emptiness test: `<field> = ""` or `<field> <> ""` (either order) where the field path reads a stored protected
// string directly (label ProtectedDirect), bare or under ВЫРАЗИТЬ(... КАК СТРОКА). It discloses one bit, filled or
// not, never the value, so the analyzer labels it Open and the rule engine adds no reason. Anything computed first
// (ПОДСТРОКА(x, 5, 1) = "", a parameter, a token, a derived value) is not an emptiness test: a substring of a value is
// a length oracle.
inline bool IsEmptinessTest(const Expr& e, const LabelFn& label) {
    if (e.kind != Expr::K::Binary || (e.text != "=" && e.text != "<>") || e.args.size() != 2) return false;
    const Expr* a = e.args[0].get();
    const Expr* b = e.args[1].get();
    if (!a || !b) return false;
    const auto empty = [](const Expr& x) { return x.kind == Expr::K::StringLit && x.text.empty(); };
    const auto direct = [&label](const Expr& x) {
        const Expr* field = EmptinessOperand(x);
        return field->kind == Expr::K::Field && label(field) == Origin::ProtectedDirect;
    };
    return (empty(*b) && direct(*a)) || (empty(*a) && direct(*b));
}

// A filter by equality: `<field> = <literal or client parameter>`, `<>` likewise, either order, and
// `<field> В (<literals / client parameters>)`, where the field path reads a stored protected string directly (label
// ProtectedDirect). Equality is the normal way to find a record; the value is never returned. The analyzer labels it
// Open and the rule engine adds no reason. A partial comparison (ПОДОБНО, <, >, МЕЖДУ) or a function over the field is
// not covered: it is an oracle on pieces of the value.
inline bool IsFilterEquality(const Expr& e, const LabelFn& label, const FieldPolicy& policy) {
    const auto direct_field = [&label](const Expr* x) {
        return x != nullptr && x->kind == Expr::K::Field && label(x) == Origin::ProtectedDirect;
    };
    const auto client_value = [&policy](const Expr* x) {
        return x != nullptr && (x->kind == Expr::K::StringLit ||
                                (x->kind == Expr::K::Param && policy.OriginOfParam(x->text) == ParamOrigin::Client));
    };
    if (e.kind == Expr::K::Binary && (e.text == "=" || e.text == "<>") && e.args.size() == 2) {
        const Expr* a = e.args[0].get();
        const Expr* b = e.args[1].get();
        return (direct_field(a) && client_value(b)) || (direct_field(b) && client_value(a));
    }
    if (e.kind == Expr::K::InList && e.args.size() >= 2 && !e.subquery) {
        if (!direct_field(e.args[0].get())) return false;
        for (size_t i = 1; i < e.args.size(); ++i) {
            if (!client_value(e.args[i].get())) return false;
        }
        return true;
    }
    return false;
}

// True when a grouping item is also selected as is (same field path): the group key is then returned as a
// protected value, and the group counts describe that value only. Any other protected grouping hides the key.
inline bool GroupItemIsSelected(const Select& s, const Expr& g) {
    if (g.kind != Expr::K::Field) return false;
    for (const SelectItem& item : s.items) {
        if (item.wildcard || !item.expr || item.expr->kind != Expr::K::Field) continue;
        const Expr& x = *item.expr;
        if (x.parts.size() != g.parts.size()) continue;
        bool same = true;
        for (size_t i = 0; same && i < x.parts.size(); ++i) same = FoldedKey(x.parts[i]) == FoldedKey(g.parts[i]);
        if (same) return true;
    }
    return false;
}

// Appends rule and resolution reasons to `result` and sets the verdict.
void ApplyRules(const Batch& batch, const FieldPolicy& policy, const LabelTable& labels, AnalysisResult& result);

}  // namespace lineage::strict
