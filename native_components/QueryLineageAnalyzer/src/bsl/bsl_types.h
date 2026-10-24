#pragma once
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "bsl/bsl_allowlist.h"
#include "bsl/bsl_ast.h"

// Symbol and type tracking of the strict BSL checker (plan Task 24). AnalyzeCodeTypes walks a validated AST and
// proves, for every identifier, global function, "Новый" type, member, method and index, that it is on the
// allowlist (bsl_allowlist.h) and that the receiver's type is KNOWN. Anything else is a reason code (the list is
// in the comment of CodeAnalysis) and the verdict is Confirm. Safe means "no reason", nothing more: taint, implicit
// flow, query checking and risk classes are Tasks 25-27.
//
// Soundness rules (a type that cannot be proven is Unknown, and nothing is allowed on Unknown):
//   - the walk is flow-sensitive; branches (Если, ?(), И / ИЛИ, Попытка) join their environments, and two
//     different types join to Unknown;
//   - a variable assigned on only one path is "maybe unassigned"; reading it is C_UNKNOWN_IDENT, because on the
//     other path the name could resolve to a module variable of the host;
//   - a loop is not iterated to a fixpoint: every variable assigned anywhere in the loop (including the loop
//     variable and out-parameters) is Unknown, and maybe unassigned, at the loop head and after the loop, so a
//     type carried from one iteration into the next cannot be assumed; the same holds for the Исключение block
//     of Попытка (it may start after any statement of the body);
//   - a collection element and the result of an unknown call are Unknown;
//   - a Запрос object may only be used as the receiver of a call or of a Текст assignment: copying it into
//     another variable, a collection or an argument is C_QUERY_ESCAPES, so a text change can never reach an object
//     the checker did not associate with its allocation site;
//   - names are matched case-insensitively with ё = е; two variable spellings that differ only in ё / е are
//     C_AMBIGUOUS_IDENT, so the result does not depend on whether the platform treats them as one name.

namespace lineage::bsl {

// Allowlist key: upper case, ё folded to е. The same normalisation as NormalizeIdentifierKey plus the ё fold that
// IsReservedName applies.
std::string AllowlistKey(const std::string& name);

struct ColumnInfo {
    std::vector<std::string> refs;   // target tables when the column holds a reference (non-empty => Ty::Ref)
    bool operator==(const ColumnInfo& o) const { return refs == o.refs; }
};

// Columns of a query result / value table / row, keyed by AllowlistKey. Immutable once built.
struct ColumnSet {
    std::map<std::string, ColumnInfo> columns;
    bool operator==(const ColumnSet& o) const { return columns == o.columns; }
};

struct TypeCheckOptions {
    // Column labels of the query allocated at `site` (the "Новый Запрос" node), called at Запрос.Выполнить().
    // Task 25 supplies it from CheckQuery. Without it (or when it returns null) the columns are unknown and a
    // column read is C_UNKNOWN_MEMBER.
    std::function<std::shared_ptr<const ColumnSet>(const Expr* site)> columns_for_query;
};

struct CodeReason {
    std::string code;
    Pos pos;
};

// Hand-off (Task 25): one Запрос site may carry several texts (Новый Запрос(t1), then .Текст = t2, or assignments on
// different paths). CheckQuery every text recorded for the site and use the worst case per column across them.
// A constant query text given to a Запрос: "Новый Запрос(<text>)" or "<Запрос>.Текст = <text>".
struct QueryTextUse {
    const Expr* site = nullptr;        // the "Новый Запрос" node the text belongs to
    const Expr* text_expr = nullptr;   // the expression that supplies the text
    std::string text;                  // the constant-folded text (a literal or a concatenation of literals)
};

enum class CodeVerdict { Safe, Confirm };

// Reasons (all positions are in the client's own text; no value is ever echoed):
//   C_UNKNOWN_IDENT   name not assigned on every path and not allowlisted; also an unknown global function
//   C_COMMON_MODULE   "Имя.Метод(...)" on an unassigned name that is not a context name (a module call)
//   C_UNKNOWN_RECEIVER  member / method / index / iteration on a value whose type is Unknown
//   C_UNKNOWN_MEMBER  property or column not allowed on a known type (also assignment to a property)
//   C_UNKNOWN_METHOD  method not allowed on a known type
//   C_UNKNOWN_INDEX   index on a type that has none in the allowlist
//   C_UNKNOWN_TYPE    "Новый" of a type that is not allowlisted
//   C_UNKNOWN_ITER    "Для Каждого" over a type that is not iterable in the allowlist
//   C_EVAL            member named Вычислить / Eval
//   C_DYNAMIC_QUERY   query text that is not a constant-folded literal
//   C_DYNAMIC_KEY     structure / map key (index, Свойство) or a type name that is not a literal
//   C_DYNAMIC_PARAM   query parameter name that is not a literal
//   C_BAD_ARGS        argument count outside the allowlisted range, or a malformed out-parameter
//   C_QUERY_ESCAPES   a Запрос value used other than as a receiver
//   C_AMBIGUOUS_IDENT variable spellings that differ only in ё / е
//   C_LIMIT / C_PARSE a tree that fails ValidateBody (hand-built trees)
struct CodeAnalysis {
    CodeVerdict verdict = CodeVerdict::Confirm;   // fail closed: Safe only on a clean pass
    std::vector<CodeReason> reasons;
    std::vector<CodeReason> risks;                // filled by Task 26
    std::vector<QueryTextUse> query_texts;
};

CodeAnalysis AnalyzeCodeTypes(const Body& body, const TypeCheckOptions& options = TypeCheckOptions());

}  // namespace lineage::bsl
