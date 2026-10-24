#pragma once
#include <string>

#include "bsl/bsl_ast.h"
#include "bsl/bsl_types.h"
#include "strict/field_policy.h"

// Taint pass of the strict BSL checker (plan Task 25): drives the type and label walk of bsl_types.h to a fixpoint
// and checks every query text of the client code with CheckQuery under the same policy.
//
//   - The flow-insensitive state (collection contents per allocation site, query parameters per Запрос site) and
//     the column labels depend on each other (a parameter may come from another query's column). Each pass fixes
//     the parameters, checks the queries with them and repeats the walk from a fresh state until the collection
//     state is stable; passes repeat until the parameters the code binds equal the ones the pass assumed. A
//     budget overrun is C_LIMIT.
//   - Every text recorded for a Запрос site is checked; a column takes the worst label across the texts, and a
//     site whose texts disagree on the column names has no known columns. The texts' reasons are added as Q_* at
//     the code position of the text; the canonical query text of each is in CodeAnalysis::query_canonical.
//   - A query in client code starts with NO parameters: only УстановитьПараметр on that site binds one, with the
//     join of every value bound to it (Open / Client -> client, ProtectedDirect -> token_protected, anything else
//     -> token_unknown). A parameter the code never sets is missing, so the query is not safe. The host's
//     "params" table of the policy is not used here.
//   - Token-bound values: a string literal whose whole value is a token from the policy's "tokens" table is that
//     token's origin and goes to CodeAnalysis::bound_tokens (the canonical printer writes МСПЗначенияТокенов[n]).
//     A token inside a longer literal is C_TOKEN_IN_STRING; a token-format literal missing from the table is
//     C_TOKEN_UNKNOWN; a token as a name is C_TOKEN_AS_NAME; a token in a query text is C_TOKEN_IN_QUERY.
//
// Hand-offs:
//   - The keys of bound_tokens / query_canonical / query_texts point into `body`: it must outlive the result.
//   - Task 27: a protected_derived / mixed / unknown value in Результат must not auto-pass (equal derived values
//     would show equal tokens); result_label is the label of the whole Результат, the per-path labels still have
//     to be built from the same walk.
//   - A token literal written into a query text would need an inserted З.УстановитьПараметр("МСПТокен<n>",
//     МСПЗначенияТокенов[n-1]) statement; the canonical printer replaces expressions only, so it is refused
//     (C_TOKEN_IN_QUERY) and the client binds the token as a parameter value instead.
//   - CheckQuery reports no value types: a column without reference targets may still hold a reference (ЕСТЬNULL,
//     ОБЪЕДИНИТЬ, parameters), so a string conversion of such a column needs confirmation.

namespace lineage::bsl {

// Token format of the host (ЭтоВалидныйТокенФормат): "[" + Latin letters + "-" + at least five digits + "]".
bool IsTokenFormat(const std::string& s);

enum class TokenUse { None, Bound, InString, Unknown };

// Classifies a string literal: the whole value equal to an issued token (Bound, `binding` set), a whole
// token-format value that is not issued (Unknown), a token or token-format part inside the value (InString).
// Tokens match case-insensitively in their Latin letters, as the host compares them.
TokenUse ClassifyTokenLiteral(const std::string& value, const TokenTable* tokens, TokenBinding* binding);

// Reads the policy's "tokens" object: {"<token>": {"index": <int >= 0>, "origin": "protected" | "unknown"}}.
// No "tokens" key is an empty table. A malformed table, a key that is not in the token format, a negative or
// repeated index, or two keys equal up to case is false (the caller refuses the check).
bool ParseTokenTable(const std::string& policy_json, TokenTable& out);

// The taint pass over a body. `tokens` may be empty. Never throws: an internal failure is C_INTERNAL / confirm.
CodeAnalysis AnalyzeCode(const Body& body, const strict::FieldPolicy& policy, const TokenTable& tokens);

}  // namespace lineage::bsl
