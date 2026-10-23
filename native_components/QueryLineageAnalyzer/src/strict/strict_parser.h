#pragma once
#include <string>

#include "strict/strict_ast.h"
#include "strict/strict_tokenizer.h"

// Function names are NOT allowlisted here: any identifier followed by '(' parses as a Call. The allowlist
// of callable functions lives in the checker (Task 14+). A keyword after '.' is a ParseError (Q_PARSE_KEYWORD_SEGMENT)
// except ССЫЛКА, ПРЕДСТАВЛЕНИЕ, ПРЕДСТАВЛЕНИЕССЫЛКИ, ЗНАЧЕНИЕ, which are accepted as non-first path
// segments and stored with their source spelling as ordinary Field parts.

namespace lineage::strict {

// Maximum nesting of parenthesised expressions / chained unary operators (Q_PARSE_LIMIT beyond it).
constexpr int kMaxParseDepth = 64;
// Maximum depth of a built expression tree, chains of left-associative operators included
// (Q_PARSE_LIMIT beyond it). Keeps every later recursive walk and the destructor inside a small stack.
constexpr int kMaxExprDepth = 256;
// Node-visit budget of ValidateExpr (equals the tokenizer token limit); stops shared-child DAG blowup.
constexpr size_t kMaxExprNodes = 200000;

struct ParseResult { bool ok = false; Batch batch; ParseError error; };
struct ExprResult { bool ok = false; ExprP expr; ParseError error; };

ParseResult ParseBatchStrict(const std::string& utf8);
ExprResult ParseExpressionForTest(const std::string& utf8);

// Structural validator for an expression tree: every node must have a concrete kind (Expr::K::Unset is
// rejected), the arity and payload its kind requires, no null children, and Row only as the left operand
// of a subquery-form В / В ИЕРАРХИИ. Iterative, so it is safe on arbitrary caller-built trees.
// Returns false and fills `err` (code Q_PARSE_INVALID_NODE, or Q_PARSE_LIMIT when deeper than kMaxExprDepth).
// Subquery bodies (Select) are not walked here.
bool ValidateExpr(const ExprP& root, ParseError& err);

}  // namespace lineage::strict
