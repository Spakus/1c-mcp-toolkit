#pragma once
#include <string>

#include "strict/strict_ast.h"

namespace lineage::strict {

// Deterministic S-expression dump of an expression tree, used by tests and by the round-trip property.
// Recursive: call it only on trees that passed the parser's depth limit / ValidateExpr.
std::string DumpExpr(const Expr& e);

}  // namespace lineage::strict
