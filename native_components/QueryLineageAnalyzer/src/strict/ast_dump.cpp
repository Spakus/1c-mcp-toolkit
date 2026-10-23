#include "strict/ast_dump.h"

#include <cstdio>

namespace lineage::strict {

namespace {

std::string Quote(const std::string& s) {
    std::string out = "\"";
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (ch == '"') out += "\\\"";
        else if (ch == '\\') out += "\\\\";
        else if (ch == '\n') out += "\\n";
        else if (ch == '\r') out += "\\r";
        else if (ch == '\t') out += "\\t";
        else if (c < 0x20 || c == 0x7F) {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\x%02X", c);
            out += buf;
        } else out += ch;
    }
    return out + "\"";
}

void Args(const Expr& e, std::string& out, size_t from = 0) {
    for (size_t i = from; i < e.args.size(); ++i) {
        out += ' ';
        out += e.args[i] ? DumpExpr(*e.args[i]) : std::string("(NULL)");
    }
}

}  // namespace

std::string DumpExpr(const Expr& e) {
    std::string o;
    const char* neg = e.negated ? "!" : "";
    switch (e.kind) {
        case Expr::K::Unset: return "(UNSET)";
        case Expr::K::Field: {
            o = "(f";
            for (const auto& p : e.parts) o += " " + p;
            return o + ")";
        }
        case Expr::K::Param: return "(param &" + e.text + ")";
        case Expr::K::StringLit: return Quote(e.text);
        case Expr::K::NumberLit: return e.text;
        case Expr::K::BoolLit: return e.text;
        case Expr::K::NullLit: return "NULL";
        case Expr::K::UndefinedLit: return "НЕОПРЕДЕЛЕНО";
        case Expr::K::Unary:
        case Expr::K::Binary:
            o = "(" + e.text;
            Args(e, o);
            return o + ")";
        case Expr::K::Call:
            o = std::string(e.distinct ? "(call! " : "(call ") + e.text;
            if (e.args.empty() && (e.text == "КОЛИЧЕСТВО" || e.text == "COUNT")) o += " *";
            Args(e, o);
            return o + ")";
        case Expr::K::Case:
            o = e.has_operand ? "(case-op" : "(case";
            Args(e, o);
            return o + ")";
        case Expr::K::Cast:
            o = "(cast";
            Args(e, o);
            o += " " + e.type_name;
            for (const auto& a : e.type_args) o += " " + a;
            return o + ")";
        case Expr::K::InList:
            o = std::string("(") + neg + "in";
            Args(e, o);
            return o + ")";
        case Expr::K::InSubquery:
            o = std::string("(") + neg + "in-sub";
            Args(e, o);
            return o + " (subquery))";
        case Expr::K::InHierarchy:
            o = std::string("(") + neg + "in-h";
            Args(e, o);
            if (e.subquery) o += " (subquery)";
            return o + ")";
        case Expr::K::Between:
            o = std::string("(") + neg + "between";
            Args(e, o);
            return o + ")";
        case Expr::K::Like:
            o = std::string("(") + neg + "like";
            Args(e, o);
            return o + ")";
        case Expr::K::IsNullTest:
            o = std::string("(") + neg + "isnull";
            Args(e, o);
            return o + ")";
        case Expr::K::RefsTest:
            o = std::string("(") + neg + "refs";
            Args(e, o);
            return o + " " + e.type_name + ")";
        case Expr::K::ValueFn: return "(value " + e.type_name + ")";
        case Expr::K::TypeFn: return "(type " + e.type_name + ")";
        case Expr::K::Row:
            o = "(row";
            Args(e, o);
            return o + ")";
    }
    return "(UNKNOWN)";
}

}  // namespace lineage::strict
