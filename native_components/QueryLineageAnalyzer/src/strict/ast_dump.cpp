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

std::string DumpSelect(const Select& s);

std::string OptExpr(const ExprP& e) { return e ? DumpExpr(*e) : std::string("_"); }

std::string DumpSource(const Source& src) {
    std::string o;
    switch (src.kind) {
        case Source::K::Table: o = "(table " + src.name; break;
        case Source::K::VirtualTable:
            o = "(vt " + src.name + " (params";
            for (const ExprP& p : src.vt_params) o += " " + OptExpr(p);
            o += ")";
            break;
        case Source::K::Subquery:
            o = "(subq " + (src.subquery ? DumpSelect(*src.subquery) : std::string("(NULL)"));
            break;
    }
    if (!src.alias.empty()) o += " КАК " + src.alias;
    return o + ")";
}

const char* JoinName(Join::K k) {
    switch (k) {
        case Join::K::Inner: return "inner";
        case Join::K::Left: return "left";
        case Join::K::Right: return "right";
        case Join::K::Full: return "full";
    }
    return "?";
}

std::string ExprList(const std::vector<ExprP>& v) {
    std::string o;
    for (const ExprP& e : v) o += " " + OptExpr(e);
    return o;
}

std::string DumpSelect(const Select& s) {
    std::string o = "(select";
    if (s.allowed) o += " allowed";
    if (s.distinct) o += " distinct";
    if (!s.top.empty()) o += " top " + s.top;
    o += " (items";
    for (const SelectItem& it : s.items) {
        o += " (item ";
        if (it.wildcard) {
            for (const std::string& p : it.wildcard_prefix) o += p + ".";
            o += "*";
        } else {
            o += OptExpr(it.expr);
        }
        if (!it.alias.empty()) o += " КАК " + it.alias;
        o += ")";
    }
    o += ")";
    if (!s.into.empty()) o += " (into " + s.into + ")";
    if (!s.from.empty()) {
        o += " (from";
        for (size_t i = 0; i < s.from.size(); ++i) {
            o += " " + DumpSource(s.from[i]);
            if (i < s.joins.size()) {
                for (const Join& j : s.joins[i]) {
                    o += std::string(" (join ") + JoinName(j.kind) + " " + DumpSource(j.source) + " ON " + OptExpr(j.on) + ")";
                }
            }
        }
        o += ")";
    }
    if (s.where) o += " (where " + DumpExpr(*s.where) + ")";
    if (!s.group_by.empty()) o += " (group" + ExprList(s.group_by) + ")";
    if (s.having) o += " (having " + DumpExpr(*s.having) + ")";
    if (s.for_update) {
        o += " (for-update";
        for (const std::string& t : s.for_update_tables) o += " " + t;
        o += ")";
    }
    if (!s.index_by.empty()) o += " (index" + ExprList(s.index_by) + ")";
    for (const Select::UnionPart& u : s.unions) {
        o += std::string(" (union ") + (u.all ? "all " : "") + (u.select ? DumpSelect(*u.select) : std::string("(NULL)")) + ")";
    }
    if (!s.order_by.empty()) {
        o += " (order";
        for (const OrderItem& it : s.order_by) o += " " + OptExpr(it.expr) + (it.desc ? " desc" : "");
        o += ")";
    }
    if (s.autoorder) o += " autoorder";
    if (s.has_totals) {
        o += " (totals (aggregates" + ExprList(s.totals_aggregates) + ") (by";
        for (const TotalsItem& t : s.totals_by) {
            o += " (";
            o += t.overall ? "overall" : OptExpr(t.expr);
            if (t.only_hierarchy) o += " only-hierarchy";
            else if (t.hierarchy) o += " hierarchy";
            if (t.periods) o += " periods" + ExprList(t.periods_args);
            if (!t.alias.empty()) o += " КАК " + t.alias;
            o += ")";
        }
        o += "))";
    }
    return o + ")";
}

}  // namespace

std::string DumpBatch(const Batch& b) {
    std::string o = "(batch";
    for (const Statement& st : b.statements) {
        if (st.kind == Statement::K::Drop) o += " (drop " + st.drop_name + ")";
        else o += " " + (st.select ? DumpSelect(*st.select) : std::string("(NULL)"));
    }
    return o + ")";
}

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
