#include "bsl/bsl_types.h"

#include <set>
#include <utility>

#include "bsl/bsl_parser.h"
#include "utf_utils.h"

namespace lineage::bsl {

std::string AllowlistKey(const std::string& name) {
    std::wstring units = Utf8ToUtf16Units(name);
    for (auto& unit : units) {
        uint32_t c = UppercaseU16(static_cast<uint32_t>(unit));
        if (c == 0x0401) c = 0x0415;   // Ё -> Е
        unit = static_cast<wchar_t>(c);
    }
    return Utf16UnitsToUtf8(units);
}

namespace {

// ---- lookup tables built from the data in bsl_allowlist.h ------------------------------------------------------

struct Tables {
    std::map<std::string, const GlobalRule*> globals;
    std::map<std::string, const NewRule*> news;
    std::map<std::pair<int, std::string>, const MethodRule*> methods;
    std::map<std::pair<int, std::string>, const PropertyRule*> properties;
    std::set<std::string> context_names;
    std::set<std::string> query_text, property_method, eval_member;

    Tables() {
        for (const GlobalRule& r : kGlobalRules) {
            globals[AllowlistKey(r.ru)] = &r;
            globals[AllowlistKey(r.en)] = &r;
        }
        for (const NewRule& r : kNewRules) {
            news[AllowlistKey(r.ru)] = &r;
            news[AllowlistKey(r.en)] = &r;
        }
        for (const MethodRule& r : kMethodRules) {
            methods[{static_cast<int>(r.receiver), AllowlistKey(r.ru)}] = &r;
            methods[{static_cast<int>(r.receiver), AllowlistKey(r.en)}] = &r;
        }
        for (const PropertyRule& r : kPropertyRules) {
            properties[{static_cast<int>(r.receiver), AllowlistKey(r.ru)}] = &r;
            properties[{static_cast<int>(r.receiver), AllowlistKey(r.en)}] = &r;
        }
        for (const char* n : kContextNames) context_names.insert(AllowlistKey(n));
        query_text = {AllowlistKey(kQueryTextRu), AllowlistKey(kQueryTextEn)};
        property_method = {AllowlistKey(kPropertyMethodRu), AllowlistKey(kPropertyMethodEn)};
        eval_member = {AllowlistKey(kEvalMemberRu), AllowlistKey(kEvalMemberEn)};
    }
};

const Tables& T() {
    static const Tables tables;
    return tables;
}

// ---- types and environments --------------------------------------------------------------------------------------

struct VType {
    Ty ty = Ty::Unknown;
    bool maybe_unassigned = false;               // assigned on some paths only
    const Expr* site = nullptr;                  // Query: the "Новый Запрос" node
    std::shared_ptr<const ColumnSet> columns;    // QueryResult / Selection / ValueTable / TableRow
};

bool SameColumns(const std::shared_ptr<const ColumnSet>& a, const std::shared_ptr<const ColumnSet>& b) {
    if (a == b) return true;
    return a && b && *a == *b;
}

VType Typed(Ty ty) {
    VType v;
    v.ty = ty;
    return v;
}

// Two values that may reach the same place. Different types, or different Запрос objects, join to Unknown.
VType JoinType(const VType& a, const VType& b) {
    VType r;
    r.maybe_unassigned = a.maybe_unassigned || b.maybe_unassigned;
    if (a.ty != b.ty) return r;
    if (a.ty == Ty::Query && a.site != b.site) return r;
    r.ty = a.ty;
    r.site = a.site;
    if (SameColumns(a.columns, b.columns)) r.columns = a.columns;
    return r;
}

using Env = std::map<std::string, VType>;

VType MaybeUnassigned() {
    VType v;
    v.maybe_unassigned = true;
    return v;
}

Env JoinEnv(const Env& a, const Env& b) {
    Env out;
    for (const auto& kv : a) {
        const auto it = b.find(kv.first);
        out[kv.first] = it == b.end() ? MaybeUnassigned() : JoinType(kv.second, it->second);
    }
    for (const auto& kv : b) {
        if (a.find(kv.first) == a.end()) out[kv.first] = MaybeUnassigned();
    }
    return out;
}

void Demote(Env& env, const std::set<std::string>& names) {
    for (const std::string& n : names) {
        const auto it = env.find(n);
        if (it == env.end()) {
            env[n] = MaybeUnassigned();
        } else {
            const bool flag = it->second.maybe_unassigned;
            it->second = VType();
            it->second.maybe_unassigned = flag;
        }
    }
}

bool IsStringLit(const Expr& e) { return e.kind == Expr::K::Lit && e.lit == Expr::L::String; }

// A literal, or a concatenation of literals. Nothing else counts as constant (Task 25 may widen this).
bool Fold(const Expr& e, std::string& out) {
    if (IsStringLit(e)) {
        out = e.text;
        return true;
    }
    if (e.kind == Expr::K::Binary && e.text == "+" && e.args.size() == 2) {
        std::string left, right;
        if (!Fold(*e.args[0], left) || !Fold(*e.args[1], right)) return false;
        out = left + right;
        return true;
    }
    return false;
}

// ---- variables assigned inside a block (loops and Попытка demote them) ----------------------------------------------

void CollectExpr(const Expr& e, std::set<std::string>& out) {
    if (e.kind == Expr::K::MethodCall && e.args.size() == 3 && e.args[2] && e.args[2]->kind == Expr::K::Var &&
        T().property_method.count(AllowlistKey(e.text))) {
        out.insert(AllowlistKey(e.args[2]->text));
    }
    for (const ExprP& a : e.args) {
        if (a) CollectExpr(*a, out);
    }
}

void CollectBody(const Body& b, std::set<std::string>& out);

void CollectStmt(const Stmt& s, std::set<std::string>& out) {
    if (s.kind == Stmt::K::Assign && !s.exprs.empty() && s.exprs[0] && s.exprs[0]->kind == Expr::K::Var) {
        out.insert(AllowlistKey(s.exprs[0]->text));
    }
    if (s.kind == Stmt::K::ForEach || s.kind == Stmt::K::ForTo) out.insert(AllowlistKey(s.var));
    for (const ExprP& e : s.exprs) {
        if (e) CollectExpr(*e, out);
    }
    for (const Body& b : s.blocks) CollectBody(b, out);
}

void CollectBody(const Body& b, std::set<std::string>& out) {
    for (const StmtP& s : b.stmts) {
        if (s) CollectStmt(*s, out);
    }
}

// ---- the checker -----------------------------------------------------------------------------------------------------

class Checker {
public:
    explicit Checker(const TypeCheckOptions& options) : options_(options) {}

    CodeAnalysis Run(const Body& body) {
        ParseError err;
        if (!ValidateBody(body, err)) {
            Add(err.code.empty() ? "C_PARSE" : err.code.c_str(), err.pos);
        } else {
            Block(body);
        }
        result_.verdict = result_.reasons.empty() ? CodeVerdict::Safe : CodeVerdict::Confirm;
        return std::move(result_);
    }

private:
    const TypeCheckOptions& options_;
    CodeAnalysis result_;
    Env env_;
    std::set<std::pair<std::string, size_t>> seen_;
    std::map<std::string, std::string> spelling_;   // allowlist key -> first spelling (upper case, ё kept)

    void Add(const char* code, const Pos& pos) {
        if (!seen_.insert({code, pos.offset}).second) return;
        result_.reasons.push_back(CodeReason{code, pos});
    }

    // The environment key of a variable. Two spellings that differ only in ё / е are reported.
    std::string VarKey(const std::string& name, const Pos& pos) {
        const std::string key = AllowlistKey(name);
        const std::string raw = NormalizeIdentifierKey(name);
        const auto it = spelling_.find(key);
        if (it == spelling_.end()) {
            spelling_[key] = raw;
        } else if (it->second != raw) {
            Add("C_AMBIGUOUS_IDENT", pos);
        }
        return key;
    }

    void Block(const Body& b) {
        for (const StmtP& s : b.stmts) Statement(*s);
    }

    // ---- expressions ----

    // `recv` is true when the value is only used as the receiver of a call, member or index.
    // A Запрос value outside a receiver position (argument, element, copy) is C_QUERY_ESCAPES; the one exception is
    // the allocation assigned straight to a variable.
    VType Eval(const Expr& e, bool recv = false) {
        const VType t = EvalInner(e, recv);
        if (!recv && t.ty == Ty::Query) Add("C_QUERY_ESCAPES", e.pos);
        return t;
    }

    VType EvalInner(const Expr& e, bool recv) {
        switch (e.kind) {
            case Expr::K::Lit: return EvalLit(e);
            case Expr::K::Var: return EvalVar(e);
            case Expr::K::Member: return EvalMember(e);
            case Expr::K::Index: return EvalIndex(e);
            case Expr::K::Call: return EvalCall(e);
            case Expr::K::MethodCall: return EvalMethod(e);
            case Expr::K::New: return EvalNew(e);
            case Expr::K::Ternary: return EvalTernary(e);
            case Expr::K::Unary:
                Eval(*e.args[0]);
                return Typed(e.text == "-" ? Ty::Number : Ty::Boolean);
            case Expr::K::Binary: return EvalBinary(e);
            default: Add("C_PARSE", e.pos); return VType();
        }
    }

    static VType EvalLit(const Expr& e) {
        switch (e.lit) {
            case Expr::L::Number: return Typed(Ty::Number);
            case Expr::L::String: return Typed(Ty::String);
            case Expr::L::Date: return Typed(Ty::Date);
            case Expr::L::True:
            case Expr::L::False: return Typed(Ty::Boolean);
            case Expr::L::Undefined: return Typed(Ty::Undefined);
            case Expr::L::Null: return Typed(Ty::Null);
            default: return VType();
        }
    }

    VType EvalVar(const Expr& e) {
        const std::string key = VarKey(e.text, e.pos);
        const auto it = env_.find(key);
        if (it == env_.end() || it->second.maybe_unassigned) {
            Add("C_UNKNOWN_IDENT", e.pos);
            return VType();
        }
        return it->second;
    }

    static VType ColumnType(const ColumnInfo& c) {
        VType v;
        if (!c.refs.empty()) v.ty = Ty::Ref;
        return v;
    }

    VType EvalMember(const Expr& e) {
        const VType obj = Eval(*e.args[0], true);
        const std::string key = AllowlistKey(e.text);
        if (obj.ty == Ty::Unknown) {
            Add("C_UNKNOWN_RECEIVER", e.pos);
            return VType();
        }
        if (obj.ty == Ty::Selection || obj.ty == Ty::TableRow) {
            if (obj.columns) {
                const auto it = obj.columns->columns.find(key);
                if (it != obj.columns->columns.end()) return ColumnType(it->second);
            }
            Add("C_UNKNOWN_MEMBER", e.pos);
            return VType();
        }
        const auto it = T().properties.find({static_cast<int>(obj.ty), key});
        if (it == T().properties.end()) {
            Add("C_UNKNOWN_MEMBER", e.pos);
            return VType();
        }
        return Typed(it->second->result);
    }

    VType EvalIndex(const Expr& e) {
        const VType obj = Eval(*e.args[0], true);
        Eval(*e.args[1]);
        return IndexResult(obj, *e.args[1], e.pos);
    }

    // Shared by reads and writes of "obj[index]".
    VType IndexResult(const VType& obj, const Expr& index, const Pos& pos) {
        switch (obj.ty) {
            case Ty::Unknown:
                Add("C_UNKNOWN_RECEIVER", pos);
                return VType();
            case Ty::ValueTable: {
                VType row = Typed(Ty::TableRow);
                row.columns = obj.columns;
                return row;
            }
            case Ty::Array:
                return VType();
            case Ty::Structure:
                if (!IsStringLit(index)) Add("C_DYNAMIC_KEY", index.pos);
                return VType();
            case Ty::Map:
                if (index.kind != Expr::K::Lit) Add("C_DYNAMIC_KEY", index.pos);
                return VType();
            default:
                Add("C_UNKNOWN_INDEX", pos);
                return VType();
        }
    }

    bool CheckArity(int given, int min_args, int max_args, const Pos& pos) {
        if (given >= min_args && given <= max_args) return true;
        Add("C_BAD_ARGS", pos);
        return false;
    }

    VType EvalCall(const Expr& e) {
        for (const ExprP& a : e.args) Eval(*a);
        const auto it = T().globals.find(AllowlistKey(e.text));
        if (it == T().globals.end()) {
            Add("C_UNKNOWN_IDENT", e.pos);
            return VType();
        }
        const GlobalRule& rule = *it->second;
        if (CheckArity(static_cast<int>(e.args.size()), rule.min_args, rule.max_args, e.pos) &&
            rule.arg0 == ArgRule::LiteralString && !IsStringLit(*e.args[0])) {
            Add("C_DYNAMIC_KEY", e.args[0]->pos);
        }
        return Typed(rule.result);
    }

    VType EvalNew(const Expr& e) {
        for (const ExprP& a : e.args) Eval(*a);
        const auto it = T().news.find(AllowlistKey(e.text));
        if (it == T().news.end()) {
            Add("C_UNKNOWN_TYPE", e.pos);
            return VType();
        }
        const NewRule& rule = *it->second;
        CheckArity(static_cast<int>(e.args.size()), rule.min_args, rule.max_args, e.pos);
        VType v = Typed(rule.result);
        if (rule.result == Ty::Query) {
            v.site = &e;
            if (e.args.size() == 1) NoteQueryText(&e, *e.args[0]);
        }
        return v;
    }

    void NoteQueryText(const Expr* site, const Expr& text_expr) {
        QueryTextUse use;
        if (!Fold(text_expr, use.text)) {
            Add("C_DYNAMIC_QUERY", text_expr.pos);
            return;
        }
        use.site = site;
        use.text_expr = &text_expr;
        result_.query_texts.push_back(std::move(use));
    }

    VType EvalMethod(const Expr& e) {
        const Expr& recv_expr = *e.args[0];
        const int nargs = static_cast<int>(e.args.size()) - 1;
        if (recv_expr.kind == Expr::K::Var && Unassigned(recv_expr)) {
            // "Имя.Метод(...)" on a name the code never assigned: a module call, or a context object.
            for (int i = 1; i <= nargs; ++i) Eval(*e.args[i]);
            const bool context = T().context_names.count(AllowlistKey(recv_expr.text)) != 0;
            Add(context ? "C_UNKNOWN_IDENT" : "C_COMMON_MODULE", recv_expr.pos);
            return VType();
        }
        const VType recv = Eval(recv_expr, true);
        const std::string key = AllowlistKey(e.text);
        if (T().eval_member.count(key)) Add("C_EVAL", e.pos);

        const MethodRule* rule = nullptr;
        if (recv.ty == Ty::Unknown) {
            Add("C_UNKNOWN_RECEIVER", e.pos);
        } else {
            const auto it = T().methods.find({static_cast<int>(recv.ty), key});
            if (it == T().methods.end()) {
                Add("C_UNKNOWN_METHOD", e.pos);
            } else {
                rule = it->second;
            }
        }
        const bool out_param = rule && nargs == 2 && T().property_method.count(key);
        for (int i = 1; i <= nargs; ++i) {
            if (!(out_param && i == 2)) Eval(*e.args[i]);
        }
        if (!rule) return VType();
        if (out_param) AssignOutParam(*e.args[2]);
        if (CheckArity(nargs, rule->min_args, rule->max_args, e.pos) && rule->arg0 == ArgRule::LiteralString &&
            !IsStringLit(*e.args[1])) {
            Add(rule->receiver == Ty::Query ? "C_DYNAMIC_PARAM" : "C_DYNAMIC_KEY", e.args[1]->pos);
        }
        return MethodResult(*rule, recv);
    }

    VType MethodResult(const MethodRule& rule, const VType& recv) {
        VType v = Typed(rule.result);
        if (recv.ty == Ty::Query && rule.result == Ty::QueryResult) {
            if (options_.columns_for_query) v.columns = options_.columns_for_query(recv.site);
        } else if (recv.ty == Ty::QueryResult && (rule.result == Ty::Selection || rule.result == Ty::ValueTable)) {
            v.columns = recv.columns;
        }
        return v;
    }

    bool Unassigned(const Expr& var) {
        const std::string key = VarKey(var.text, var.pos);
        return env_.find(key) == env_.end();
    }

    void AssignOutParam(const Expr& target) {
        if (target.kind != Expr::K::Var) {
            Add("C_BAD_ARGS", target.pos);
            return;
        }
        AssignVar(target, VType());
    }

    VType EvalTernary(const Expr& e) {
        Eval(*e.args[0]);
        const Env before = env_;
        const VType a = Eval(*e.args[1]);
        const Env after_a = env_;
        env_ = before;
        const VType b = Eval(*e.args[2]);
        env_ = JoinEnv(after_a, env_);
        return JoinType(a, b);
    }

    VType EvalBinary(const Expr& e) {
        const VType a = Eval(*e.args[0]);
        const std::string& op = e.text;
        const bool logic = op == "И" || op == "ИЛИ";
        const Env before = env_;
        const VType b = Eval(*e.args[1]);
        if (logic) env_ = JoinEnv(before, env_);   // the right side may not run
        if (logic || op == "=" || op == "<>" || op == "<" || op == ">" || op == "<=" || op == ">=") {
            return Typed(Ty::Boolean);
        }
        if (a.ty == Ty::Number && b.ty == Ty::Number) return Typed(Ty::Number);
        if (op == "+" && a.ty == Ty::String && b.ty == Ty::String) return Typed(Ty::String);
        return VType();
    }

    // ---- statements ----

    void AssignVar(const Expr& target, const VType& value) {
        const std::string key = VarKey(target.text, target.pos);
        if (T().context_names.count(key)) {
            Add("C_UNKNOWN_IDENT", target.pos);
            return;
        }
        VType v = value;
        v.maybe_unassigned = false;
        env_[key] = std::move(v);
    }

    void Assign(const Stmt& s) {
        const Expr& target = *s.exprs[0];
        const Expr& value_expr = *s.exprs[1];
        const VType value = Eval(value_expr, target.kind == Expr::K::Var && value_expr.kind == Expr::K::New);
        if (target.kind == Expr::K::Var) {
            AssignVar(target, value);
        } else if (target.kind == Expr::K::Member) {
            const VType obj = Eval(*target.args[0], true);
            if (obj.ty == Ty::Unknown) {
                Add("C_UNKNOWN_RECEIVER", target.pos);
            } else if (obj.ty == Ty::Query && T().query_text.count(AllowlistKey(target.text))) {
                NoteQueryText(obj.site, value_expr);
            } else {
                Add("C_UNKNOWN_MEMBER", target.pos);
            }
        } else {
            const VType obj = Eval(*target.args[0], true);
            Eval(*target.args[1]);
            if (obj.ty == Ty::Array || obj.ty == Ty::Structure || obj.ty == Ty::Map) {
                IndexResult(obj, *target.args[1], target.pos);
            } else if (obj.ty == Ty::Unknown) {
                Add("C_UNKNOWN_RECEIVER", target.pos);
            } else {
                Add("C_UNKNOWN_INDEX", target.pos);
            }
        }
    }

    void If(const Stmt& s) {
        std::vector<Env> outs;
        for (size_t i = 0; i < s.exprs.size(); ++i) {
            Eval(*s.exprs[i]);
            const Env base = env_;   // the state when this condition is false
            Block(s.blocks[i]);
            outs.push_back(env_);
            env_ = base;
        }
        if (s.has_else) Block(s.blocks[s.exprs.size()]);
        outs.push_back(env_);
        env_ = outs[0];
        for (size_t i = 1; i < outs.size(); ++i) env_ = JoinEnv(env_, outs[i]);
    }

    // The body of any loop: variables assigned anywhere in it are Unknown at the head and after the loop.
    void Loop(const Stmt& s, const Expr* condition, const std::string* loop_var, const Pos& var_pos,
              const VType& element) {
        std::set<std::string> assigned;
        CollectBody(s.blocks[0], assigned);
        if (condition) CollectExpr(*condition, assigned);
        if (loop_var) assigned.insert(AllowlistKey(*loop_var));
        Demote(env_, assigned);
        const Env head = env_;
        if (condition) Eval(*condition);
        if (loop_var) {
            const std::string key = VarKey(*loop_var, var_pos);
            if (T().context_names.count(key)) {
                Add("C_UNKNOWN_IDENT", var_pos);
            } else {
                env_[key] = element;
            }
        }
        Block(s.blocks[0]);
        env_ = head;
    }

    void ForEach(const Stmt& s) {
        const VType coll = Eval(*s.exprs[0]);
        VType element;
        if (coll.ty == Ty::ValueTable) {
            element = Typed(Ty::TableRow);
            element.columns = coll.columns;
        } else if (coll.ty == Ty::Unknown) {
            Add("C_UNKNOWN_RECEIVER", s.exprs[0]->pos);
        } else if (coll.ty != Ty::Array) {
            Add("C_UNKNOWN_ITER", s.exprs[0]->pos);
        }
        Loop(s, nullptr, &s.var, s.pos, element);
    }

    void Try(const Stmt& s) {
        std::set<std::string> assigned;
        CollectBody(s.blocks[0], assigned);
        Env except_env = env_;
        Demote(except_env, assigned);   // the body may stop after any statement
        Block(s.blocks[0]);
        const Env after_body = env_;
        env_ = except_env;
        Block(s.blocks[1]);
        env_ = JoinEnv(after_body, env_);
    }

    void Statement(const Stmt& s) {
        switch (s.kind) {
            case Stmt::K::Assign: Assign(s); break;
            case Stmt::K::CallStmt: Eval(*s.exprs[0]); break;
            case Stmt::K::If: If(s); break;
            case Stmt::K::ForEach: ForEach(s); break;
            case Stmt::K::ForTo:
                Eval(*s.exprs[0]);
                Eval(*s.exprs[1]);
                Loop(s, nullptr, &s.var, s.pos, Typed(Ty::Number));
                break;
            case Stmt::K::While: Loop(s, s.exprs[0].get(), nullptr, s.pos, VType()); break;
            case Stmt::K::Try: Try(s); break;
            case Stmt::K::Break:
            case Stmt::K::Continue: break;   // the loop exit state is the (already widened) loop head
            default: Add("C_PARSE", s.pos); break;
        }
    }
};

}  // namespace

CodeAnalysis AnalyzeCodeTypes(const Body& body, const TypeCheckOptions& options) {
    Checker checker(options);
    return checker.Run(body);
}

}  // namespace lineage::bsl
