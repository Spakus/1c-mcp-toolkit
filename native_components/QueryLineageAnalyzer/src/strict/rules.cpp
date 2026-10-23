#include "strict/rules.h"

#include <string>

namespace lineage::strict {

namespace {

enum class Ctx { SelectList, Condition, GroupBy, OrderBy, Totals, VtParam, JoinOn };

bool IsConditionCtx(Ctx c) { return c == Ctx::Condition || c == Ctx::JoinOn || c == Ctx::VtParam; }

// Anything that may hold protected content. Unknown is reported by its own rule.
bool Tainted(Origin o) {
    return o == Origin::ProtectedDirect || o == Origin::ProtectedDerived || o == Origin::Mixed;
}

bool IsLiteral(const Expr& e) {
    switch (e.kind) {
        case Expr::K::StringLit:
        case Expr::K::NumberLit:
        case Expr::K::BoolLit:
        case Expr::K::NullLit:
        case Expr::K::UndefinedLit: return true;
        default: return false;
    }
}

bool IsComparison(const std::string& op) {
    return op == "<>" || op == "<" || op == ">" || op == "<=" || op == ">=";
}

bool IsLogicalOp(const std::string& op) { return op == "И" || op == "ИЛИ" || op == "AND" || op == "OR"; }

class RuleEngine {
public:
    RuleEngine(const FieldPolicy& policy, const LabelTable& labels, AnalysisResult& out)
        : policy_(policy), labels_(labels), out_(out) {}

    void Run(const Batch& batch) {
        for (const Statement& st : batch.statements) {
            if (st.kind == Statement::K::Select && st.select) CheckSelect(*st.select);
        }
        CheckOutputColumns();
        for (const Statement& st : batch.statements) {
            if (st.kind == Statement::K::Select && st.select && st.select->into.empty()) CheckResultSet(*st.select);
        }
        MirrorResolution();
    }

private:
    const FieldPolicy& policy_;
    const LabelTable& labels_;
    AnalysisResult& out_;

    void Add(const char* code, const Pos& pos) {
        for (const Reason& r : out_.reasons) {
            if (r.code == code && r.pos.offset == pos.offset) return;
        }
        out_.reasons.push_back(Reason{code, pos});
    }

    Origin LabelOf(const Expr* e) const {
        if (e == nullptr) return Origin::Unknown;
        const auto it = labels_.expr.find(e);
        return it == labels_.expr.end() ? Origin::Unknown : it->second.origin;   // unlabelled: fail closed
    }

    bool TaintedExpr(const ExprP& e) const { return e && Tainted(LabelOf(e.get())); }

    // Join of the returned columns of a subquery; Unknown if they cannot be enumerated.
    Origin SubqueryOrigin(const Select& s) const {
        const auto it = labels_.select_columns.find(&s);
        if (it == labels_.select_columns.end() || it->second.empty()) return Origin::Unknown;
        Origin o = it->second[0].origin;
        for (size_t i = 1; i < it->second.size(); ++i) o = JoinOrigin(o, it->second[i].origin);
        return o;
    }

    // ---- output and resolution ----

    void CheckOutputColumns() {
        for (const ColumnLabel& c : out_.columns) {
            switch (c.origin) {
                case Origin::Mixed: Add("Q_MIXED_COLUMN", c.pos); break;
                case Origin::Unknown: Add("Q_UNKNOWN_COLUMN", c.pos); break;
                case Origin::ProtectedDerived: Add("Q_FUNC_OVER_PROTECTED", c.pos); break;   // safety net
                default: break;
            }
        }
    }

    // Every statement that returns rows to the client (not ПОМЕСТИТЬ), whether or not it is the last one.
    void CheckResultSet(const Select& s) {
        const auto it = labels_.select_columns.find(&s);
        if (it == labels_.select_columns.end()) {
            Add("Q_UNKNOWN_COLUMN", s.pos);
            return;
        }
        for (size_t i = 0; i < it->second.size(); ++i) {
            const Pos& pos = it->second.size() == s.items.size() ? s.items[i].pos : s.pos;
            switch (it->second[i].origin) {
                case Origin::Mixed: Add("Q_MIXED_COLUMN", pos); break;
                case Origin::Unknown: Add("Q_UNKNOWN_COLUMN", pos); break;
                case Origin::ProtectedDerived: Add("Q_FUNC_OVER_PROTECTED", pos); break;
                default: break;
            }
        }
    }

    // A literal as an ordering / grouping item may be read by the platform as a column ordinal.
    void CheckOrdinal(const ExprP& e) {
        if (e && IsLiteral(*e)) Add("Q_ORDER_PROTECTED", e->pos);
    }

    void MirrorResolution() {
        for (const ResolveIssue& issue : out_.resolution_issues) {
            const std::string code = "Q_" + issue.code;   // RESOLVE_X -> Q_RESOLVE_X
            bool have = false;
            for (const Reason& r : out_.reasons) have = have || (r.code == code && r.pos.offset == issue.pos.offset);
            if (!have) out_.reasons.push_back(Reason{code, issue.pos});
        }
        if (!out_.missing_tables.empty()) out_.reasons.push_back(Reason{"Q_INCOMPLETE", Pos()});
        const bool clean = out_.reasons.empty() && out_.missing_tables.empty() && out_.resolution_issues.empty();
        out_.verdict = clean ? Verdict::Safe : Verdict::Confirm;
    }

    // ---- statements ----

    void CheckSource(const Source& src) {
        if (src.kind == Source::K::Subquery && src.subquery) CheckSelect(*src.subquery);
        if (src.kind != Source::K::VirtualTable) return;
        for (const ExprP& p : src.vt_params) {
            if (p) CheckVtParam(*p);
        }
    }

    // Task 18 resolves these against the base table and applies the condition rules. Until then only a constant,
    // a client parameter or a plain date function over those is accepted.
    void CheckVtParam(const Expr& e) {
        switch (e.kind) {
            case Expr::K::StringLit:
            case Expr::K::NumberLit:
            case Expr::K::BoolLit:
            case Expr::K::NullLit:
            case Expr::K::UndefinedLit:
            case Expr::K::ValueFn:
            case Expr::K::TypeFn: return;
            case Expr::K::Param:
                if (policy_.OriginOfParam(e.text) != ParamOrigin::Client) Add("Q_VT_PARAM", e.pos);
                return;
            case Expr::K::Unary:
            case Expr::K::Binary: break;
            case Expr::K::Call:
                if (ClassifyCall(e.text) != CallClass::Plain) {
                    Add("Q_VT_PARAM", e.pos);
                    return;
                }
                break;
            default: Add("Q_VT_PARAM", e.pos); return;
        }
        const int period = e.kind == Expr::K::Call ? PeriodArgIndex(e.text) : -1;
        for (size_t i = 0; i < e.args.size(); ++i) {
            const ExprP& a = e.args[i];
            if (!a) {
                Add("Q_VT_PARAM", e.pos);
            } else if (static_cast<int>(i) == period && a->kind == Expr::K::Field && a->parts.size() == 1 &&
                       IsPeriodName(a->parts[0])) {
                continue;
            } else {
                CheckVtParam(*a);
            }
        }
    }

    bool AutoorderTainted(const Select& s) const {
        const auto it = labels_.select_columns.find(&s);
        if (it == labels_.select_columns.end()) return true;
        for (const Column& c : it->second) {
            if (Tainted(c.origin) || c.origin == Origin::Unknown) return true;
            // automatic ordering sorts a reference by its presentation
            for (const std::string& target : c.refs) {
                if (!policy_.HasTable(target) || policy_.PresentationClass(target) != FieldClass::Open) return true;
            }
        }
        return false;
    }

    void CheckSelect(const Select& s) {
        if (s.for_update) Add("Q_FOR_UPDATE", s.pos);
        for (const SelectItem& item : s.items) {
            if (item.wildcard) Add("Q_WILDCARD", item.pos);
            else if (item.expr) Walk(*item.expr, Ctx::SelectList, true);
            else Add("Q_UNKNOWN_COLUMN", item.pos);
        }
        for (size_t i = 0; i < s.from.size(); ++i) {
            CheckSource(s.from[i]);
            if (i >= s.joins.size()) continue;
            for (const Join& j : s.joins[i]) {
                CheckSource(j.source);
                WalkOpt(j.on, Ctx::JoinOn, j.pos, false);
            }
        }
        WalkOpt(s.where, Ctx::Condition, s.pos, false);
        for (const ExprP& g : s.group_by) {
            WalkOpt(g, Ctx::GroupBy, s.pos);
            CheckOrdinal(g);
        }
        WalkOpt(s.having, Ctx::Condition, s.pos, false);
        for (const ExprP& g : s.index_by) WalkOpt(g, Ctx::GroupBy, s.pos);

        bool ordering = false;
        for (const OrderItem& o : s.order_by) {
            WalkOpt(o.expr, Ctx::OrderBy, s.pos);
            if (o.expr && IsLiteral(*o.expr)) {
                CheckOrdinal(o.expr);
                ordering = true;
            }
            if (TaintedExpr(o.expr)) {
                Add("Q_ORDER_PROTECTED", o.expr->pos);
                ordering = true;
            }
        }
        if (s.autoorder && AutoorderTainted(s)) {
            Add("Q_ORDER_PROTECTED", s.pos);
            ordering = true;
        }
        if (ordering && !s.top.empty()) Add("Q_TOP_WITH_ORDER", s.pos);

        if (s.has_totals) Add("Q_TOTALS", s.pos);
        for (const ExprP& a : s.totals_aggregates) WalkOpt(a, Ctx::Totals, s.pos);
        for (const TotalsItem& t : s.totals_by) {
            if (t.periods) Add("Q_PERIODS", s.pos);
            WalkOpt(t.expr, Ctx::Totals, s.pos, false);
            CheckOrdinal(t.expr);
            for (const ExprP& a : t.periods_args) WalkOpt(a, Ctx::Totals, s.pos);
        }
        for (const Select::UnionPart& u : s.unions) {
            if (u.select) CheckSelect(*u.select);
        }
    }

    // A null slot is malformed (fail closed); `required` false: null is the normal "absent" (WHERE, ИТОГИ ОБЩИЕ).
    void WalkOpt(const ExprP& e, Ctx ctx, const Pos& parent, bool required = true) {
        if (e) Walk(*e, ctx, false);
        else if (required) Add("Q_UNKNOWN_EXPR", parent);
    }

    // ---- expressions ----

    bool ChildUnknown(const Expr& e) const {
        for (const ExprP& a : e.args) {
            if (!a || LabelOf(a.get()) == Origin::Unknown) return true;
        }
        return e.subquery && SubqueryOrigin(*e.subquery) == Origin::Unknown;
    }

    void Walk(const Expr& e, Ctx ctx, bool item_root) {
        const int period = e.kind == Expr::K::Call ? PeriodArgIndex(e.text) : -1;
        for (size_t i = 0; i < e.args.size(); ++i) {
            const ExprP& a = e.args[i];
            if (!a) {
                Add("Q_UNKNOWN_EXPR", e.pos);   // malformed node: fail closed
                continue;
            }
            if (static_cast<int>(i) == period && a->kind == Expr::K::Field && a->parts.size() == 1 &&
                IsPeriodName(a->parts[0])) {
                continue;
            }
            Walk(*a, ctx, false);
        }
        if (e.subquery) CheckSelect(*e.subquery);

        const bool unrecognized = e.kind == Expr::K::Call && ClassifyCall(e.text) == CallClass::Unrecognized;
        if (unrecognized) Add("Q_UNKNOWN_FUNCTION", e.pos);
        if (LabelOf(&e) == Origin::Unknown && !unrecognized) {
            if (item_root) Add("Q_UNKNOWN_COLUMN", e.pos);
            else if (!ChildUnknown(e)) Add("Q_UNKNOWN_EXPR", e.pos);
        }
        ApplyNodeRules(e, ctx, item_root);
    }

    // Reason for "a protected value is compared with `other`" when exactly one side is a direct protected read
    // (a bound token or a protected field). `la`/`lb` are the operand labels; `other` the non-protected operand.
    void EqRule(Origin la, Origin lb, const Expr* a, const Expr* b, Ctx ctx, const Pos& pos) {
        const bool ta = Tainted(la);
        const bool tb = Tainted(lb);
        if (!ta && !tb) return;
        if (!IsConditionCtx(ctx)) Add("Q_FUNC_OVER_PROTECTED", pos);   // a computed bit of a protected value
        if (la == Origin::ProtectedDirect && lb == Origin::ProtectedDirect) return;
        if ((ta && la != Origin::ProtectedDirect) || (tb && lb != Origin::ProtectedDirect)) {
            Add("Q_COMPARE_PROTECTED", pos);
            return;
        }
        const Expr* other = ta ? b : a;
        if (other != nullptr && other->kind == Expr::K::Param &&
            policy_.OriginOfParam(other->text) == ParamOrigin::TokenUnknown) {
            Add("Q_EQ_UNKNOWN_TOKEN", pos);
        } else if (other != nullptr && IsLiteral(*other)) {
            Add("Q_EQ_LITERAL", pos);
        } else {
            Add("Q_EQ_CLIENT_PARAM", pos);   // client parameter, client column or an open (client-readable) column
        }
    }

    void ApplyNodeRules(const Expr& e, Ctx ctx, bool item_root) {
        const bool any = AnyArgTainted(e);
        switch (e.kind) {
            case Expr::K::Call: CallRules(e, ctx, item_root, any); break;
            case Expr::K::Cast:
            case Expr::K::Case:
            case Expr::K::IsNullTest:
                if (any) Add("Q_FUNC_OVER_PROTECTED", e.pos);
                break;
            case Expr::K::Unary: UnaryRules(e, ctx, any); break;
            case Expr::K::Binary: BinaryRules(e, ctx, any); break;
            case Expr::K::InList: InListRules(e, ctx); break;
            case Expr::K::InSubquery:
            case Expr::K::InHierarchy: InSubqueryRules(e, ctx); break;
            case Expr::K::Between:
                if (any) Add("Q_COMPARE_PROTECTED", e.pos);
                break;
            case Expr::K::Like:
                if (any) Add("Q_LIKE_PROTECTED", e.pos);
                break;
            default: break;   // leaves, ССЫЛКА type test, Row
        }
    }

    bool AnyArgTainted(const Expr& e) const {
        for (const ExprP& a : e.args) {
            if (TaintedExpr(a)) return true;
        }
        return false;
    }

    void CallRules(const Expr& e, Ctx ctx, bool item_root, bool any) {
        switch (ClassifyCall(e.text)) {
            case CallClass::Count: return;   // COUNT([DISTINCT] x) is an open number
            case CallClass::MinMax:
                if (any) Add("Q_MINMAX_PROTECTED", e.pos);
                return;
            case CallClass::Presentation:
                if (any) Add("Q_FUNC_OVER_PROTECTED", e.pos);   // a presentation of a protected scalar
                else if (Tainted(LabelOf(&e)) && !(item_root && ctx == Ctx::SelectList)) Add("Q_PRESENTATION", e.pos);
                return;
            case CallClass::Sum:
            case CallClass::TypeOf:
            case CallClass::Plain:
                if (any) Add("Q_FUNC_OVER_PROTECTED", e.pos);
                return;
            case CallClass::Unrecognized: return;   // Q_UNKNOWN_FUNCTION already added
        }
    }

    void UnaryRules(const Expr& e, Ctx ctx, bool any) {
        if (!any) return;
        const bool logical = e.text == "НЕ" || e.text == "NOT";
        if (!logical || !IsConditionCtx(ctx)) Add("Q_FUNC_OVER_PROTECTED", e.pos);
    }

    void BinaryRules(const Expr& e, Ctx ctx, bool any) {
        if (e.args.size() != 2 || !e.args[0] || !e.args[1]) {
            Add("Q_UNKNOWN_EXPR", e.pos);
            return;
        }
        if (!any) return;
        if (e.text == "=") {
            EqRule(LabelOf(e.args[0].get()), LabelOf(e.args[1].get()), e.args[0].get(), e.args[1].get(), ctx, e.pos);
        } else if (IsComparison(e.text)) {
            Add("Q_COMPARE_PROTECTED", e.pos);
            if (!IsConditionCtx(ctx)) Add("Q_FUNC_OVER_PROTECTED", e.pos);
        } else if (IsLogicalOp(e.text)) {
            if (!IsConditionCtx(ctx)) Add("Q_FUNC_OVER_PROTECTED", e.pos);
        } else {
            Add("Q_FUNC_OVER_PROTECTED", e.pos);   // arithmetic (and any operator this engine does not know)
        }
    }

    void InListRules(const Expr& e, Ctx ctx) {
        if (e.args.empty() || !e.args[0]) {
            Add("Q_UNKNOWN_EXPR", e.pos);
            return;
        }
        const Origin l0 = LabelOf(e.args[0].get());
        for (size_t i = 1; i < e.args.size(); ++i) {
            if (!e.args[i]) continue;
            EqRule(l0, LabelOf(e.args[i].get()), e.args[0].get(), e.args[i].get(), ctx, e.pos);
        }
    }

    void InSubqueryRules(const Expr& e, Ctx ctx) {
        if (e.args.empty() || !e.args[0]) {
            Add("Q_UNKNOWN_EXPR", e.pos);
            return;
        }
        const Origin l0 = LabelOf(e.args[0].get());
        const Origin ls = e.subquery ? SubqueryOrigin(*e.subquery) : Origin::Unknown;
        if (e.kind == Expr::K::InHierarchy) {
            if (Tainted(l0) || Tainted(ls) || AnyArgTainted(e)) Add("Q_COMPARE_PROTECTED", e.pos);
            return;
        }
        EqRule(l0, ls, e.args[0].get(), nullptr, ctx, e.pos);
    }
};

}  // namespace

void ApplyRules(const Batch& batch, const FieldPolicy& policy, const LabelTable& labels, AnalysisResult& result) {
    RuleEngine engine(policy, labels, result);
    engine.Run(batch);
}

}  // namespace lineage::strict
