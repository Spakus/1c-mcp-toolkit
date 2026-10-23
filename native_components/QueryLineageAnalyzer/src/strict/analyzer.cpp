#include "strict/analyzer.h"

#include <map>
#include <utility>

#include "strict/ast_dump.h"

namespace lineage::strict {

namespace {

constexpr int kMaxSelectDepth = 128;   // nesting of subqueries; the parser already caps it, this is a backstop

struct TempTable {
    std::vector<Column> columns;
    bool complete = true;
};

struct SelectOut {
    std::vector<Column> columns;
    std::vector<Pos> positions;
    bool complete = true;
};

class Analyzer {
public:
    Analyzer(const FieldPolicy& policy, AnalysisResult& out) : policy_(policy), out_(out) {
        sink_.missing_tables = &out.missing_tables;
        sink_.issues = &out.resolution_issues;
    }

    void Run(const Batch& batch) {
        for (size_t i = 0; i < batch.statements.size(); ++i) {
            const bool last = i + 1 == batch.statements.size();
            RunStatement(batch.statements[i], last);
        }
    }

private:
    const FieldPolicy& policy_;
    AnalysisResult& out_;
    ResolveSink sink_;
    std::map<std::string, TempTable> temps_;   // normalized temp-table name -> columns

    // Exact (normalized) match only. A name that matches another spelling after e/yo folding, or a table whose
    // spelling collides with another one, is not found: the tokenizer treats such near-collisions as ambiguous.
    const TempTable* FindTemp(const std::string& name) const {
        const std::string key = ScopeKey(name);
        const std::string folded = FoldedKey(name);
        const TempTable* found = nullptr;
        for (const auto& entry : temps_) {
            if (entry.first == key) found = &entry.second;
            else if (FoldedKey(entry.first) == folded) return nullptr;
        }
        return found;
    }

    void RunStatement(const Statement& st, bool last) {
        if (st.kind == Statement::K::Drop) {
            if (FindTemp(st.drop_name) == nullptr) sink_.Issue(kResolveUnknownTemp, st.pos);
            else temps_.erase(ScopeKey(st.drop_name));
            return;
        }
        if (!st.select) {
            sink_.Issue(kResolveBadStatement, st.pos);
            return;
        }
        SelectOut result = AnalyzeSelect(*st.select, nullptr, 0, true);
        if (!st.select->into.empty()) StoreTemp(*st.select, result);
        if (last) PublishColumns(result);
    }

    void StoreTemp(const Select& head, const SelectOut& result) {
        if (head.into.find('.') != std::string::npos) {
            sink_.Issue(kResolveBadStatement, head.pos);
            return;
        }
        TempTable table;
        table.columns = result.columns;
        table.complete = result.complete;
        temps_[ScopeKey(head.into)] = std::move(table);   // re-creating a name replaces the old table
    }

    void PublishColumns(const SelectOut& result) {
        for (size_t i = 0; i < result.columns.size(); ++i) {
            ColumnLabel label;
            label.name = result.columns[i].name;
            label.origin = result.columns[i].origin;
            label.refs = result.columns[i].refs;
            if (i < result.positions.size()) label.pos = result.positions[i];
            out_.columns.push_back(std::move(label));
        }
    }

    // ---- sources ----

    Binding BuildBinding(const Source& src, int depth) {
        Binding b;
        switch (src.kind) {
            case Source::K::Table: BuildTable(src, b); break;
            case Source::K::VirtualTable: BuildVirtualTable(src, b); break;
            case Source::K::Subquery: BuildSubquery(src, depth, b); break;
        }
        SetBindingNames(b, src.kind == Source::K::Subquery ? std::string() : src.name, src.alias);
        return b;
    }

    void BuildTable(const Source& src, Binding& b) {
        if (src.name.find('.') != std::string::npos) {
            b.kind = Binding::Kind::Table;
            b.table = src.name;
            b.known = policy_.HasTable(src.name);
            if (!b.known) {
                sink_.MissingTable(src.name);
                sink_.Issue(kResolveUnknownSource, src.pos);
            }
            return;
        }
        b.kind = Binding::Kind::Temp;   // a name without a dot can only be a temporary table
        const TempTable* temp = FindTemp(src.name);
        if (temp == nullptr) {
            b.known = false;
            sink_.Issue(kResolveUnknownTemp, src.pos);
            return;
        }
        b.columns = temp->columns;
        b.complete = temp->complete;
    }

    void BuildVirtualTable(const Source& src, Binding& b) {
        // The parameters are conditions over the register's own fields; the rule engine checks them (Task 18).
        b.kind = Binding::Kind::Table;
        b.table = src.name;
        b.known = src.name.find('.') != std::string::npos && !policy_.ResolveVirtualBase(src.name).empty();
        if (!b.known) {
            sink_.MissingTable(src.name);
            sink_.Issue(kResolveUnknownSource, src.pos);
        }
    }

    void BuildSubquery(const Source& src, int depth, Binding& b) {
        b.kind = Binding::Kind::Subquery;
        if (!src.subquery) {
            b.known = false;
            sink_.Issue(kResolveBadStatement, src.pos);
            return;
        }
        SelectOut r = AnalyzeSelect(*src.subquery, nullptr, depth + 1, false);   // a derived table sees no outer scope
        b.columns = std::move(r.columns);
        b.complete = r.complete;
    }

    // ---- expressions ----

    // `aliases` (ORDER BY / TOTALS only): result column names that a single-part path may refer to.
    FieldLabel Label(const Expr& e, const Scope& scope, int depth, const std::vector<std::string>* aliases) {
        if (e.kind == Expr::K::Field) {
            if (aliases != nullptr && e.parts.size() == 1) {
                const std::string key = FoldedKey(e.parts[0]);
                for (const std::string& name : *aliases) {
                    if (!name.empty() && FoldedKey(name) == key) return FieldLabel();
                }
            }
            return ResolveFieldPath(e.parts, e.pos, scope, policy_, sink_);
        }
        // Other expression kinds get their labels in Task 16; until then they are Unknown, but their operands
        // are still resolved so that unknown names and missing tables inside them are reported.
        for (const ExprP& a : e.args) {
            if (a) Label(*a, scope, depth, aliases);
        }
        if (e.subquery) AnalyzeSelect(*e.subquery, &scope, depth + 1, false);
        return FieldLabel();
    }

    void Walk(const ExprP& e, const Scope& scope, int depth, const std::vector<std::string>* aliases = nullptr) {
        if (e) Label(*e, scope, depth, aliases);
    }

    void WalkList(const std::vector<ExprP>& list, const Scope& scope, int depth,
                  const std::vector<std::string>* aliases = nullptr) {
        for (const ExprP& e : list) Walk(e, scope, depth, aliases);
    }

    // ---- queries ----

    Scope BuildScope(const Select& s, const Scope* parent, int depth) {
        Scope scope;
        scope.parent = parent;
        for (size_t i = 0; i < s.from.size(); ++i) {
            scope.bindings.push_back(BuildBinding(s.from[i], depth));
            if (i >= s.joins.size()) continue;
            for (const Join& j : s.joins[i]) scope.bindings.push_back(BuildBinding(j.source, depth));
        }
        return scope;
    }

    void WalkConditions(const Select& s, const Scope& scope, int depth) {
        for (size_t i = 0; i < s.joins.size(); ++i) {
            for (const Join& j : s.joins[i]) Walk(j.on, scope, depth);
        }
        Walk(s.where, scope, depth);
        WalkList(s.group_by, scope, depth);
        Walk(s.having, scope, depth);
    }

    void WalkOrderAndTotals(const Select& s, const Scope& scope, int depth, const std::vector<std::string>& names) {
        for (const OrderItem& o : s.order_by) Walk(o.expr, scope, depth, &names);
        WalkList(s.totals_aggregates, scope, depth, &names);
        for (const TotalsItem& t : s.totals_by) {
            Walk(t.expr, scope, depth, &names);
            WalkList(t.periods_args, scope, depth, &names);
        }
    }

    SelectOut LabelItems(const Select& head, const Scope& scope, int depth, const std::vector<std::string>& names,
                         bool names_ok) {
        SelectOut out;
        for (size_t i = 0; i < head.items.size(); ++i) {
            const SelectItem& item = head.items[i];
            Column col;
            if (names_ok && i < names.size()) col.name = names[i];
            if (item.wildcard) {
                out.complete = false;   // not expanded: the column list is no longer enumerable
            } else if (item.expr) {
                const FieldLabel l = Label(*item.expr, scope, depth, nullptr);
                col.origin = l.origin;
                col.refs = l.refs;
            }
            out.columns.push_back(std::move(col));
            out.positions.push_back(item.pos);
        }
        return out;
    }

    void JoinUnionPart(SelectOut& head, const SelectOut& part, const Pos& pos) {
        if (part.columns.size() != head.columns.size()) {
            sink_.Issue(kResolveColumnMismatch, pos);
            for (Column& c : head.columns) {
                c.origin = Origin::Unknown;
                c.refs.clear();
            }
            head.complete = false;
            return;
        }
        for (size_t i = 0; i < head.columns.size(); ++i) {
            head.columns[i].origin = JoinOrigin(head.columns[i].origin, part.columns[i].origin);
            // Targets survive only when BOTH sides are references; otherwise a dereference would be a guess.
            if (head.columns[i].refs.empty() || part.columns[i].refs.empty()) {
                head.columns[i].refs.clear();
                continue;
            }
            for (const std::string& r : part.columns[i].refs) {
                bool have = false;
                for (const std::string& h : head.columns[i].refs) have = have || ScopeKey(h) == ScopeKey(r);
                if (!have) head.columns[i].refs.push_back(r);
            }
        }
        head.complete = head.complete && part.complete;
    }

    SelectOut AnalyzeSelect(const Select& head, const Scope* parent, int depth, bool allow_into) {
        if (depth > kMaxSelectDepth) {
            sink_.Issue(kResolveBadStatement, head.pos);
            return SelectOut();
        }
        if (!allow_into && !head.into.empty()) sink_.Issue(kResolveBadStatement, head.pos);

        std::vector<std::string> names;
        const bool names_ok = ComputeResultNames(head, names);
        if (!names_ok) sink_.Issue(kResolveColumnMismatch, head.pos);   // colliding explicit aliases

        const Scope scope = BuildScope(head, parent, depth);
        WalkConditions(head, scope, depth);
        SelectOut out = LabelItems(head, scope, depth, names, names_ok);
        if (!names_ok) out.complete = false;
        WalkOrderAndTotals(head, scope, depth, names);

        for (const Select::UnionPart& u : head.unions) {
            if (!u.select) {
                sink_.Issue(kResolveBadStatement, head.pos);
                out.complete = false;
                continue;
            }
            const SelectOut part = AnalyzeSelect(*u.select, parent, depth + 1, false);
            JoinUnionPart(out, part, u.select->pos);
        }
        return out;
    }
};

}  // namespace

AnalysisResult AnalyzeQuery(const Batch& batch, const FieldPolicy& policy) {
    AnalysisResult result;
    Analyzer analyzer(policy, result);
    analyzer.Run(batch);
    return result;
}

}  // namespace lineage::strict
