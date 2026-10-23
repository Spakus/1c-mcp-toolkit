#include "test_framework.h"
#include "analysis_helpers.h"
#include "policy_fixture.h"

#include <string>

using namespace lineage::strict;

namespace {

Origin FirstOrigin(const AnalysisResult& r) {
    if (r.columns.empty()) {
        CHECK_EQ(r.reasons.empty() ? std::string("no columns") : r.reasons[0].code, std::string("columns"));
    }
    return r.columns.at(0).origin;
}

}  // namespace

TEST(Origin, ResolvesAliasImplicitAliasAndTempTable) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Имя ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; ВЫБРАТЬ ВТ.Имя ИЗ ВТ КАК ВТ");
    CHECK_EQ(r.columns.at(0).origin, Origin::ProtectedDirect);
}

TEST(Origin, AmbiguousUnqualifiedFieldIsUnknown) {
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Код КАК К ИЗ Справочник.А КАК А, Справочник.Б КАК Б");   // both have Код (bare Ссылка is a keyword)
    CHECK_EQ(r.columns.at(0).origin, Origin::Unknown);
    CHECK(HasIssue(r, kResolveAmbiguousName));
}

TEST(Origin, DereferenceFollowsRefs) {
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Б.СсылкаНаА.Имя КАК Н ИЗ Справочник.Б КАК Б");
    CHECK_EQ(r.columns.at(0).origin, Origin::ProtectedDirect);
}

TEST(Origin, MissingTableReported) {
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Вх.Х ИЗ Справочник.Нет КАК Вх");
    CHECK(r.missing_tables.count("Справочник.Нет") == 1);
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
}

TEST(Origin, ImplicitAliasOnlyWhenUnique) {
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А")), Origin::ProtectedDirect);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Справочник.А.Имя КАК Н ИЗ Справочник.А")),
             Origin::ProtectedDirect);
    // the same last segment from two sources: the implicit alias is not unique
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А, Документ.А");
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
    CHECK(HasIssue(r, kResolveAmbiguousName));
    // an explicit alias hides the table name
    auto hidden = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А КАК Х");
    CHECK_EQ(FirstOrigin(hidden), Origin::Unknown);
    CHECK(HasIssue(hidden, kResolveUnknownName));
}

TEST(Origin, UnqualifiedFieldInSingleSourceAndUnknownNames) {
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Имя КАК Н ИЗ Справочник.А КАК А")), Origin::ProtectedDirect);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Сумма КАК С ИЗ Справочник.А КАК А, Справочник.Б КАК Б")),
             Origin::Open);
    auto unknown_alias = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Ц.Имя КАК Н ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(unknown_alias), Origin::Unknown);
    CHECK(HasIssue(unknown_alias, kResolveUnknownName));
    // a field the policy does not list is Unknown, never open
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ А.Нет КАК Н ИЗ Справочник.А КАК А")), Origin::Unknown);
}

TEST(Origin, DuplicateAliasIsAmbiguous) {
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Х.Имя КАК Н ИЗ Справочник.А КАК Х, Справочник.Б КАК Х");
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
    CHECK(HasIssue(r, kResolveAmbiguousName));
}

TEST(Origin, TempTableLifecycle) {
    // used before it is created
    auto early = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ВТ.Имя ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(early), Origin::Unknown);
    CHECK(HasIssue(early, kResolveUnknownTemp));
    // destroyed, then used
    auto dropped = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Имя ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; УНИЧТОЖИТЬ ВТ; ВЫБРАТЬ ВТ.Имя ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(dropped), Origin::Unknown);
    CHECK(HasIssue(dropped, kResolveUnknownTemp));
    // destroying a table that does not exist
    CHECK(HasIssue(AnalyzeForTest(kPolicyAB, "УНИЧТОЖИТЬ ВТ; ВЫБРАТЬ 1 КАК Х"), kResolveUnknownTemp));
    // re-creation replaces the columns; the old protected column is gone
    auto replaced = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Х ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; УНИЧТОЖИТЬ ВТ; "
        "ВЫБРАТЬ Б.Сумма КАК Х ПОМЕСТИТЬ ВТ ИЗ Справочник.Б КАК Б; ВЫБРАТЬ ВТ.Х ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(replaced), Origin::Open);
    // the select that creates a table reads the old one of the same name
    auto self = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Х ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; ВЫБРАТЬ ВТ.Х КАК Х ПОМЕСТИТЬ ВТ ИЗ ВТ КАК ВТ; "
        "ВЫБРАТЬ ВТ.Х ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(self), Origin::ProtectedDirect);
    // lookup of the temp-table name is case-insensitive
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Имя ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; ВЫБРАТЬ вт.имя ИЗ вт КАК вт")), Origin::ProtectedDirect);
}

TEST(Origin, TempTableKeepsRefsForDereference) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.СсылкаНаА КАК К ПОМЕСТИТЬ ВТ ИЗ Справочник.Б КАК Б; ВЫБРАТЬ ВТ.К.Имя КАК Н ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(r), Origin::ProtectedDirect);
}

TEST(Origin, TempTableWithWildcardIsOpaque) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ * ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; ВЫБРАТЬ ВТ.Имя ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
}

TEST(Origin, SubqueryAsSourceAndCorrelatedSubquery) {
    auto derived = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Т.Х КАК Х ИЗ (ВЫБРАТЬ А.Имя КАК Х ИЗ Справочник.А КАК А) КАК Т");
    CHECK_EQ(FirstOrigin(derived), Origin::ProtectedDirect);
    // a derived table does not see the outer scope
    auto isolated = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Т.Х КАК Х ИЗ Справочник.А КАК А, (ВЫБРАТЬ А.Имя КАК Х ИЗ Справочник.Б КАК Б) КАК Т");
    CHECK(HasIssue(isolated, kResolveUnknownName));
    // a subquery in a condition sees the outer alias
    auto corr = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А КАК А ГДЕ А.Ссылка В (ВЫБРАТЬ Б.СсылкаНаА ИЗ Справочник.Б КАК Б ГДЕ Б.Сумма > А.Код)");
    // ... but only when no inner policy table could own the name (the policy might not list every field)
    CHECK(HasIssue(corr, kResolveAmbiguousName));
    // an alias visible at both levels is ambiguous (fail closed)
    auto shadow = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А КАК Т ГДЕ Т.Ссылка В (ВЫБРАТЬ Т.СсылкаНаА ИЗ Справочник.Б КАК Т)");
    CHECK(HasIssue(shadow, kResolveAmbiguousName));
    // missing table inside a nested query is still reported
    auto nested = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А КАК А ГДЕ А.Ссылка В (ВЫБРАТЬ Вх.Х ИЗ Справочник.Нет КАК Вх)");
    CHECK(nested.missing_tables.count("Справочник.Нет") == 1);
}

TEST(Origin, UnionJoinsColumnsPositionally) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Сумма КАК Х ИЗ Справочник.Б КАК Б ОБЪЕДИНИТЬ ВСЕ ВЫБРАТЬ А.Имя ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(r), Origin::Mixed);
    auto mismatch = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Сумма КАК Х ИЗ Справочник.Б КАК Б ОБЪЕДИНИТЬ ВЫБРАТЬ А.Имя, А.Код ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(mismatch), Origin::Unknown);
    CHECK(HasIssue(mismatch, kResolveColumnMismatch));
}

TEST(Origin, CompositeRefsJoinAllTargets) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Владелец":{"class":"open","refs":["Справочник.А","Справочник.Б"]}}},
        "Справочник.А":{"fields":{"Имя":{"class":"protected"}}},
        "Справочник.Б":{"fields":{"Имя":{"class":"open"}}},
        "Справочник.Ц":{"fields":{"Имя":{"class":"open"}}}}})");
    CHECK(p.ok);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ Д.Владелец.Имя КАК Н ИЗ Документ.Д КАК Д")), Origin::Mixed);
    // a target without the field makes the result Unknown
    auto q = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Владелец":{"class":"open","refs":["Справочник.А","Справочник.Ц"]}}},
        "Справочник.А":{"fields":{"Имя":{"class":"protected"}}},
        "Справочник.Ц":{"fields":{"Другое":{"class":"open"}}}}})");
    CHECK(q.ok);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(q.policy, "ВЫБРАТЬ Д.Владелец.Имя КАК Н ИЗ Документ.Д КАК Д")), Origin::Unknown);
    // a missing target table is reported
    auto m = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Владелец":{"class":"open","refs":["Справочник.Нет"]}}}}})");
    CHECK(m.ok);
    auto r = AnalyzeForTest(m.policy, "ВЫБРАТЬ Д.Владелец.Имя КАК Н ИЗ Документ.Д КАК Д");
    CHECK(r.missing_tables.count("Справочник.Нет") == 1);
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
}

TEST(Origin, PresentationSegmentUsesTablePresentationClass) {
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Б.СсылкаНаА.Представление КАК П ИЗ Справочник.Б КАК Б")),
             Origin::ProtectedDirect);
}

TEST(Origin, YoAndYeNeverMergeSilently) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"Справочник.Е":{"fields":{
        "Ёж":{"class":"protected"},"Ель":{"class":"open"}}}}})");
    CHECK(p.ok);
    // exact spelling resolves
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ Е.Ёж КАК Х ИЗ Справочник.Е КАК Е")), Origin::ProtectedDirect);
    // the other spelling is not the policy's field: Unknown, never open
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ Е.Еж КАК Х ИЗ Справочник.Е КАК Е")), Origin::Unknown);
    // result names that differ only by ё/е collide: the column list is not trusted
    auto t = AnalyzeForTest(p.policy,
        "ВЫБРАТЬ Е.Ёж КАК Ёж, Е.Ель КАК Еж ПОМЕСТИТЬ ВТ ИЗ Справочник.Е КАК Е; ВЫБРАТЬ ВТ.Еж ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(t), Origin::Unknown);
    CHECK(HasIssue(t, kResolveColumnMismatch));
    // a temp-table name spelled with the other letter is a different name: unknown, never a silent match
    auto d = AnalyzeForTest(p.policy,
        "ВЫБРАТЬ Е.Ёж КАК Х ПОМЕСТИТЬ Ёлка ИЗ Справочник.Е КАК Е; ВЫБРАТЬ Елка.Х ИЗ Елка КАК Елка");
    CHECK_EQ(FirstOrigin(d), Origin::Unknown);
    CHECK(HasIssue(d, kResolveUnknownTemp));
    // two temp tables that differ only by ё/е make either spelling unresolvable
    auto c = AnalyzeForTest(p.policy,
        "ВЫБРАТЬ Е.Ёж КАК Х ПОМЕСТИТЬ Ёлка ИЗ Справочник.Е КАК Е; ВЫБРАТЬ Е.Ель КАК Х ПОМЕСТИТЬ Елка ИЗ Справочник.Е КАК Е; "
        "ВЫБРАТЬ Елка.Х ИЗ Елка КАК Елка");
    CHECK_EQ(FirstOrigin(c), Origin::Unknown);
}

TEST(Origin, OrderByMayUseResultAlias) {
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А КАК А УПОРЯДОЧИТЬ ПО Н");
    CHECK(r.resolution_issues.empty());
    auto bad = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ А.Имя КАК Н ИЗ Справочник.А КАК А УПОРЯДОЧИТЬ ПО Нет");
    CHECK(HasIssue(bad, kResolveUnknownName));
}

TEST(Origin, ParseErrorBecomesReason) {
    auto r = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ИЗ");
    CHECK(!r.reasons.empty());
    CHECK(r.columns.empty());
}

TEST(Origin, ProtectedReferenceTaintsDereference) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Секрет":{"class":"protected","refs":["Справочник.А"]},
                                "Темный":{"class":"unknown","refs":["Справочник.А"]},
                                "Откр":{"class":"open","refs":["Справочник.А"]}}},
        "Справочник.А":{"fields":{"Код":{"class":"open"}}}}})");
    CHECK(p.ok);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ Д.Секрет.Код КАК К ИЗ Документ.Д КАК Д")),
             Origin::ProtectedDerived);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ Д.Темный.Код КАК К ИЗ Документ.Д КАК Д")), Origin::Unknown);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ Д.Откр.Код КАК К ИЗ Документ.Д КАК Д")), Origin::Open);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy,
        "ВЫБРАТЬ Д.Секрет КАК С ПОМЕСТИТЬ ВТ ИЗ Документ.Д КАК Д; ВЫБРАТЬ ВТ.С.Код КАК К ИЗ ВТ КАК ВТ")),
        Origin::ProtectedDerived);
}

TEST(Origin, UnionKeepsRefsOnlyWhenBothSidesHaveThem) {
    // the other branch is not a reference: a dereference of the merged column is a guess
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Ссылка КАК К ПОМЕСТИТЬ ВТ ИЗ Справочник.Б КАК Б ОБЪЕДИНИТЬ ВСЕ ВЫБРАТЬ Б.Сумма ИЗ Справочник.Б КАК Б; "
        "ВЫБРАТЬ ВТ.К.Код КАК Х ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
    auto c = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Ссылка КАК К ПОМЕСТИТЬ ВТ ИЗ Справочник.Б КАК Б ОБЪЕДИНИТЬ ВСЕ "
        "ВЫБРАТЬ ВЫБОР КОГДА А.Имя = \"x\" ТОГДА А.Ссылка КОНЕЦ ИЗ Справочник.А КАК А; "
        "ВЫБРАТЬ ВТ.К.Код КАК Х ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(c), Origin::Unknown);
}

TEST(Origin, UnknownResolutionAlwaysLeavesAnIssue) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"Справочник.Е":{"fields":{
        "Ёж":{"class":"protected"}}}}})");
    CHECK(p.ok);
    auto t = AnalyzeForTest(p.policy,
        "ВЫБРАТЬ Е.Ёж КАК Ёж ПОМЕСТИТЬ ВТ ИЗ Справочник.Е КАК Е; ВЫБРАТЬ ВТ.Еж КАК Х ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(t), Origin::Unknown);
    CHECK(!t.resolution_issues.empty());
    auto m = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя КАК Имя ПОМЕСТИТЬ ВТ ИЗ Справочник.А КАК А; ВЫБРАТЬ ВТ.Нет КАК Х ИЗ ВТ КАК ВТ");
    CHECK_EQ(FirstOrigin(m), Origin::Unknown);
    CHECK(!m.resolution_issues.empty());
    auto unlisted = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Б.СсылкаНаА.ПредставлениеСсылки КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(unlisted), Origin::Unknown);
    CHECK(HasIssue(unlisted, kResolveUnknownField));
    auto value = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ Б.СсылкаНаА.Значение КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(value), Origin::Unknown);
    CHECK(!value.resolution_issues.empty());
}
