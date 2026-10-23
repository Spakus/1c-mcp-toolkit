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

TEST(Origin, LatticeJoin) {
    CHECK(JoinOrigin(Origin::Open, Origin::Open) == Origin::Open);
    CHECK(JoinOrigin(Origin::ProtectedDirect, Origin::ProtectedDirect) == Origin::ProtectedDirect);
    CHECK(JoinOrigin(Origin::ProtectedDirect, Origin::Open) == Origin::Mixed);
    CHECK(JoinOrigin(Origin::ProtectedDirect, Origin::Client) == Origin::Mixed);
    CHECK(JoinOrigin(Origin::Client, Origin::Open) == Origin::Client);    // both public to the client
    CHECK(JoinOrigin(Origin::Unknown, Origin::Open) == Origin::Unknown);
    CHECK(JoinOrigin(Origin::Mixed, Origin::Unknown) == Origin::Unknown);
    CHECK(Transform(Origin::ProtectedDirect) == Origin::ProtectedDerived);
    CHECK(Transform(Origin::Open) == Origin::Open);
}

TEST(Origin, LiteralParamAndAggregateLabels) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ \"x\" КАК Л, &П КАК Пр, КОЛИЧЕСТВО(А.Имя) КАК К, А.Ссылка КАК С ИЗ Справочник.А КАК А");
    CHECK_EQ(r.columns.size(), static_cast<size_t>(4));
    CHECK_EQ(r.columns.at(0).origin, Origin::Client);
    CHECK_EQ(r.columns.at(1).origin, Origin::Client);     // &П is client in kPolicyAB
    CHECK_EQ(r.columns.at(2).origin, Origin::Open);       // count of protected = open number
    CHECK_EQ(r.columns.at(3).origin, Origin::Open);       // GUID ref
}

TEST(Origin, ParametersByPolicyOrigin) {
    auto token = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ &МСПТокен1 КАК Т ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(token), Origin::ProtectedDirect);
    auto missing = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ &Нет КАК Т ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(missing), Origin::Unknown);
    CHECK(HasIssue(missing, kResolveUnknownParam));
}

TEST(Origin, OtherLiteralKindsAndTypeFunctions) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ 1 КАК Ч, ИСТИНА КАК Б, NULL КАК Н, НЕОПРЕДЕЛЕНО КАК Н2, ЗНАЧЕНИЕ(Справочник.А.Пустая) КАК З, "
        "ТИПЗНАЧЕНИЯ(А.Ссылка) КАК Т, ТИП(Справочник.А) КАК Т2 ИЗ Справочник.А КАК А");
    CHECK_EQ(r.columns.size(), static_cast<size_t>(7));
    for (size_t i = 0; i < 4; ++i) CHECK_EQ(r.columns.at(i).origin, Origin::Client);
    for (size_t i = 4; i < 7; ++i) CHECK_EQ(r.columns.at(i).origin, Origin::Open);
}

TEST(Origin, SumAndMinMaxAreDerivedFromProtectedInput) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ СУММА(А.Код) КАК С, МАКСИМУМ(А.Имя) КАК М, МИНИМУМ(Б.Сумма) КАК М2, СУММА(Б.Сумма) КАК С2, "
        "КОЛИЧЕСТВО(*) КАК К, КОЛИЧЕСТВО(РАЗЛИЧНЫЕ А.Имя) КАК К2 ИЗ Справочник.А КАК А, Справочник.Б КАК Б");
    CHECK_EQ(r.columns.size(), static_cast<size_t>(6));
    CHECK_EQ(r.columns.at(0).origin, Origin::ProtectedDerived);
    CHECK_EQ(r.columns.at(1).origin, Origin::ProtectedDerived);
    CHECK_EQ(r.columns.at(2).origin, Origin::Open);
    CHECK_EQ(r.columns.at(3).origin, Origin::Open);
    CHECK_EQ(r.columns.at(4).origin, Origin::Open);
    CHECK_EQ(r.columns.at(5).origin, Origin::Open);
}

TEST(Origin, FunctionsCombineOperandsAndUnknownFunctionsFailClosed) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ПОДСТРОКА(А.Имя, 1, 2) КАК П, ЕСТЬNULL(Б.Сумма, 0) КАК Е, ГОД(&П) КАК Г, "
        "ВЫРАЗИТЬ(А.Имя КАК СТРОКА(10)) КАК Вр, -Б.Сумма КАК Н, А.Имя + \"x\" КАК Ф, СтранныйВызов(Б.Сумма) КАК Х "
        "ИЗ Справочник.А КАК А, Справочник.Б КАК Б");
    CHECK_EQ(r.columns.size(), static_cast<size_t>(7));
    CHECK_EQ(r.columns.at(0).origin, Origin::Mixed);       // protected + literal operands
    CHECK_EQ(r.columns.at(1).origin, Origin::Client);      // open + literal
    CHECK_EQ(r.columns.at(2).origin, Origin::Client);
    CHECK_EQ(r.columns.at(3).origin, Origin::ProtectedDerived);
    CHECK_EQ(r.columns.at(4).origin, Origin::Open);
    CHECK_EQ(r.columns.at(5).origin, Origin::Mixed);
    CHECK_EQ(r.columns.at(6).origin, Origin::Unknown);     // function outside the allowlist
}

TEST(Origin, PredicatesDeriveFromTheirOperands) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ А.Имя = \"x\" КАК Р, А.Имя В (\"a\", \"b\") КАК В1, А.Имя ПОДОБНО \"a%\" КАК П, "
        "А.Код МЕЖДУ 1 И 2 КАК М, А.Имя ЕСТЬ NULL КАК Н, Б.Сумма > 1 КАК С "
        "ИЗ Справочник.А КАК А, Справочник.Б КАК Б");
    CHECK_EQ(r.columns.size(), static_cast<size_t>(6));
    for (size_t i = 0; i < 4; ++i) CHECK_EQ(r.columns.at(i).origin, Origin::Mixed);
    CHECK_EQ(r.columns.at(4).origin, Origin::ProtectedDerived);
    CHECK_EQ(r.columns.at(5).origin, Origin::Client);
}

TEST(Origin, InSubqueryJoinsSubqueryColumns) {
    auto r = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Сумма В (ВЫБРАТЬ А.Имя ИЗ Справочник.А КАК А) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(r), Origin::Mixed);
    auto open = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Сумма В (ВЫБРАТЬ Б2.Сумма ИЗ Справочник.Б КАК Б2) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(open), Origin::Open);
    auto wild = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ Б.Сумма В (ВЫБРАТЬ * ИЗ Справочник.Б КАК Б2) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(wild), Origin::Unknown);
}

TEST(Origin, CaseCombinesBranchesAndConditions) {
    // implicit flow: constant branches, but the condition reads a protected value
    auto flow = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ВЫБОР КОГДА А.Имя = \"x\" ТОГДА 1 ИНАЧЕ 0 КОНЕЦ КАК Х ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(flow), Origin::Mixed);
    auto simple = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ВЫБОР А.Имя КОГДА \"x\" ТОГДА 1 ИНАЧЕ 0 КОНЕЦ КАК Х ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(simple), Origin::Mixed);
    auto branch = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ВЫБОР КОГДА Б.Сумма > 1 ТОГДА А.Имя ИНАЧЕ А.Имя КОНЕЦ КАК Х ИЗ Справочник.А КАК А, Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(branch), Origin::Mixed);   // client-visible condition joined with a protected branch
    auto only = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ВЫБОР КОГДА А.Имя ЕСТЬ NULL ТОГДА А.Код ИНАЧЕ А.Имя КОНЕЦ КАК Х ИЗ Справочник.А КАК А");
    CHECK_EQ(FirstOrigin(only), Origin::ProtectedDerived);
    auto plain = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ВЫБОР КОГДА Б.Сумма > 1 ТОГДА 1 ИНАЧЕ 0 КОНЕЦ КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(plain), Origin::Client);
    auto unknown = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ВЫБОР КОГДА Б.Нет > 1 ТОГДА 1 КОНЕЦ КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(unknown), Origin::Unknown);
}

TEST(Origin, ReferencePresentationBelongsToTheMainSpace) {
    auto fn = AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ПРЕДСТАВЛЕНИЕ(Б.СсылкаНаА) КАК П, ПРЕДСТАВЛЕНИЕССЫЛКИ(Б.СсылкаНаА) КАК П2 ИЗ Справочник.Б КАК Б");
    CHECK_EQ(fn.columns.at(0).origin, Origin::ProtectedDirect);
    CHECK_EQ(fn.columns.at(1).origin, Origin::ProtectedDirect);
    // presentation of an open table
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Вид":{"class":"open","refs":["Справочник.О"]}}},
        "Справочник.О":{"presentation":"open","fields":{"Код":{"class":"open"}}}}})");
    CHECK(p.ok);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ ПРЕДСТАВЛЕНИЕ(Д.Вид) КАК П ИЗ Документ.Д КАК Д")),
             Origin::Open);
    // a protected scalar operand: a plain function over protected data
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ПРЕДСТАВЛЕНИЕ(А.Имя) КАК П ИЗ Справочник.А КАК А")),
             Origin::ProtectedDerived);
    // an operand whose type cannot be proven (a parameter may hold any reference): fail closed
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ПРЕДСТАВЛЕНИЕ(&П) КАК П ИЗ Справочник.А КАК А")),
             Origin::Unknown);
    // a target that the policy does not list
    auto q = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Вид":{"class":"open","refs":["Справочник.Нет"]}}}}})");
    CHECK(q.ok);
    auto miss = AnalyzeForTest(q.policy, "ВЫБРАТЬ ПРЕДСТАВЛЕНИЕ(Д.Вид) КАК П ИЗ Документ.Д КАК Д");
    CHECK_EQ(FirstOrigin(miss), Origin::Unknown);
    CHECK(miss.missing_tables.count("Справочник.Нет") == 1);
}

TEST(Origin, CallClassification) {
    CHECK(ClassifyCall("КОЛИЧЕСТВО") == CallClass::Count);
    CHECK(ClassifyCall("count") == CallClass::Count);
    CHECK(ClassifyCall("СУММА") == CallClass::Sum);
    CHECK(ClassifyCall("МАКСИМУМ") == CallClass::MinMax);
    CHECK(ClassifyCall("ПРЕДСТАВЛЕНИЕ") == CallClass::Presentation);
    CHECK(ClassifyCall("ТИПЗНАЧЕНИЯ") == CallClass::TypeOf);
    CHECK(ClassifyCall("ПОДСТРОКА") == CallClass::Plain);
    CHECK(ClassifyCall("Подстрока") == CallClass::Plain);
    CHECK(ClassifyCall("СтранныйВызов") == CallClass::Unrecognized);
}

TEST(Origin, CastOfReferenceToNonReferenceTypeFailsClosed) {
    auto str = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ВЫРАЗИТЬ(Б.СсылкаНаА КАК СТРОКА(50)) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(str), Origin::Unknown);
    auto param = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ВЫРАЗИТЬ(&П КАК СТРОКА(50)) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(param), Origin::Unknown);
    auto to_ref = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ВЫРАЗИТЬ(Б.СсылкаНаА КАК Справочник.А) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(to_ref), Origin::Open);
    auto scalar = AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ВЫРАЗИТЬ(Б.Сумма КАК ЧИСЛО(15, 2)) КАК Х ИЗ Справочник.Б КАК Б");
    CHECK_EQ(FirstOrigin(scalar), Origin::Open);
}

TEST(Origin, TypeOfDependsOnOperandOrigin) {
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ТИПЗНАЧЕНИЯ(А.Имя) КАК Х ИЗ Справочник.А КАК А")),
             Origin::ProtectedDerived);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB, "ВЫБРАТЬ ТИПЗНАЧЕНИЯ(Б.Сумма) КАК Х ИЗ Справочник.Б КАК Б")),
             Origin::Open);
}

TEST(Origin, PeriodArgumentIsAConstant) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Документ.Д":{"fields":{"Дата":{"class":"open"}}}}})");
    CHECK(p.ok);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ НАЧАЛОПЕРИОДА(Д.Дата, ДЕНЬ) КАК Х ИЗ Документ.Д КАК Д")),
             Origin::Open);
    CHECK_EQ(FirstOrigin(AnalyzeForTest(p.policy, "ВЫБРАТЬ РАЗНОСТЬДАТ(Д.Дата, Д.Дата, МЕСЯЦ) КАК Х ИЗ Документ.Д КАК Д")),
             Origin::Open);
    // any other identifier there is a field lookup
    auto r = AnalyzeForTest(p.policy, "ВЫБРАТЬ НАЧАЛОПЕРИОДА(Д.Дата, Нечто) КАК Х ИЗ Документ.Д КАК Д");
    CHECK_EQ(FirstOrigin(r), Origin::Unknown);
    CHECK(!r.resolution_issues.empty());
}

TEST(Origin, PresentationOverNonFieldOperandFailsClosed) {
    CHECK_EQ(FirstOrigin(AnalyzeForTest(kPolicyAB,
        "ВЫБРАТЬ ПРЕДСТАВЛЕНИЕ(ЕСТЬNULL(Б.СсылкаНаА, НЕОПРЕДЕЛЕНО)) КАК Х ИЗ Справочник.Б КАК Б")), Origin::Unknown);
}
