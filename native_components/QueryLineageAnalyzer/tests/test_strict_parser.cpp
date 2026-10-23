#include "test_framework.h"
#include "strict/strict_parser.h"
#include "strict/ast_dump.h"

#include <string>

using namespace lineage::strict;

namespace {

std::string ExprDump(const std::string& text) {
    auto r = ParseExpressionForTest(text);
    return r.ok ? DumpExpr(*r.expr) : "ERR:" + r.error.code;
}

std::string Code(const std::string& text) {
    auto r = ParseExpressionForTest(text);
    return r.ok ? "OK" : r.error.code;
}

ExprP Make(Expr::K kind) {
    auto e = std::make_shared<Expr>();
    e->kind = kind;
    return e;
}

}  // namespace

TEST(StrictParser, PrecedenceOrAndNotComparison) {
    CHECK_EQ(ExprDump("А = 1 ИЛИ НЕ Б > 2 И Г"),
             std::string("(ИЛИ (= (f А) 1) (И (НЕ (> (f Б) 2)) (f Г)))"));
}
TEST(StrictParser, BareВIsTheInKeywordNotAField) {
    // The plan text used "В" as a field name; it is the В (IN) keyword and must never parse as a field.
    CHECK(Code("А И В") != "OK");
}
TEST(StrictParser, ArithmeticPrecedence) {
    CHECK_EQ(ExprDump("1 + 2 * -Х"), std::string("(+ 1 (* 2 (- (f Х))))"));
    CHECK_EQ(ExprDump("А - -Б"), std::string("(- (f А) (- (f Б)))"));
    CHECK_EQ(ExprDump("(1 + 2) * 3"), std::string("(* (+ 1 2) 3)"));
    CHECK_EQ(ExprDump("1 - 2 - 3"), std::string("(- (- 1 2) 3)"));
}
TEST(StrictParser, Predicates) {
    CHECK_EQ(ExprDump("Х ПОДОБНО \"а%\" СПЕЦСИМВОЛ \"~\""), std::string("(like (f Х) \"а%\" \"~\")"));
    CHECK_EQ(ExprDump("Х НЕ МЕЖДУ 1 И 2"), std::string("(!between (f Х) 1 2)"));
    CHECK_EQ(ExprDump("Х ЕСТЬ НЕ NULL"), std::string("(!isnull (f Х))"));
    CHECK_EQ(ExprDump("Х ЕСТЬ NULL"), std::string("(isnull (f Х))"));
    CHECK_EQ(ExprDump("Х В (1, 2)"), std::string("(in (f Х) 1 2)"));
    CHECK_EQ(ExprDump("Х НЕ В (&П)"), std::string("(!in (f Х) (param &П))"));
    CHECK_EQ(ExprDump("Х ССЫЛКА Справочник.Контрагенты"), std::string("(refs (f Х) Справочник.Контрагенты)"));
    CHECK_EQ(ExprDump("Х НЕ ПОДОБНО \"а\""), std::string("(!like (f Х) \"а\")"));
}
TEST(StrictParser, BetweenBoundsAreAdditiveAndConsumeOneAnd) {
    CHECK_EQ(ExprDump("Х МЕЖДУ 1 + 1 И 3 И Y"), std::string("(И (between (f Х) (+ 1 1) 3) (f Y))"));
}
TEST(StrictParser, InHierarchy) {
    CHECK_EQ(ExprDump("Х В ИЕРАРХИИ (&Р)"), std::string("(in-h (f Х) (param &Р))"));
    CHECK_EQ(ExprDump("Х НЕ в иерархии (&Р, &Q)"), std::string("(!in-h (f Х) (param &Р) (param &Q))"));
    CHECK_EQ(ExprDump("Х IN HIERARCHY (1)"), std::string("(in-h (f Х) 1)"));
    CHECK(Code("Х В ИЕРАРХИЯ (1)") != "OK");     // wrong word
    CHECK(Code("Х В ИЕРАРXИИ (1)") != "OK");     // Latin X inside: not the word
}
TEST(StrictParser, FunctionsCaseCast) {
    CHECK_EQ(ExprDump("ПОДСТРОКА(Т.Имя, 1, 3)"), std::string("(call ПОДСТРОКА (f Т Имя) 1 3)"));
    CHECK_EQ(ExprDump("КОЛИЧЕСТВО(РАЗЛИЧНЫЕ Т.Х)"), std::string("(call! КОЛИЧЕСТВО (f Т Х))"));
    CHECK_EQ(ExprDump("КОЛИЧЕСТВО(*)"), std::string("(call КОЛИЧЕСТВО *)"));
    CHECK_EQ(ExprDump("ВЫБОР КОГДА А ТОГДА 1 ИНАЧЕ 2 КОНЕЦ"), std::string("(case (f А) 1 2)"));
    CHECK_EQ(ExprDump("ВЫБОР Х КОГДА 1 ТОГДА 2 КОГДА 3 ТОГДА 4 КОНЕЦ"), std::string("(case-op (f Х) 1 2 3 4)"));
    CHECK_EQ(ExprDump("ВЫРАЗИТЬ(Х КАК Строка(10))"), std::string("(cast (f Х) Строка 10)"));
    CHECK_EQ(ExprDump("ВЫРАЗИТЬ(Х КАК Число(15, 2))"), std::string("(cast (f Х) Число 15 2)"));
    CHECK_EQ(ExprDump("ЗНАЧЕНИЕ(Перечисление.Виды.Основной)"), std::string("(value Перечисление.Виды.Основной)"));
    CHECK_EQ(ExprDump("ТИП(Число)"), std::string("(type Число)"));
    CHECK_EQ(ExprDump("ЕСТЬNULL(А, 0)"), std::string("(call ЕСТЬNULL (f А) 0)"));
    CHECK_EQ(ExprDump("isnull(А, 0)"), std::string("(call ЕСТЬNULL (f А) 0)"));
    CHECK_EQ(ExprDump("ТИПЗНАЧЕНИЯ(А)"), std::string("(call ТИПЗНАЧЕНИЯ (f А))"));
    CHECK_EQ(ExprDump("ПРЕДСТАВЛЕНИЕ(А)"), std::string("(call ПРЕДСТАВЛЕНИЕ (f А))"));
    CHECK_EQ(ExprDump("ДАТАВРЕМЯ(2020, 1, 31)"), std::string("(call ДАТАВРЕМЯ 2020 1 31)"));
}
TEST(StrictParser, LiteralsParametersAndPaths) {
    CHECK_EQ(ExprDump("\"a\" + \"b\""), std::string("(+ \"a\" \"b\")"));
    CHECK_EQ(ExprDump("\"a\"\"b\""), std::string("\"a\\\"b\""));
    CHECK_EQ(ExprDump("ИСТИНА И ЛОЖЬ"), std::string("(И ИСТИНА ЛОЖЬ)"));
    CHECK_EQ(ExprDump("НЕОПРЕДЕЛЕНО = NULL"), std::string("(= НЕОПРЕДЕЛЕНО NULL)"));
    CHECK_EQ(ExprDump("1.5"), std::string("1.5"));
    CHECK_EQ(ExprDump("&Имя"), std::string("(param &Имя)"));
    CHECK_EQ(ExprDump("Т.Ссылка = Т.Представление"), std::string("(= (f Т Ссылка) (f Т Представление))"));
    CHECK_EQ(ExprDump("X and not Y or Z"), std::string("(ИЛИ (И (f X) (НЕ (f Y))) (f Z))"));
    CHECK_EQ(ExprDump("Расчёты.Ёмкость"), std::string("(f Расчёты Ёмкость)"));
}
TEST(StrictParser, RowOnlyBeforeSubqueryIn) {
    CHECK_EQ(Code("(1, 2) В (1, 2)"), std::string("Q_PARSE_ROW_POSITION"));
    CHECK_EQ(Code("(1, 2) = 3"), std::string("Q_PARSE_INVALID_NODE"));
    CHECK_EQ(Code("Х = (1, 2)"), std::string("Q_PARSE_INVALID_NODE"));
    CHECK_EQ(Code("(ВЫБРАТЬ 1)"), std::string("Q_PARSE_SUBQUERY_POSITION"));
    CHECK_EQ(Code("Х = (ВЫБРАТЬ 1)"), std::string("Q_PARSE_SUBQUERY_POSITION"));
}
TEST(StrictParser, FailClosed) {
    for (const char* bad : {"Х +", "(Х", "Х КАК", "ПОДСТРОКА(Х,", "ВЫБОР КОГДА А ТОГДА 1", "'x'", "{Х}", "Х ПОДОБНО"})
        CHECK(ExprDump(bad).rfind("ERR:", 0) == 0);
}
TEST(StrictParser, FailClosedBattery) {
    for (const char* bad : {
             "", "1 2", "1 )", "Х;", "+Х", "Х = ", "НЕ", "Х НЕ = 1", "Х НЕ ЕСТЬ NULL", "Х ЕСТЬ", "Х ЕСТЬ НЕ",
             "Х В", "Х В ()", "Х В (1,", "Х В (1 2)", "Х МЕЖДУ 1", "Х МЕЖДУ 1 И", "Х ССЫЛКА", "Х ССЫЛКА Справочник",
             "ЗНАЧЕНИЕ(Х)", "ЗНАЧЕНИЕ()", "ТИП()", "ВЫРАЗИТЬ(Х КАК)", "ВЫРАЗИТЬ(Х КАК Строка(1.5))",
             "ВЫРАЗИТЬ(Х КАК Строка(1,2,3))", "ВЫРАЗИТЬ(Х Строка)", "ВЫБОР КОНЕЦ", "ВЫБОР Х КОНЕЦ",
             "ВЫБОР КОГДА А ТОГДА 1 ИНАЧЕ КОНЕЦ", "ВЫБРАТЬ", "Значение", "ССЫЛКА.Х", "Т.", "Т..Х", "Т.1", "Т.Х(1)",
             "КОЛИЧЕСТВО()", "КОЛИЧЕСТВО(РАЗЛИЧНЫЕ *)", "СУММА(*)", "СУММА(РАЗЛИЧНЫЕ Х)",
             "КОЛИЧЕСТВО(РАЗЛИЧНЫЕ А, Б)", "ЕСТЬNULL(А)", "ЕСТЬNULL(А, Б, В)", "ТИПЗНАЧЕНИЯ(А, Б)", "ПРЕДСТАВЛЕНИЕ",
             "&", "& Х", "&Х.Y", "1abc", "1..2", "Х <> = 1", "Х ! 1", "Х == 1", "Х /* c */", "Х -- ", "$Х",
             "ПЁРВЫЕ", "(,)", "(1,)", "ИЛИ Х", "Х И", "Х ТОГДА"})
        CHECK(Code(bad) != "OK");
}
TEST(StrictParser, ChainedPredicatesAreErrors) {
    CHECK_EQ(Code("А = Б = В"), std::string("Q_PARSE_CHAIN"));
    CHECK_EQ(Code("А < Б > В"), std::string("Q_PARSE_CHAIN"));
    CHECK_EQ(Code("А = Б В (1)"), std::string("Q_PARSE_CHAIN"));
    CHECK_EQ(Code("А В (1) = 2"), std::string("Q_PARSE_CHAIN"));
    CHECK_EQ(Code("А В (1) В (2)"), std::string("Q_PARSE_CHAIN"));
    CHECK_EQ(Code("А ЕСТЬ NULL ЕСТЬ NULL"), std::string("Q_PARSE_CHAIN"));
    CHECK_EQ(Code("А МЕЖДУ 1 И 2 НЕ ПОДОБНО \"x\""), std::string("Q_PARSE_CHAIN"));
}
TEST(StrictParser, MixedScriptIdentifiersRejected) {
    CHECK_EQ(Code("Aб"), std::string("Q_PARSE_MIXED_SCRIPT"));      // Latin A + Cyrillic б
    CHECK_EQ(Code("Т.Aб"), std::string("Q_PARSE_MIXED_SCRIPT"));
    CHECK_EQ(Code("&Aб"), std::string("Q_PARSE_MIXED_SCRIPT"));
    CHECK_EQ(Code("Aб(1)"), std::string("Q_PARSE_MIXED_SCRIPT"));
    CHECK_EQ(Code("ВЫРАЗИТЬ(Х КАК Aб.Ц)"), std::string("Q_PARSE_MIXED_SCRIPT"));
    CHECK_EQ(Code("ЗНАЧЕНИЕ(Перечисление.Bид.Основной)"), std::string("Q_PARSE_MIXED_SCRIPT"));
    CHECK_EQ(Code("Х ССЫЛКА Справочник.Aб"), std::string("Q_PARSE_MIXED_SCRIPT"));
    CHECK_EQ(Code("Abc_1"), std::string("OK"));
    CHECK_EQ(Code("Абв_1"), std::string("OK"));
}
TEST(StrictParser, ErrorsCarryPosition) {
    auto r = ParseExpressionForTest("Х +");
    CHECK(!r.ok);
    CHECK_EQ(r.error.pos.line, 1u);
    CHECK_EQ(r.error.pos.col, 4u);
    r = ParseExpressionForTest("А =\n  'x'");
    CHECK_EQ(r.error.code, std::string("Q_PARSE_TOKEN"));
    CHECK_EQ(r.error.pos.line, 2u);
    CHECK_EQ(r.error.pos.col, 3u);
}
TEST(StrictParser, DepthLimitIsError) {
    std::string deep(200, '(');
    deep += "1" + std::string(200, ')');
    CHECK_EQ(ExprDump(deep), std::string("ERR:Q_PARSE_LIMIT"));
    std::string nots;
    for (int i = 0; i < 100; ++i) nots += "НЕ ";
    CHECK_EQ(ExprDump(nots + "Х"), std::string("ERR:Q_PARSE_LIMIT"));
    std::string minus(100, '-');
    CHECK_EQ(ExprDump(minus + "1"), std::string("ERR:Q_PARSE_LIMIT"));
    std::string ok(30, '(');
    ok += "1" + std::string(30, ')');
    CHECK_EQ(ExprDump(ok), std::string("1"));
}
TEST(StrictParser, LeftDeepChainsAreBoundedByTreeDepth) {
    auto chain = [](int terms, const char* op) {
        std::string s = "1";
        for (int i = 1; i < terms; ++i) s += std::string(" ") + op + " 1";
        return s;
    };
    CHECK_EQ(Code(chain(100, "+")), std::string("OK"));
    CHECK_EQ(Code(chain(100, "ИЛИ")), std::string("OK"));
    CHECK_EQ(Code(chain(300, "+")), std::string("Q_PARSE_LIMIT"));
    CHECK_EQ(Code(chain(150000, "+")), std::string("Q_PARSE_LIMIT"));
}
TEST(StrictParser, UnsetNodeIsRejectedByValidator) {
    CHECK(Expr().kind == Expr::K::Unset);
    ParseError err;
    CHECK(!ValidateExpr(std::make_shared<Expr>(), err));
    CHECK_EQ(err.code, std::string("Q_PARSE_INVALID_NODE"));
    CHECK(!ValidateExpr(nullptr, err));

    // An Unset node buried in an otherwise valid tree.
    auto bin = Make(Expr::K::Binary);
    bin->text = "+";
    auto one = Make(Expr::K::NumberLit);
    one->text = "1";
    bin->args = {one, std::make_shared<Expr>()};
    CHECK(!ValidateExpr(bin, err));
    bin->args[1] = one;
    CHECK(ValidateExpr(bin, err));

    // Null child, wrong arity, Row misuse, bad payload.
    bin->args[1] = nullptr;
    CHECK(!ValidateExpr(bin, err));
    auto un = Make(Expr::K::Unary);
    un->text = "-";
    CHECK(!ValidateExpr(un, err));   // no operand
    auto row = Make(Expr::K::Row);
    row->args = {one, one};
    CHECK(!ValidateExpr(row, err));  // Row outside subquery В
    auto lit = Make(Expr::K::BoolLit);
    lit->text = "MAYBE";
    CHECK(!ValidateExpr(lit, err));
}
TEST(StrictParser, KeywordPathSegmentsRejected) {
    CHECK_EQ(ExprDump("Т.Ссылка.Наименование"), std::string("(f Т Ссылка Наименование)"));
    CHECK_EQ(ExprDump("Т.ПредставлениеСсылки"), std::string("(f Т ПредставлениеСсылки)"));
    CHECK_EQ(ExprDump("Х.Значение"), std::string("(f Х Значение)"));
    CHECK(Code("Ссылка.Х") != "OK");   // allowlisted words are never the first segment
    for (const char* bad : {"Т.И", "Т.НЕ", "Т.ВЫБРАТЬ", "Т.ТИП", "ТИП(Х.И)", "Т.А.В", "ВЫРАЗИТЬ(Х КАК Т.Тип)", "Х ССЫЛКА Справочник.Все",
                            "ЗНАЧЕНИЕ(Перечисление.Виды.Для)"})
        CHECK_EQ(Code(bad), std::string("Q_PARSE_KEYWORD_SEGMENT"));
}
TEST(StrictParser, NotLikeWithEscape) {
    CHECK_EQ(ExprDump("Х НЕ ПОДОБНО \"а\" СПЕЦСИМВОЛ \"~\""), std::string("(!like (f Х) \"а\" \"~\")"));
}
TEST(StrictParser, LimitThroughCaseAndCallNesting) {
    std::string cs, ce, call, callend;
    for (int i = 0; i < 100; ++i) {
        cs += "ВЫБОР КОГДА ";
        ce += " ТОГДА 1 КОНЕЦ";
        call += "Ф(";
        callend += ")";
    }
    CHECK_EQ(Code(cs + "1" + ce), std::string("Q_PARSE_LIMIT"));
    CHECK_EQ(Code(call + "1" + callend), std::string("Q_PARSE_LIMIT"));
}
TEST(StrictParser, ValidatorRejectsMalformedHandBuiltNodes) {
    ParseError err;
    auto num = [] {
        auto e = Make(Expr::K::NumberLit);
        e->text = "1";
        return e;
    };
    auto with = [&](Expr::K k, std::vector<ExprP> args) {
        auto e = Make(k);
        e->args = std::move(args);
        return e;
    };
    // Control: a well-formed case passes.
    auto good = with(Expr::K::Case, {num(), num()});
    CHECK(ValidateExpr(good, err));
    // Case shape.
    CHECK(!ValidateExpr(with(Expr::K::Case, {num()}), err));
    CHECK(!ValidateExpr(with(Expr::K::Case, {num(), num(), num()}), err));
    auto op = with(Expr::K::Case, {num(), num()});
    op->has_operand = true;
    CHECK(!ValidateExpr(op, err));
    // Cast.
    auto cast = with(Expr::K::Cast, {num()});
    CHECK(!ValidateExpr(cast, err));                 // no type
    cast->type_name = "Строка";
    cast->type_args = {"10"};
    CHECK(ValidateExpr(cast, err));
    cast->type_args = {"1", "2", "3"};
    CHECK(!ValidateExpr(cast, err));
    cast->type_args = {"1 OR 1"};
    CHECK(!ValidateExpr(cast, err));
    cast->type_args.clear();
    cast->type_name = "Строка\") ; DROP";
    CHECK(!ValidateExpr(cast, err));
    // InList / Between / Like arity.
    CHECK(!ValidateExpr(with(Expr::K::InList, {num()}), err));
    CHECK(!ValidateExpr(with(Expr::K::Between, {num(), num()}), err));
    CHECK(!ValidateExpr(with(Expr::K::Like, {num()}), err));
    CHECK(ValidateExpr(with(Expr::K::Like, {num(), num()}), err));
    // Call + distinct.
    auto call = with(Expr::K::Call, {num()});
    call->text = "СУММА";
    CHECK(ValidateExpr(call, err));
    call->distinct = true;
    CHECK(!ValidateExpr(call, err));
    call->text = "КОЛИЧЕСТВО";
    CHECK(ValidateExpr(call, err));
    call->text = "Ф(); --";
    call->distinct = false;
    CHECK(!ValidateExpr(call, err));
    // Subquery misuse.
    auto sub = with(Expr::K::InList, {num(), num()});
    sub->subquery = std::make_shared<Select>();
    CHECK(!ValidateExpr(sub, err));
    CHECK(!ValidateExpr(with(Expr::K::InSubquery, {num()}), err));   // no subquery
    // Flags on the wrong kind.
    auto n1 = num();
    n1->negated = true;
    CHECK(!ValidateExpr(n1, err));
    n1 = num();
    n1->has_else = true;
    CHECK(!ValidateExpr(n1, err));
    n1 = num();
    n1->distinct = true;
    CHECK(!ValidateExpr(n1, err));
    n1 = num();
    n1->type_name = "X";
    CHECK(!ValidateExpr(n1, err));
    n1 = num();
    n1->parts = {"X"};
    CHECK(!ValidateExpr(n1, err));
    // Injected payload text.
    for (const char* t : {"1e5", "-1", "1.", ".5", "1.2.3", "1 2", "", "0x10"}) {
        n1 = num();
        n1->text = t;
        CHECK(!ValidateExpr(n1, err));
    }
    auto fld = Make(Expr::K::Field);
    fld->parts = {"Т", "Х; DROP"};
    CHECK(!ValidateExpr(fld, err));
    fld->parts = {"Т", "Aб"};   // mixed script
    CHECK(!ValidateExpr(fld, err));
    fld->parts = {"Т", "1X"};
    CHECK(!ValidateExpr(fld, err));
    fld->parts = {"Т", "Имя_1"};
    CHECK(ValidateExpr(fld, err));
    auto prm = Make(Expr::K::Param);
    prm->text = "Х) OR (1=1";
    CHECK(!ValidateExpr(prm, err));
    auto txt = num();
    txt = Make(Expr::K::IsNullTest);
    txt->args = {num()};
    txt->text = "junk";
    CHECK(!ValidateExpr(txt, err));
}
TEST(StrictParser, ValidatorNodeBudgetStopsSharedChildDag) {
    auto cur = Make(Expr::K::NumberLit);
    cur->text = "1";
    for (int i = 0; i < 60; ++i) {
        auto b = Make(Expr::K::Binary);
        b->text = "+";
        b->args = {cur, cur};   // 2^60 paths, depth 61
        cur = b;
    }
    ParseError err;
    CHECK(!ValidateExpr(cur, err));
    CHECK_EQ(err.code, std::string("Q_PARSE_LIMIT"));
}
TEST(StrictParser, ValidatorBoundsDepth) {
    auto cur = Make(Expr::K::NumberLit);
    cur->text = "1";
    for (int i = 0; i < kMaxExprDepth + 10; ++i) {
        auto u = Make(Expr::K::Unary);
        u->text = "-";
        u->args = {cur};
        cur = u;
    }
    ParseError err;
    CHECK(!ValidateExpr(cur, err));
    CHECK_EQ(err.code, std::string("Q_PARSE_LIMIT"));
    // Unwind iteratively so the test itself does not rely on recursive destruction depth.
    while (cur && !cur->args.empty()) {
        ExprP next = cur->args[0];
        cur->args.clear();
        cur = next;
    }
}
TEST(StrictParser, BatchGrammarNotYetAvailableFailsClosed) {
    CHECK(!ParseBatchStrict("ВЫБРАТЬ 1").ok);
    CHECK(!ParseBatchStrict("").ok);
}
