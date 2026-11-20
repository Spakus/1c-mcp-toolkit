#include <nlohmann/json.hpp>

#include <cstdlib>
#include <set>
#include <iostream>
#include <string>
#include <utility>

#include "bsl/bsl_types.h"
#include "bsl/check_code.h"
#include "policy_fixture.h"
#include "test_framework.h"

using lineage::bsl::CheckCodeImpl;
using lineage::strict::kPolicyABJson;

namespace {

using Json = nlohmann::json;

Json Check(const std::string& code, const std::string& policy = kPolicyABJson) {
    Json j = Json::parse(CheckCodeImpl(code, policy));
    if (std::getenv("QLA_DEBUG")) std::cout << j.dump() << std::endl;
    return j;
}

std::string Verdict(const Json& j) { return j["verdict"].get<std::string>(); }

bool HasReason(const Json& j, const char* code) {
    for (const Json& r : j["reasons"]) {
        if (r["code"].get<std::string>() == code) return true;
    }
    return false;
}

bool HasRisk(const Json& j, const char* code) {
    for (const Json& r : j["risks"]) {
        if (r["code"].get<std::string>() == code) return true;
    }
    return false;
}

std::string Label(const Json& j, const char* path) {
    const auto it = j["result_labels"].find(path);
    return it == j["result_labels"].end() ? std::string("<none>") : it->get<std::string>();
}

// The policy of kPolicyABJson with two issued tokens.
std::string PolicyWithTokens() {
    Json p = Json::parse(kPolicyABJson);
    p["tokens"] = Json::parse(R"({"[str-00001]": {"index": 0, "origin": "protected"}})");
    return p.dump();
}

const char* kQuery =
    "З = Новый Запрос(\"ВЫБРАТЬ А.Ссылка КАК С, А.Имя КАК Имя ИЗ Справочник.А КАК А\");\n";

}  // namespace

TEST(CheckCode, ResultLabels) {
    // The plan expects "open" for the reference column; the checker writes "ref" so that the masker applies the
    // reference rule to the object description of the reference (see check_code.h). The column is called Имя here:
    // "И" is the AND keyword of the query language, so the plan's alias does not parse.
    const Json j = Check(std::string(kQuery) + "Результат = З.Выполнить().Выгрузить();");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("container"));
    CHECK_EQ(Label(j, "$[*]"), std::string("container"));
    CHECK_EQ(Label(j, "$[*].Имя"), std::string("protected"));
    CHECK_EQ(Label(j, "$[*].С"), std::string("ref"));
    CHECK(!j["canonical"].get<std::string>().empty());
}

TEST(CheckCode, ClientLiteralInResultIsClient) {
    const Json j = Check("Результат = Новый Структура(\"К\", \"x\");");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("container"));
    CHECK_EQ(Label(j, "$.К"), std::string("client"));
}

TEST(CheckCode, MixedContainerNeedsConfirmation) {
    const Json j = Check(
        "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя ИЗ Справочник.А КАК А\"); Т = З.Выполнить().Выгрузить();\n"
        "М = Новый Массив; М.Добавить(Т[0].Имя); М.Добавить(\"догадка\"); Результат = М;");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK_EQ(Label(j, "$[*]"), std::string("mixed"));
    CHECK(HasReason(j, "C_MIXED_RESULT"));
}

TEST(CheckCode, NotLoadedPolicyFailsClosed) {
    const Json j = Check("Результат = 1;", "{");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_POLICY_INVALID"));
    CHECK(j["canonical"].get<std::string>().empty());
    CHECK(HasRisk(j, "R_UNKNOWN_EFFECT"));
}

// The code checker reads the same policy: "params" spellings colliding up to case with different origins make it
// malformed there too, though the code sets its own parameters.
TEST(CheckCode, CollidingParamOriginsArePolicyInvalid) {
    Json policy = Json::parse(kPolicyABJson);
    policy["params"] = Json::parse(R"({"пар": "client", "Пар": "token_protected"})");
    const Json j = Check("Результат = 1;", policy.dump());
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_POLICY_INVALID"));
    CHECK(HasRisk(j, "R_UNKNOWN_EFFECT"));
}

TEST(CheckCode, EnvelopeShape) {
    const Json j = Check("Результат = 1;");
    CHECK_EQ(j["api"].get<int>(), 2);
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK(j["reasons"].is_array() && j["reasons"].empty());
    CHECK(j["risks"].is_array() && j["risks"].empty());
    CHECK(j["missing_tables"].is_array());
    CHECK(j["result_labels"].is_object());
    CHECK_EQ(Label(j, "$"), std::string("client"));
    CHECK(j["canonical"].get<std::string>().find("Результат") != std::string::npos);
}

TEST(CheckCode, UnassignedResultIsOpen) {
    const Json j = Check("Х = 1;");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("open"));
}

TEST(CheckCode, ProtectedScalarIsLabelledProtected) {
    const Json j = Check(std::string(kQuery) + "Т = З.Выполнить().Выгрузить(); Результат = Т[0].Имя;");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("protected"));
}

TEST(CheckCode, DerivedLabelNeedsConfirmation) {
    const Json j = Check(std::string(kQuery) + "Т = З.Выполнить().Выгрузить(); Результат = НЕ Т[0].Имя;");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK_EQ(Label(j, "$"), std::string("protected_derived"));
    CHECK(HasReason(j, "C_DERIVED_RESULT"));
}

TEST(CheckCode, UnknownLabelNeedsConfirmation) {
    const Json j = Check("Результат = Новый ТаблицаЗначений;");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK_EQ(Label(j, "$"), std::string("unknown"));
    CHECK(HasReason(j, "C_UNLABELED_RESULT"));
}

TEST(CheckCode, StructureKeysKeepSeparateLabels) {
    const Json j = Check(std::string(kQuery) + "Т = З.Выполнить().Выгрузить();\n"
                         "Результат = Новый Структура(\"С, Имя\", Т[0].С, Т[0].Имя); Результат.Вставить(\"К\", 5);");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$.С"), std::string("ref"));
    CHECK_EQ(Label(j, "$.Имя"), std::string("protected"));
    CHECK_EQ(Label(j, "$.К"), std::string("client"));
}

TEST(CheckCode, ArrayOfStructuresIsLabelledPerKey) {
    const Json j = Check(std::string(kQuery) + "Т = З.Выполнить().Выгрузить(); М = Новый Массив;\n"
                         "Для Каждого Стр Из Т Цикл М.Добавить(Новый Структура(\"С, Имя\", Стр.С, Стр.Имя)); КонецЦикла;\n"
                         "Результат = М;");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("container"));
    CHECK_EQ(Label(j, "$[*]"), std::string("container"));
    CHECK_EQ(Label(j, "$[*].Имя"), std::string("protected"));
    CHECK_EQ(Label(j, "$[*].С"), std::string("ref"));
}

TEST(CheckCode, UnloadedColumnIsAnArrayOfThatColumn) {
    const Json j = Check(std::string(kQuery) + "Результат = З.Выполнить().Выгрузить().ВыгрузитьКолонку(\"Имя\");");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$[*]"), std::string("protected"));
}

// A cell of an open column without reference targets, moved as is, is "open" wherever it lands (as a table cell is):
// the masker applies its reference rule to the serialized value by shape, whatever the label.
TEST(CheckCode, OpenColumnCellWithoutTargetsIsOpen) {
    const std::string q =
        "З = Новый Запрос(\"ВЫБРАТЬ Б.Сумма КАК Сумма, Б.Ссылка КАК С ИЗ Справочник.Б КАК Б\");\n"
        "В = З.Выполнить().Выбрать(); В.Следующий(); Т = З.Выполнить().Выгрузить();\n";
    const Json s = Check(q + "Х = В.Сумма; Результат = Новый Структура(\"Сумма, С, Т\", Х, В.С, Т[0].Сумма);");
    CHECK_EQ(Verdict(s), std::string("safe"));
    CHECK_EQ(Label(s, "$.Сумма"), std::string("open"));
    CHECK_EQ(Label(s, "$.С"), std::string("ref"));
    CHECK_EQ(Label(s, "$.Т"), std::string("open"));
    const Json root = Check(q + "Результат = В.Сумма;");
    CHECK_EQ(Verdict(root), std::string("safe"));
    CHECK_EQ(Label(root, "$"), std::string("open"));
    const Json col = Check(q + "Результат = Т.ВыгрузитьКолонку(\"Сумма\");");
    CHECK_EQ(Verdict(col), std::string("safe"));
    CHECK_EQ(Label(col, "$[*]"), std::string("open"));
    const Json map = Check(q + "Результат = Новый Соответствие; Результат.Вставить(\"к\", В.Сумма);");
    CHECK_EQ(Verdict(map), std::string("safe"));
    CHECK_EQ(Label(map, "$[*].value"), std::string("open"));
    // Joined with another cell on two paths: still a cell. Joined with a computed value: not.
    const Json joined = Check(q + "Если В.Сумма = 1 Тогда Х = В.Сумма; Иначе Х = Т[0].Сумма; КонецЕсли; Результат = Х;");
    CHECK_EQ(Label(joined, "$"), std::string("open"));
    const Json mixed = Check(q + "Если В.Сумма = 1 Тогда Х = В.Сумма; Иначе Х = В; КонецЕсли; Результат = Х;");
    CHECK_EQ(Verdict(mixed), std::string("confirm"));
    // A cell that is provably not a reference is no presentation read: functions and operators over it are open.
    CHECK_EQ(Verdict(Check(q + "Результат = Строка(В.Сумма);")), std::string("safe"));
    CHECK_EQ(Verdict(Check(q + "Результат = \"x\" + В.Сумма;")), std::string("safe"));
    // What a collection holds keeps the "not a reference" of the cells stored in it.
    CHECK_EQ(Verdict(Check(q + "М = Новый Массив; М.Добавить(В.Сумма); Результат = Строка(М[0]);")), std::string("safe"));
    // An element read back by an index of a column unload is a value of unknown type.
    CHECK_EQ(Verdict(Check(q + "Результат = Новый Структура(\"К\", Т.ВыгрузитьКолонку(\"Сумма\")[0]);")),
             std::string("confirm"));
    // A protected column stays protected, a tainted holder taints the cell.
    const Json prot = Check(std::string(kQuery) + "В = З.Выполнить().Выбрать(); В.Следующий(); Результат = В.Имя;");
    CHECK_EQ(Label(prot, "$"), std::string("protected"));
}

TEST(CheckCode, MapIsAnArrayOfKeyValueEntries) {
    const Json j = Check(std::string(kQuery) + "Т = З.Выполнить().Выгрузить();\n"
                         "М = Новый Соответствие; М.Вставить(\"к\", Т[0].Имя); Результат = М;");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("container"));
    CHECK_EQ(Label(j, "$[*]"), std::string("container"));
    CHECK_EQ(Label(j, "$[*].key"), std::string("client"));
    CHECK_EQ(Label(j, "$[*].value"), std::string("protected"));
}

TEST(CheckCode, TaintedMapKeyNeedsConfirmation) {
    const Json j = Check(std::string(kQuery) + "Т = З.Выполнить().Выгрузить();\n"
                         "М = Новый Соответствие; М.Вставить(Т[0].Имя, 1); Результат = М;");
    CHECK_EQ(Verdict(j), std::string("confirm"));
}

TEST(CheckCode, DepthLimitOfTheSerializer) {
    // Six nested structures: the innermost one is at depth 5, its value at depth 6 is "<max_depth>" and is labelled unknown.
    const Json j = Check(
        "С1 = Новый Структура(\"а\", 1); С2 = Новый Структура(\"в\", С1); С3 = Новый Структура(\"в\", С2);\n"
        "С4 = Новый Структура(\"в\", С3); С5 = Новый Структура(\"в\", С4); Результат = Новый Структура(\"в\", С5);");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_UNLABELED_RESULT"));
    CHECK_EQ(Label(j, "$.в.в.в.в.в"), std::string("container"));
    CHECK_EQ(Label(j, "$.в.в.в.в.в.а"), std::string("unknown"));
}

TEST(CheckCode, StructureKeyThatIsNotAnIdentifierIsUnlabeled) {
    const Json j = Check("Результат = Новый Структура(\"А.Б\", 1);");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_UNLABELED_RESULT"));
}

TEST(CheckCode, ParseRefusalIsConfirmWithRefusedRisks) {
    const Json j = Check("Результат = Вычислить(\"1\");");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK_EQ(j["reasons"].size(), static_cast<size_t>(1));
    CHECK(!HasReason(j, "C_NOT_IMPLEMENTED"));
    CHECK(HasRisk(j, "R_UNKNOWN_EFFECT"));
    CHECK(j["canonical"].get<std::string>().empty());
    CHECK(j["risks"][0].contains("line") && j["risks"][0].contains("col"));
}

TEST(CheckCode, RiskForcesConfirmAndKeepsCanonical) {
    const Json j = Check("ЗаписьЖурналаРегистрации(\"x\"); Результат = 1;");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasRisk(j, "R_WRITE"));
    CHECK(!j["canonical"].get<std::string>().empty());
}

TEST(CheckCode, IncompleteListsMissingTables) {
    const Json j = Check("З = Новый Запрос(\"ВЫБРАТЬ Н.Х КАК Х ИЗ Справочник.Нет КАК Н\");\n"
                         "Результат = З.Выполнить().Выгрузить();");
    CHECK_EQ(Verdict(j), std::string("incomplete"));
    CHECK_EQ(j["missing_tables"][0].get<std::string>(), std::string("Справочник.Нет"));
    CHECK(j["canonical"].get<std::string>().empty());
}

TEST(CheckCode, BoundTokenIsPrintedAsHostValue) {
    const Json j = Check("Результат = \"[str-00001]\";", PolicyWithTokens());
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$"), std::string("protected"));
    const std::string canonical = j["canonical"].get<std::string>();
    CHECK(canonical.find("МСПЗначенияТокенов[0]") != std::string::npos);
    CHECK(canonical.find("str-00001") == std::string::npos);
}

TEST(CheckCode, QueryTextIsReplacedByItsCanonicalForm) {
    const Json j = Check("З = Новый Запрос(\"выбрать а.Имя как Имя из Справочник.А как а\");\n"
                         "Результат = З.Выполнить().Выгрузить();");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK(j["canonical"].get<std::string>().find("ВЫБРАТЬ") != std::string::npos);
    CHECK_EQ(Label(j, "$[*].Имя"), std::string("protected"));
}

TEST(CheckCode, ClientTextOnlyInCanonicalAndPaths) {
    // A string value the client wrote appears in the canonical text and nowhere else.
    const Json j = Check("Х = \"СекретноеЗначениеКлиента\"; Результат = Х;");
    CHECK_EQ(Verdict(j), std::string("safe"));
    Json rest = j;
    rest.erase("canonical");
    CHECK(rest.dump().find("СекретноеЗначениеКлиента") == std::string::npos);
    CHECK(j["canonical"].get<std::string>().find("СекретноеЗначениеКлиента") != std::string::npos);
}

TEST(CheckCode, NeverThrowsAndFailsClosed) {
    const Json j = Check("\xFF\xFE", "\xFF");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    const Json k = Check(std::string(3000000, 'x'));
    CHECK_EQ(Verdict(k), std::string("confirm"));
}

TEST(CheckCode, AnalysisFailureHasNoCanonical) {
    // An over-budget loop nest is C_LIMIT: the walk did not complete, nothing may be executed from this answer.
    std::string code = "Х = 0;\n";
    for (int i = 0; i < 40; ++i) code += "Пока Х < 5 Цикл\n";
    code += "Х = Х + 1;\n";
    for (int i = 0; i < 40; ++i) code += "КонецЦикла;\n";
    code += "Результат = Х;";
    const Json j = Check(code);
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(j["canonical"].get<std::string>().empty());
}

TEST(CheckCode, KeysDifferingOnlyInYoAreUnknown) {
    // ё and е fold into one field internally; the serialized spelling is not known, so the field is unknown.
    const Json j = Check("Результат = Новый Структура(\"Её\", 1); Результат.Вставить(\"Ее\", 2);");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_UNLABELED_RESULT"));
    CHECK_EQ(Label(j, "$.Её"), std::string("unknown"));
    // A single spelling keeps its exact spelling in the path.
    const Json k = Check("Результат = Новый Структура(\"Её\", 1);");
    CHECK_EQ(Verdict(k), std::string("safe"));
    CHECK_EQ(Label(k, "$.Её"), std::string("client"));
}

TEST(CheckCode, InvalidBodyHasUnknownRoot) {
    lineage::bsl::Body body;
    body.stmts.push_back(std::make_shared<lineage::bsl::Stmt>());   // kind Unset: ValidateBody refuses it
    lineage::bsl::LabelState state;
    const auto r = lineage::bsl::AnalyzeCodeWalk(body, lineage::bsl::TypeCheckOptions(), state);
    CHECK_EQ(r.result_labels.size(), static_cast<size_t>(1));
    CHECK_EQ(r.result_labels[0].label, std::string("unknown"));
    CHECK(!r.result_reasons.empty());
}

// A parameter name literal no query text can spell (a space, an invisible or look-alike character, empty, a digit
// first) is refused: the host may trim or fold it onto the clean spelling and bind the protected value there. The
// column of the clean parameter never keeps the client label of its other binding.
TEST(CheckCode, ParamNameOutsideTheParameterAlphabetIsConfirm) {
    const std::pair<const char*, const char*> cases[] = {
        {"Пар", "Пар "},
        {"Пар", " Пар"},
        {"Пар", "Пар\xC2\xA0"},
        {"Пар", "Па\xE2\x80\x8Bр"},
        {"ПаВ", "Па\xE1\xB2\x80"},
        {"Sum", "\xC5\xBFum"},
        {"ID", "\xC4\xB1" "d"},
        {"k", "\xE2\x84\xAA"},
        {"Пар", ""},
        {"Пар", "1Пар"},
    };
    for (const auto& c : cases) {
        const std::string code = std::string(
            "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя ИЗ Справочник.А КАК А\");\n"
            "В = З.Выполнить().Выбрать();\nВ.Следующий();\n"
            "З2 = Новый Запрос(\"ВЫБРАТЬ &") + c.first + " КАК Х\");\n"
            "З2.УстановитьПараметр(\"" + c.first + "\", 1);\n"
            "З2.УстановитьПараметр(\"" + c.second + "\", В.Имя);\n"
            "Результат = З2.Выполнить().Выгрузить();\n";
        const Json j = Check(code);
        CHECK_EQ(Verdict(j), std::string("confirm"));
        CHECK(HasReason(j, "C_BAD_PARAM_NAME"));
        CHECK(Label(j, "$[*].Х") != std::string("client"));
    }
}

// Mixed scripts inside the parameter alphabet are a legitimate parameter name (a query text naming it is refused by
// the query parser's own mixed-script rule, so the text below names another parameter).
TEST(CheckCode, MixedScriptParamNameIsSafe) {
    const Json j = Check(
        "З = Новый Запрос(\"ВЫБРАТЬ &Пар КАК Х\");\n"
        "З.УстановитьПараметр(\"Пар\", 1);\n"
        "З.УстановитьПараметр(\"ДатаНачалаUTC\", 1);\n"
        "Результат = З.Выполнить().Выгрузить();\n");
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK(!HasReason(j, "C_BAD_PARAM_NAME"));
    CHECK_EQ(Label(j, "$[*].Х"), std::string("client"));
}

// A query text naming a mixed-script parameter (a Latin A inside a Cyrillic word) passes; a field or a table with the
// same mixing, or a look-alike pair of parameters, stays refused.
TEST(CheckCode, MixedScriptQueryParameterInCode) {
    const std::string q = "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя ИЗ Справочник.А КАК А ГДЕ А.Код = &ВидA\");\n";
    const Json ok = Check(q + "З.УстановитьПараметр(\"ВидA\", \"1\");\nРезультат = З.Выполнить().Выгрузить();");
    CHECK(!HasReason(ok, "Q_PARSE_MIXED_SCRIPT"));
    CHECK(!HasReason(ok, "C_BAD_PARAM_NAME"));
    CHECK(!HasReason(ok, "C_PARSE"));
    CHECK(ok["canonical"].get<std::string>().find("&ВидA") != std::string::npos);
    // field / table of the text stay refused even next to a mixed parameter
    CHECK(HasReason(Check("З = Новый Запрос(\"ВЫБРАТЬ А.ВидA ИЗ Справочник.А КАК А ГДЕ А.Код = &ВидA\");\nРезультат = 1;"),
                    "Q_PARSE_MIXED_SCRIPT"));
    CHECK(HasReason(Check("З = Новый Запрос(\"ВЫБРАТЬ А.Код ИЗ Справочник.ВидA КАК А ГДЕ А.Код = &ВидA\");\nРезультат = 1;"),
                    "Q_PARSE_MIXED_SCRIPT"));
    CHECK(HasReason(Check("З = Новый Запрос(\"ВЫБРАТЬ &ВидA КАК Х, &ВидА КАК У\");\nРезультат = 1;"), "Q_PARSE_MIXED_SCRIPT"));
    // a parameter used inside a nested query
    const Json nested = Check(
        "З = Новый Запрос(\"ВЫБРАТЬ Н.Код КАК Х ИЗ (ВЫБРАТЬ А.Код КАК Код ИЗ Справочник.А КАК А ГДЕ А.Код = &ВидA) КАК Н\");\n"
        "З.УстановитьПараметр(\"ВидA\", \"1\");\nРезультат = З.Выполнить().Выгрузить();");
    CHECK(!HasReason(nested, "Q_PARSE_MIXED_SCRIPT"));
    // the same name used as a code identifier is still a refused mixed-script identifier (a parameter name is no variable)
    const Json ident = Check("З = Новый Запрос(\"ВЫБРАТЬ &ВидA КАК Х\");\nРезультат = ВидA;");
    CHECK(Verdict(ident) != std::string("safe"));
    // a binding under the look-alike spelling does not bind the text's parameter
    const Json other = Check(q + "З.УстановитьПараметр(\"ВидА\", \"1\");\nРезультат = З.Выполнить().Выгрузить();");
    CHECK(Verdict(other) != std::string("safe"));
}

// A confusable pair of parameter names (Latin A / Cyrillic А) is refused wherever the two spellings sit: in one text,
// or split across two texts of the same code. A sibling text never makes the Latin-mixed spelling pass.
TEST(CheckCode, MixedScriptParameterLookalikeAcrossTexts) {
    const Json same = Check(
        "А = Новый Запрос(\"ВЫБРАТЬ &ВидA КАК Первый\");\nА.УстановитьПараметр(\"ВидA\", \"1\");\n"
        "Б = Новый Запрос(\"ВЫБРАТЬ &ВидA КАК Первый, &ВидА КАК Второй\");\n"
        "Б.УстановитьПараметр(\"ВидA\", \"1\");\nБ.УстановитьПараметр(\"ВидА\", \"2\");\n"
        "Результат = Б.Выполнить().Выгрузить();");
    CHECK(HasReason(same, "Q_PARSE_MIXED_SCRIPT"));
    CHECK(Verdict(same) != std::string("safe"));
    const Json split = Check(
        "А = Новый Запрос(\"ВЫБРАТЬ &ВидA КАК Первый\");\nА.УстановитьПараметр(\"ВидA\", \"1\");\n"
        "Б = Новый Запрос(\"ВЫБРАТЬ &ВидА КАК Второй\");\nБ.УстановитьПараметр(\"ВидА\", \"2\");\n"
        "Результат = А.Выполнить().Выгрузить();");
    CHECK(HasReason(split, "Q_PARSE_MIXED_SCRIPT"));
    CHECK(Verdict(split) != std::string("safe"));
}

namespace {

// A query reading the protected Имя, its first row in В, and a second query З2 (by default its only column is the
// parameter &Пар); `setters` follow, then З2's result is the Результат.
std::string LostQueryCode(const std::string& setters, const char* text = "\"ВЫБРАТЬ &Пар КАК Х\"") {
    return std::string(
               "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя ИЗ Справочник.А КАК А\");\n"
               "В = З.Выполнить().Выбрать();\nВ.Следующий();\n"
               "З2 = Новый Запрос(") +
           text + ");\n" + setters + "Результат = З2.Выполнить().Выгрузить();\n";
}

}  // namespace

// The control of the tests below: the parameter bound once with a literal is a client column.
TEST(CheckCode, LiteralParameterIsClient) {
    const Json j = Check(LostQueryCode("З2.УстановитьПараметр(\"Пар\", 1);\n"));
    CHECK_EQ(Verdict(j), std::string("safe"));
    CHECK_EQ(Label(j, "$[*].Х"), std::string("client"));
}

// A parameter binding the walk cannot follow (a name that is not a literal, the Параметры collection, any member,
// method, index or iteration not modelled on Запрос, a wrong argument count, a reserved name) is a reason, and every
// column of that query's results is unknown: a confirmed run must not return the protected value under the client
// label of the literal binding.
TEST(CheckCode, UnfollowedParameterBindingMakesColumnsUnknown) {
    const std::pair<const char*, const char*> cases[] = {
        {"Н = \"Пар\";\nЗ2.УстановитьПараметр(Н, В.Имя);\n", "C_DYNAMIC_PARAM"},
        {"З2.УстановитьПараметр(\"Па\" + \"р\", В.Имя);\n", "C_DYNAMIC_PARAM"},
        {"З2.SetParameter(\"Па\" + \"р\", В.Имя);\n", "C_DYNAMIC_PARAM"},
        {"З2.Параметры[\"Пар\"] = В.Имя;\n", "C_UNKNOWN_MEMBER"},
        {"З2.Параметры.Пар = В.Имя;\n", "C_UNKNOWN_MEMBER"},
        {"З2.Параметры.Вставить(\"Пар\", В.Имя);\n", "C_UNKNOWN_MEMBER"},
        {"З2.Parameters.Insert(\"Пар\", В.Имя);\n", "C_UNKNOWN_MEMBER"},
        {"З2.УстановитьПараметр(\"Пар\", В.Имя, 1);\n", "C_BAD_ARGS"},
        {"З2.УстановитьПараметр(\"МСПТокен1\", В.Имя);\n", "C_RESERVED"},
        {"З2.НайтиПараметры();\n", "C_UNKNOWN_METHOD"},
        {"З2[\"Пар\"] = В.Имя;\n", "C_UNKNOWN_INDEX"},
        {"Т = З2[0];\n", "C_UNKNOWN_INDEX"},
        {"З2.Пар = В.Имя;\n", "C_UNKNOWN_MEMBER"},
        {"Т = З2.Текст;\n", "C_UNKNOWN_MEMBER"},
    };
    for (const auto& c : cases) {
        const Json j = Check(LostQueryCode(std::string("З2.УстановитьПараметр(\"Пар\", 1);\n") + c.first));
        CHECK_EQ(Verdict(j), std::string("confirm"));
        CHECK(HasReason(j, c.second));
        CHECK_EQ(Label(j, "$[*]"), std::string("container"));
        CHECK_EQ(Label(j, "$[*].Х"), std::string("unknown"));
    }
}

// The same for a query allocated without a text, a query executed before the binding the walk cannot follow (the
// fixpoint relabels the earlier result too), and a column read from a row of the result.
TEST(CheckCode, UnfollowedParameterBindingVariants) {
    const char* const head =
        "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя ИЗ Справочник.А КАК А\");\n"
        "В = З.Выполнить().Выбрать();\nВ.Следующий();\n"
        "З2 = Новый Запрос(\"ВЫБРАТЬ &Пар КАК Х\");\nЗ2.УстановитьПараметр(\"Пар\", 1);\n";
    {
        const Json j = Check(LostQueryCode(
            "З2.Текст = \"ВЫБРАТЬ &Пар КАК Х\";\nЗ2.УстановитьПараметр(\"Пар\", 1);\nЗ2.Параметры.Пар = В.Имя;\n", ""));
        CHECK_EQ(Verdict(j), std::string("confirm"));
        CHECK_EQ(Label(j, "$[*].Х"), std::string("unknown"));
    }
    {
        const Json j = Check(std::string(head) +
                             "Р = З2.Выполнить().Выгрузить();\nЗ2.Параметры.Пар = В.Имя;\nРезультат = Р;\n");
        CHECK_EQ(Verdict(j), std::string("confirm"));
        CHECK_EQ(Label(j, "$[*].Х"), std::string("unknown"));
    }
    {
        const Json j = Check(std::string(head) +
                             "З2.Параметры.Пар = В.Имя;\nВ2 = З2.Выполнить().Выбрать();\nВ2.Следующий();\n"
                             "Результат = Новый Структура(\"К\", В2.Х);\n");
        CHECK_EQ(Verdict(j), std::string("confirm"));
        CHECK_EQ(Label(j, "$.К"), std::string("unknown"));
    }
}

// A query whose text or object the walk loses (a text that is not constant-folded, a copy into another variable, a
// collection or an argument) has no known columns: the whole result is unknown.
TEST(CheckCode, LostQueryTextOrObjectMakesResultUnknown) {
    const std::pair<const char*, const char*> cases[] = {
        {"Т = Новый Массив;\nТ.Добавить(\"ВЫБРАТЬ А.Имя КАК Х ИЗ Справочник.А КАК А\");\nЗ2.Текст = Т[0];\n",
         "C_DYNAMIC_QUERY"},
        {"З3 = З2;\nЗ3.УстановитьПараметр(\"Пар\", В.Имя);\n", "C_QUERY_ESCAPES"},
        {"С = Новый Структура(\"З\", З2);\n", "C_QUERY_ESCAPES"},
        {"М = Новый Массив;\nМ.Добавить(З2);\n", "C_QUERY_ESCAPES"},
        {"МойМодуль.Заполнить(З2, В.Имя);\n", "C_QUERY_ESCAPES"},
    };
    for (const auto& c : cases) {
        const Json j = Check(LostQueryCode(std::string("З2.УстановитьПараметр(\"Пар\", 1);\n") + c.first));
        CHECK_EQ(Verdict(j), std::string("confirm"));
        CHECK(HasReason(j, c.second));
        CHECK_EQ(Label(j, "$"), std::string("unknown"));
        CHECK_EQ(Label(j, "$[*].Х"), std::string("<none>"));
    }
}

// Two bindings whose names differ only in yo / ie are one binding to the code checker, whichever the platform does:
// its label joins both values, so the column is not client.
TEST(CheckCode, YoVariantParameterBindingsJoin) {
    const Json j = Check(LostQueryCode("З2.УстановитьПараметр(\"Еж\", 1);\nЗ2.УстановитьПараметр(\"Ёж\", В.Имя);\n",
                                       "\"ВЫБРАТЬ &Еж КАК Х\""));
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK_EQ(Label(j, "$[*].Х"), std::string("unknown"));
}

// "params" spellings differing only in yo / ie with different origins make the policy malformed for the code checker
// too; the same origin is fine.
TEST(CheckCode, YoCollidingParamOriginsArePolicyInvalid) {
    Json policy = Json::parse(kPolicyABJson);
    policy["params"] = Json::parse(R"({"Еж": "client", "Ёж": "token_protected"})");
    const Json j = Check("Результат = 1;", policy.dump());
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_POLICY_INVALID"));
    policy["params"] = Json::parse(R"({"Еж": "client", "ёж": "client"})");
    const Json same = Check("Результат = 1;", policy.dump());
    CHECK_EQ(Verdict(same), std::string("safe"));
}

// A configuration name mixing scripts passes when the policy lists it; a look-alike of it does not.
TEST(CheckCode, MixedScriptNamesOfThePolicyPass) {
    const std::string policy = R"({"version":1,"tables":{"Справочник.ТомаS3":{"presentation":"protected",
        "fields":{"Ссылка":{"class":"open","refs":["Справочник.ТомаS3"]},"ПометкаУдаления":{"class":"open"}}}}})";
    const Json ok = Check("З = Новый Запрос(\"ВЫБРАТЬ КОЛИЧЕСТВО(*) КАК К ИЗ Справочник.ТомаS3 КАК Т\");\n"
                          "Результат = З.Выполнить().Выгрузить()[0].К;", policy);
    CHECK_EQ(Verdict(ok), std::string("safe"));
    CHECK_EQ(Verdict(Check("ТомаS3 = 1;\nРезультат = ТомаS3;", policy)), std::string("safe"));
    CHECK_EQ(Verdict(Check("Результат = ПравоДоступа(\"Чтение\", Метаданные.Справочники.ТомаS3);", policy)),
             std::string("safe"));
    CHECK(HasReason(Check("Результат = ПравоДоступа(\"Чтение\", Метаданные.Справочники.TомаS3);", policy), "C_PARSE"));
    CHECK(HasReason(Check("З = Новый Запрос(\"ВЫБРАТЬ КОЛИЧЕСТВО(*) КАК К ИЗ Справочник.TомаS3 КАК Т\");\n"
                          "Результат = 1;", policy), "Q_PARSE_MIXED_SCRIPT"));   // Latin T inside the query text
    CHECK_EQ(Verdict(Check("ТомS3 = 1; Результат = ТомS3;", policy)), std::string("safe"));   // a variable of its own
    // Not in the policy yet: the code names its tables (managers, Метаданные collections, query texts) as missing.
    const Json first = Check("С = Справочники.ТомаS3.ПустаяСсылка();\nРезультат = 1;");
    CHECK_EQ(Verdict(first), std::string("incomplete"));
    CHECK_EQ(first["missing_tables"][0].get<std::string>(), std::string("Справочник.ТомаS3"));
    const Json text = Check("З = Новый Запрос(\"ВЫБРАТЬ Т.ПравилаXML КАК П ИЗ РегистрСведений.Правила КАК Т\");\n"
                            "В = З.Выполнить().Выбрать(); Результат = В.ПравилаXML;");
    CHECK_EQ(Verdict(text), std::string("incomplete"));
    CHECK_EQ(text["missing_tables"][0].get<std::string>(), std::string("РегистрСведений.Правила"));
    CHECK_EQ(Verdict(Check("Pезультат = 1;")), std::string("confirm"));   // no table to ask for
}

namespace {

// "code1,code2" of the reasons / risks of an answer, sorted and without repeats.
std::string CodeSet(const Json& j, const char* key) {
    std::set<std::string> codes;
    for (const Json& r : j[key]) codes.insert(r["code"].get<std::string>());
    std::string out;
    for (const std::string& c : codes) out += (out.empty() ? "" : ",") + c;
    return out;
}

}  // namespace

// B4: the no-argument calls БезопасныйРежим() / SafeMode() / ТранзакцияАктивна() / TransactionActive() read session
// state, not data: no reason, no risk.
TEST(CheckCode, PureSessionReadersAreSafeWithoutRisks) {
    const char* const kCodes[] = {
        "Результат = БезопасныйРежим();", "Результат = SafeMode();", "Результат = ТранзакцияАктивна();",
        "Результат = TransactionActive();", "Результат = безопасныйрежим();", "Результат = БезопасныйРежим( );",
        "Результат = БезопасныйРежим\n();", "Если ТранзакцияАктивна() Тогда\n    Результат = 1;\nКонецЕсли;",
        "Если НЕ БезопасныйРежим() Тогда\n    Результат = 1;\nКонецЕсли;"};
    for (const char* code : kCodes) {
        const Json j = Check(code);
        CHECK_EQ(Verdict(j), std::string("safe"));
        CHECK_EQ(CodeSet(j, "reasons"), std::string());
        CHECK_EQ(CodeSet(j, "risks"), std::string());
    }
    // A reader next to otherwise safe code stays safe; a risk of the neighbour is still reported.
    const Json mixed = Check("Если ТранзакцияАктивна() Тогда\n    УстановитьБезопасныйРежим(Истина);\nКонецЕсли;\nРезультат = 1;");
    CHECK(Verdict(mixed) != std::string("safe"));
    CHECK(HasRisk(mixed, "R_PROTECTION"));
}

// B4: what is not the exact no-argument call keeps today's verdict and risk classes (pinned before the change; a call
// with an argument now fails the arity check instead of C_UNKNOWN_IDENT, still confirm with its risk).
TEST(CheckCode, SessionSettersAndLookalikesKeepTheirVerdicts) {
    struct Pin {
        const char* code;
        const char* verdict;
        const char* reasons;
        const char* risks;
    };
    const Pin kPins[] = {
        {"УстановитьБезопасныйРежим(Истина);\nРезультат = 1;", "deny", "C_EFFECT_DENIED,C_UNKNOWN_IDENT",
         "R_PROTECTION,R_UNKNOWN_EFFECT,R_WRITE"},
        {"УстановитьОтключениеБезопасногоРежима(Истина);\nРезультат = 1;", "deny", "C_EFFECT_DENIED,C_UNKNOWN_IDENT",
         "R_PROTECTION,R_UNKNOWN_EFFECT,R_WRITE"},
        {"ОтключениеБезопасногоРежима();\nРезультат = 1;", "confirm", "C_UNKNOWN_IDENT", "R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"SetSafeMode(True);\nРезультат = 1;", "deny", "C_EFFECT_DENIED,C_UNKNOWN_IDENT",
         "R_PROTECTION,R_UNKNOWN_EFFECT,R_WRITE"},
        {"SetSafeModeDisabled(True);\nРезультат = 1;", "deny", "C_EFFECT_DENIED,C_UNKNOWN_IDENT",
         "R_PROTECTION,R_UNKNOWN_EFFECT,R_WRITE"},
        {"Результат = БезопасныйРежим(\"x\");", "confirm", "C_BAD_ARGS", "R_PROTECTION"},
        {"Результат = БезопасныйРежим(1, 2);", "confirm", "C_BAD_ARGS", "R_PROTECTION"},
        {"Результат = SafeMode(\"x\");", "confirm", "C_BAD_ARGS", "R_PROTECTION"},
        {"Результат = ТранзакцияАктивна(1);", "confirm", "C_BAD_ARGS", "R_WRITE"},
        {"Результат = Х.БезопасныйРежим();", "confirm", "C_COMMON_MODULE,C_UNLABELED_RESULT",
         "R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"Результат = Х.ТранзакцияАктивна();", "confirm", "C_COMMON_MODULE,C_UNLABELED_RESULT",
         "R_UNKNOWN_EFFECT,R_WRITE"},
        {"Результат = ЭтотОбъект.БезопасныйРежим();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"Результат = БезопасныйРежимХ();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"Результат = ХБезопасныйРежим();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"Результат = ТранзакцияАктивнаХ();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_UNKNOWN_EFFECT,R_WRITE"},
        {"Результат = Новый БезопасныйРежим();", "confirm", "C_UNKNOWN_TYPE,C_UNLABELED_RESULT",
         "R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"БезопасныйРежим = 1;\nРезультат = БезопасныйРежим;", "safe", "", "R_PROTECTION"},   // a variable
        {"Результат = БезопасныйРежим;", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT", "R_PROTECTION"},
    };
    for (const Pin& p : kPins) {
        const Json j = Check(p.code);
        CHECK_EQ(Verdict(j), std::string(p.verdict));
        CHECK_EQ(CodeSet(j, "reasons"), std::string(p.reasons));
        CHECK_EQ(CodeSet(j, "risks"), std::string(p.risks));
    }
}

// B4: the reader exemption lives in the checker's tree pass and in the token pass alike: a reader whose tree the parser
// refused is still shown with its risk when it is not the plain no-argument call.
TEST(CheckCode, ReaderExemptionNeedsTheExactCallShape) {
    CHECK(HasRisk(Check("Результат = БезопасныйРежим(\"x\") +;"), "R_PROTECTION"));   // refused tree, with an argument
    CHECK(HasRisk(Check("Результат = Х.БезопасныйРежим() +;"), "R_PROTECTION"));
    CHECK(!HasRisk(Check("Результат = БезопасныйРежим() +;"), "R_PROTECTION"));       // refused tree, plain reader
}

// B5: the synthetic R_UNKNOWN_EFFECT of a refused tree carries the refusal's own position (not 1:1), once.
TEST(CheckCode, RefusalRiskSitsAtTheRefusalPosition) {
    std::string code = "Х = НеизвестнаяФункцияА(1);\n";
    for (int i = 0; i < 2500; ++i) code += "Результат = 1;\n";
    const Json j = Check(code);
    CHECK_EQ(Verdict(j), std::string("confirm"));
    const Json* limit = nullptr;
    for (const Json& r : j["reasons"]) {
        if (r["code"].get<std::string>() == "C_LIMIT") limit = &r;
    }
    CHECK(limit != nullptr);
    if (!limit) return;
    int at_limit = 0, at_origin = 0;
    for (const Json& r : j["risks"]) {
        if (r["code"].get<std::string>() != "R_UNKNOWN_EFFECT") continue;
        if (r["line"] == (*limit)["line"] && r["col"] == (*limit)["col"]) ++at_limit;
        if (r["line"] == 1 && r["col"] == 1) ++at_origin;
    }
    CHECK_EQ(at_limit, 1);
    CHECK_EQ(at_origin, 0);
}

// A: СтрокаСоединенияИнформационнойБазы() / InfoBaseConnectionString() read the identity of the base, not data: an Open
// string, no reason, no risk (kPureReaders mechanism). The exact no-argument call only.
TEST(CheckCode, ConnectionStringReaderIsSafeWithoutRisks) {
    const char* const kCodes[] = {
        "Результат = СтрокаСоединенияИнформационнойБазы();", "Результат = InfoBaseConnectionString();",
        "Результат = строкасоединенияинформационнойбазы();", "Результат = СтрокаСоединенияИнформационнойБазы( );",
        "Результат = СтрНайти(СтрокаСоединенияИнформационнойБазы(), \"buh\") > 0;",
        "Результат = Новый Структура(\"К\", СтрНайти(InfoBaseConnectionString(), \"File\") > 0);"};
    for (const char* code : kCodes) {
        const Json j = Check(code);
        CHECK_EQ(Verdict(j), std::string("safe"));
        CHECK_EQ(CodeSet(j, "reasons"), std::string());
        CHECK_EQ(CodeSet(j, "risks"), std::string());
    }
    CHECK(Label(Check("Результат = СтрокаСоединенияИнформационнойБазы();"), "$") != std::string("protected"));
    // The neighbour's risk is still reported.
    const Json mixed = Check("Результат = СтрокаСоединенияИнформационнойБазы();\nПарольПользователя = 1;");
    CHECK(HasRisk(mixed, "R_CREDENTIALS"));
}

// A: every other name that contains СтрокаСоединения / ConnectionString keeps its verdict and risks.
TEST(CheckCode, ConnectionStringLookalikesKeepTheirVerdicts) {
    struct Pin {
        const char* code;
        const char* verdict;
        const char* reasons;
        const char* risks;
    };
    const Pin kPins[] = {
        {"Результат = СтрокаСоединенияИнформационнойБазыХ();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_CREDENTIALS,R_UNKNOWN_EFFECT"},
        {"Результат = ХСтрокаСоединенияИнформационнойБазы();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_CREDENTIALS,R_UNKNOWN_EFFECT"},
        {"Результат = СтрокаСоединенияВнешнегоИсточника();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_CREDENTIALS,R_PROTECTION,R_UNKNOWN_EFFECT"},
        {"Результат = Новый СтрокаСоединенияИнформационнойБазы();", "confirm", "C_UNKNOWN_TYPE,C_UNLABELED_RESULT",
         "R_CREDENTIALS,R_UNKNOWN_EFFECT"},
        {"Результат = СтрокаСоединенияИнформационнойБазы;", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_CREDENTIALS"},
        {"СтрокаСоединенияИнформационнойБазы = 1;\nРезультат = СтрокаСоединенияИнформационнойБазы;", "safe", "",
         "R_CREDENTIALS"},   // a variable
        {"Результат = ConnectionString();", "confirm", "C_UNKNOWN_IDENT,C_UNLABELED_RESULT",
         "R_CREDENTIALS,R_UNKNOWN_EFFECT"},
    };
    for (const Pin& p : kPins) {
        const Json j = Check(p.code);
        CHECK_EQ(Verdict(j), std::string(p.verdict));
        CHECK_EQ(CodeSet(j, "reasons"), std::string(p.reasons));
        CHECK_EQ(CodeSet(j, "risks"), std::string(p.risks));
    }
    // A call with an argument fails the arity row: still confirm with the credentials risk.
    const Json arg = Check("Результат = СтрокаСоединенияИнформационнойБазы(\"x\");");
    CHECK_EQ(Verdict(arg), std::string("confirm"));
    CHECK(HasReason(arg, "C_BAD_ARGS"));
    CHECK(HasRisk(arg, "R_CREDENTIALS"));
    // A method of another object is not the reader.
    const Json member = Check("Результат = Х.СтрокаСоединенияИнформационнойБазы();");
    CHECK(Verdict(member) != std::string("safe"));
    CHECK(HasRisk(member, "R_CREDENTIALS"));
    // A homoglyph spelling (Latin "a" instead of Cyrillic in "Строка") is not the reader.
    const Json lookalike = Check("Результат = Строк\x61" "СоединенияИнформационнойБазы();");
    CHECK(Verdict(lookalike) != std::string("safe"));
    CHECK(HasRisk(lookalike, "R_CREDENTIALS"));
}

// A: the exemption needs the exact call shape also in the token scan of refused code.
TEST(CheckCode, ConnectionStringExemptionNeedsTheExactCallShape) {
    CHECK(HasRisk(Check("Результат = СтрокаСоединенияИнформационнойБазы(\"x\") +;"), "R_CREDENTIALS"));
    CHECK(HasRisk(Check("Результат = Х.СтрокаСоединенияИнформационнойБазы() +;"), "R_CREDENTIALS"));
    CHECK(!HasRisk(Check("Результат = СтрокаСоединенияИнформационнойБазы() +;"), "R_CREDENTIALS"));
}

// D: the client may read the platform enumeration Символы / Chars (the printer no longer owns the name).
TEST(CheckCode, ClientMayReadChars) {
    const char* const kCodes[] = {
        "Результат = Символы.ПС;", "Результат = Chars.LF;", "Результат = Символы.Таб;", "Результат = символы.вк;",
        "Результат = СтрДлина(\"а\" + Символы.ПС + \"б\");", "Результат = СтрЗаменить(\"а,б\", \",\", Символы.ПС);",
        "Результат = Символы.ВТаб + Символы.НПП + Символы.ПФ;"};
    for (const char* code : kCodes) {
        const Json j = Check(code);
        CHECK_EQ(Verdict(j), std::string("safe"));
        CHECK_EQ(CodeSet(j, "reasons"), std::string());
        CHECK_EQ(CodeSet(j, "risks"), std::string());
    }
    // Only the six members of the enumeration; anything else on it, a call on it or a write to it is not allowed.
    CHECK(HasReason(Check("Результат = Символы.Пробел;"), "C_UNKNOWN_MEMBER"));
    CHECK(Verdict(Check("Символы.ПС = 1;\nРезультат = 1;")) != std::string("safe"));
    CHECK(Verdict(Check("Результат = Символы();")) != std::string("safe"));
    CHECK(Verdict(Check("Результат = Новый Символы;")) != std::string("safe"));
}

// D: the canonical text no longer uses Символы: a client variable of that name cannot change a printed line break.
TEST(CheckCode, PrintedLineBreaksDoNotUseClientNames) {
    const std::string q = "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя\n|ИЗ Справочник.А КАК А\");\n"
                          "Результат = З.Выполнить().Выгрузить();";
    const char* const kPrefixes[] = {"", "Символы = Новый Структура(\"ПС\", \"x\");\n", "Chars = 1;\n", "Символ = 5;\n",
                                     "Символ = Новый Структура(\"К\", 1);\nСимволы = Символ;\n"};
    for (const char* prefix : kPrefixes) {
        const Json j = Check(std::string(prefix) + q);
        CHECK_EQ(Verdict(j), std::string("safe"));
        const std::string canonical = j["canonical"].get<std::string>();
        CHECK(canonical.find("Символ(10)") != std::string::npos);
        CHECK(canonical.find("Символы.ПС +") == std::string::npos);
    }
    // A write to a member of the enumeration is not allowed.
    CHECK(Verdict(Check("Символы.ПС = 1;\n" + q)) != std::string("safe"));
}

// D: a query text built with Символы.ПС is a member read, not a literal: the text is dynamic.
TEST(CheckCode, CharsInQueryTextMakesItDynamic) {
    const Json j = Check("З = Новый Запрос(\"ВЫБРАТЬ 1\" + Символы.ПС + \"КАК А\");\nРезультат = 1;");
    CHECK_EQ(Verdict(j), std::string("confirm"));
    CHECK(HasReason(j, "C_DYNAMIC_QUERY"));
}

// D: Base64 re-encodes a value; it is a known platform function that never unmasks.
TEST(CheckCode, Base64OverOpenAndClientDataIsSafe) {
    const char* const kCodes[] = {
        "Результат = Base64Строка(\"abc\");", "Результат = GetBase64StringFromBinaryData(Base64Value(\"YWJj\"));",
        "Результат = СтрДлина(ПолучитьBase64СтрокуИзДвоичныхДанных(ПолучитьДвоичныеДанныеИзBase64Строки(\"YWJj\")));",
        "Результат = Base64Строка(Base64Значение(\"YWJj\"));", "Результат = base64строка(\"x\");",
        "Результат = GetBinaryDataFromBase64String(\"YWJj\");"};
    for (const char* code : kCodes) {
        const Json j = Check(code);
        CHECK_EQ(Verdict(j), std::string("safe"));
        CHECK_EQ(CodeSet(j, "reasons"), std::string());
        CHECK_EQ(CodeSet(j, "risks"), std::string());
    }
}

// ATTACK: a protected value through Base64 (once, twice, round trip, in a structure, as a loop item, via a variable)
// stays protected: never safe, C_FUNC_OVER_PROTECTED, the label is not open / client.
TEST(CheckCode, Base64OfProtectedStaysProtected) {
    const std::string q = "З = Новый Запрос(\"ВЫБРАТЬ А.Имя КАК Имя, А.Ссылка КАК С ИЗ Справочник.А КАК А\");\n"
                          "Т = З.Выполнить().Выгрузить();\n";
    const char* const kTails[] = {
        "Результат = Base64Строка(Т[0].Имя);", "Результат = Base64Строка(Base64Строка(Т[0].Имя));",
        "Результат = Base64Строка(ПолучитьДвоичныеДанныеИзBase64Строки(Base64Строка(Т[0].Имя)));",
        "Результат = Base64Строка(Base64Значение(Base64Строка(Т[0].Имя)));",   // round trip
        "Результат = ПолучитьBase64СтрокуИзДвоичныхДанных(Base64Значение(Т[0].Имя));",
        "Результат = Новый Структура(\"К\", Base64Строка(Т[0].Имя));",
        "Результат = Новый Массив; Для Каждого С Из Т Цикл Результат.Добавить(Base64Строка(С.Имя)); КонецЦикла;",
        "Х = Т[0].Имя;\nУ = Base64Строка(Х);\nРезультат = Base64Значение(У);",   // through variables
        "Результат = Base64Строка(Т[0].С);"};   // a reference: read as its (protected) presentation
    for (const char* tail : kTails) {
        const Json j = Check(q + tail);
        CHECK(Verdict(j) != std::string("safe"));
        CHECK(HasReason(j, "C_FUNC_OVER_PROTECTED"));
        const std::string l = Label(j, "$");
        CHECK(l != std::string("open") && l != std::string("client"));
    }
    // A client literal next to a protected value does not launder it.
    CHECK(Verdict(Check(q + "Результат = Base64Строка(Т[0].Имя + \"x\");")) != std::string("safe"));
    // Unknown labels stay unknown.
    CHECK(Verdict(Check("Результат = Base64Строка(Х);")) != std::string("safe"));
}

// ATTACK: look-alike spellings are not the platform names.
TEST(CheckCode, Base64LookalikeNamesStayRefused) {
    CHECK(HasReason(Check("Результат = Base64\x43" "трока(\"x\");"), "C_PARSE"));            // Latin C
    CHECK(HasReason(Check("Результат = Base64Зн\x61" "чение(\"eA==\");"), "C_PARSE"));       // Latin a
    CHECK(HasReason(Check("Результат = Base64Строка2(\"x\");"), "C_PARSE"));
    CHECK(HasReason(Check("Результат = Base64Строка(1, 2);"), "C_BAD_ARGS"));
    CHECK(HasReason(Check("Результат = Base64Строка();"), "C_BAD_ARGS"));
    CHECK(HasReason(Check("Результат = Х.Base64Строка(\"x\");"), "C_COMMON_MODULE"));
}

namespace {
std::string PolicyWithConstants() {
    Json p = Json::parse(kPolicyABJson);
    p["tables"]["Константа.КоличествоПотоков"] =
        Json::parse(R"({"presentation": "protected", "fields": {"Значение": {"class": "open"}}})");
    p["tables"]["Константа.ИмяОрганизации"] =
        Json::parse(R"({"presentation": "protected", "fields": {"Значение": {"class": "protected"}}})");
    p["tables"]["Константа.ОсновнойКонтрагент"] =
        Json::parse(R"({"presentation": "protected", "fields": {"Значение": {"class": "open", "refs": ["Справочник.А"]}}})");
    return p.dump();
}
}  // namespace

// A constant's value takes the class of the policy field Константа.<Имя>.Значение.
TEST(CheckCode, ConstantValueTakesThePolicyClass) {
    const std::string pol = PolicyWithConstants();
    const Json open = Check("Результат = Константы.КоличествоПотоков.Получить();", pol);
    CHECK_EQ(Verdict(open), std::string("safe"));
    CHECK_EQ(Label(open, "$"), std::string("open"));
    CHECK_EQ(Verdict(Check("Результат = Константы.КоличествоПотоков.Получить() + 1;", pol)), std::string("safe"));
    CHECK_EQ(Verdict(Check("Результат = Constants.КоличествоПотоков.Get();", pol)), std::string("safe"));
    const Json prot = Check("Результат = Константы.ИмяОрганизации.Получить();", pol);
    CHECK_EQ(Label(prot, "$"), std::string("protected"));
    // ATTACK: computing over a protected constant is an oracle like over a protected field
    for (const char* tail : {"Результат = СтрДлина(Константы.ИмяОрганизации.Получить());",
                             "Результат = Константы.ИмяОрганизации.Получить() = Х;",
                             "Результат = Константы.ИмяОрганизации.Получить() < \"x\";",
                             "Результат = Лев(Константы.ИмяОрганизации.Получить(), 1);",
                             "Результат = Base64Строка(Константы.ИмяОрганизации.Получить());",
                             "Х = Константы.ИмяОрганизации.Получить();\nРезультат = Base64Строка(Х + \"a\");"}) {
        const Json j = Check(tail, pol);
        CHECK(Verdict(j) != std::string("safe"));
        CHECK(HasReason(j, "C_FUNC_OVER_PROTECTED"));
    }
    // one equality with a client literal is the existing single-bit filter, as for any directly read protected value
    CHECK_EQ(Label(Check("Результат = Константы.ИмяОрганизации.Получить() = \"x\";", pol), "$"), std::string("open"));
    CHECK_EQ(Verdict(Check("Результат = Константы.ОсновнойКонтрагент.Получить();", pol)), std::string("safe"));
    const Json deref = Check("Результат = Константы.ОсновнойКонтрагент.Получить().Имя;", pol);
    CHECK_EQ(Verdict(deref), std::string("safe"));   // a masked presentation is returned, as for Ссылка.Имя
    CHECK_EQ(Label(deref, "$"), std::string("protected"));
    // a protected constant kept in a variable: one literal guess is the existing filter equality
    CHECK_EQ(Verdict(Check("Х = Константы.ИмяОрганизации.Получить();\nРезультат = 0;\n"
                           "Если Х = \"a\" Тогда Результат = 1; КонецЕсли;", pol)),
             std::string("safe"));
    // a computed guess in a loop is not
    CHECK(Verdict(Check("Х = Константы.ИмяОрганизации.Получить();\nРезультат = 0;\nДля Н = 1 По 10 Цикл\n"
                        "Если Х = \"a\" + Строка(Н) Тогда Результат = Н; КонецЕсли;\nКонецЦикла;", pol)) != std::string("safe"));
    // unknown to the policy: the host is asked for the table, nothing runs
    const Json missing = Check("Результат = Константы.НетТакой.Получить();", pol);
    CHECK_EQ(Verdict(missing), std::string("incomplete"));
    CHECK_EQ(missing["missing_tables"][0].get<std::string>(), std::string("Константа.НетТакой"));
}

// Only Получить() is a read; everything else on the constants manager is refused.
TEST(CheckCode, ConstantsManagerStaysReadOnly) {
    const std::string pol = PolicyWithConstants();
    for (const char* code : {"Константы.КоличествоПотоков.Установить(1);\nРезультат = 1;",
                             "Результат = Константы.КоличествоПотоков.Значение;",
                             "Результат = Константы.КоличествоПотоков.СоздатьМенеджерЗначения();",
                             "Результат = Константы.СоздатьНабор(\"КоличествоПотоков\");",
                             "Результат = Константы.КоличествоПотоков.Получить(1);",
                             "Результат = Справочники.А.Получить();",
                             "Результат = Константы.КоличествоПотоков;",
                             "Результат = Х.Константы.КоличествоПотоков.Получить();",
                             "Имя = \"КоличествоПотоков\";\nРезультат = Константы[Имя].Получить();",
                             "Результат = Константы[\"КоличествоПотоков\"].Получить();",
                             "Результат = \x4B\xD0\xBE\x6E\x73\x74\x61\x6E\x74\xD1\x8B.КоличествоПотоков.Получить();"}) {   // Latin K, n, s, t, a, n, t
        CHECK(Verdict(Check(code, pol)) != std::string("safe"));
    }
    // look-alike constant name (Latin A inside): not in the policy
    CHECK(Verdict(Check("Результат = Константы.Количество\x50отоков.Получить();", pol)) != std::string("safe"));
}

// R_WRITE is not raised on exactly Константы.<Имя>.Получить() (a read of a constant); the verdict is unchanged.
TEST(CheckCode, ConstantGetChainHasNoWriteRisk) {
    const std::string pol = PolicyWithConstants();
    for (const char* code : {"Результат = Константы.КоличествоПотоков.Получить();",
                             "Результат = Constants.КоличествоПотоков.Get();",
                             "Результат = Константы.КоличествоПотоков.Получить() + 1;",
                             "Результат = СтрДлина(Константы.ИмяОрганизации.Получить());",
                             "Результат = СтрДлина(Константы.Тип.Получить());"}) {
        CHECK(!HasRisk(Check(code, pol), "R_WRITE"));
    }
    CHECK_EQ(Verdict(Check("Результат = Константы.КоличествоПотоков.Получить();", pol)), std::string("safe"));
    CHECK(HasReason(Check("Результат = СтрДлина(Константы.ИмяОрганизации.Получить());", pol), "C_FUNC_OVER_PROTECTED"));
}

// ATTACK: every other use of Константы keeps R_WRITE.
TEST(CheckCode, ConstantsWriteRiskStaysOnEverythingElse) {
    const std::string pol = PolicyWithConstants();
    for (const char* code : {"Константы.КоличествоПотоков.Установить(1);\nРезультат = 1;",
                             "Результат = Константы.КоличествоПотоков.СоздатьМенеджерЗначения();",
                             "М = Константы.КоличествоПотоков;\nМ.Установить(1);\nРезультат = 1;",
                             "Результат = Константы.КоличествоПотоков;",
                             "Результат = Константы.КоличествоПотоков.Значение;",
                             "Результат = Константы.КоличествоПотоков.Получить(1);",
                             "Результат = Константы.СоздатьНабор(\"КоличествоПотоков\");",
                             "Результат = Х.Константы.КоличествоПотоков.Получить();",
                             "Результат = Константы[\"КоличествоПотоков\"].Получить();",
                             "Результат = Константы.КоличествоПотоков.Получить() +;"}) {   // refused: token scan keeps the risk
        CHECK(HasRisk(Check(code, pol), "R_WRITE"));
    }
    // Latin-letter spellings of the manager (Konstants; Latin K, n, s, t, a, n, t): not the exempt key and, as on HEAD,
    // not a Write name either; the exemption does not change it and the verdict stays a refusal
    CHECK(Verdict(Check("Результат = Konstants.КоличествоПотоков.Получить();", pol)) != std::string("safe"));
    CHECK(Verdict(Check("Результат = \x4B\xD0\xBE\x6E\x73\x74\x61\x6E\x74\xD1\x8B.КоличествоПотоков.Получить();", pol)) != std::string("safe"));
}
