#include <nlohmann/json.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

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

TEST(CheckCode, EnvelopeShape) {
    const Json j = Check("Результат = 1;");
    CHECK_EQ(j["api"].get<int>(), 1);
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
