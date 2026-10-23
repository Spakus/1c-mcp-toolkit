#include <nlohmann/json.hpp>

#include "policy_fixture.h"
#include "strict/check_query.h"
#include "test_framework.h"

using lineage::strict::CheckQueryImpl;
using lineage::strict::kPolicyABJson;

TEST(CheckQuery, JsonContract) {
    auto j = nlohmann::json::parse(CheckQueryImpl("ВЫБРАТЬ А.Имя ИЗ Справочник.А КАК А", kPolicyABJson));
    CHECK_EQ(j["api"].get<int>(), 1);
    CHECK_EQ(j["verdict"].get<std::string>(), std::string("safe"));
    CHECK_EQ(j["columns"][0]["name"].get<std::string>(), std::string("Имя"));
    CHECK_EQ(j["columns"][0]["origin"].get<std::string>(), std::string("protected"));
    CHECK(j["columns"][0]["direct"].get<bool>());
    CHECK(j["canonical"].get<std::string>().rfind("ВЫБРАТЬ", 0) == 0);
}

TEST(CheckQuery, IncompleteListsTables) {
    auto j = nlohmann::json::parse(CheckQueryImpl("ВЫБРАТЬ Н.Х ИЗ Справочник.Нет КАК Н", kPolicyABJson));
    CHECK_EQ(j["verdict"].get<std::string>(), std::string("incomplete"));
    CHECK_EQ(j["missing_tables"][0].get<std::string>(), std::string("Справочник.Нет"));
}

TEST(CheckQuery, NeverThrowsAndFailsClosed) {
    auto j = nlohmann::json::parse(CheckQueryImpl("\xFF", "{"));
    CHECK_EQ(j["verdict"].get<std::string>(), std::string("confirm"));
}

TEST(CheckQuery, MalformedPolicyIsConfirm) {
    auto j = nlohmann::json::parse(CheckQueryImpl("ВЫБРАТЬ 1", "{"));
    CHECK_EQ(j["verdict"].get<std::string>(), std::string("confirm"));
    CHECK_EQ(j["reasons"][0]["code"].get<std::string>(), std::string("Q_POLICY_INVALID"));
    CHECK(j["canonical"].get<std::string>().empty());
}

TEST(CheckQuery, ParseFailureCarriesCodeAndPosition) {
    auto j = nlohmann::json::parse(CheckQueryImpl("ВЫБРАТЬ ИЗ ИЗ", kPolicyABJson));
    CHECK_EQ(j["verdict"].get<std::string>(), std::string("confirm"));
    CHECK(j["reasons"][0]["code"].get<std::string>().rfind("Q_PARSE_", 0) == 0);
    CHECK(j["reasons"][0].contains("line"));
    CHECK(j["canonical"].get<std::string>().empty());
}

TEST(CheckQuery, ReasonsDoNotEchoClientText) {
    auto j = nlohmann::json::parse(CheckQueryImpl(
        "ВЫБРАТЬ А.Имя ИЗ Справочник.А КАК А ГДЕ А.Имя = \"СекретЗначение\"", kPolicyABJson));
    CHECK_EQ(j["verdict"].get<std::string>(), std::string("confirm"));
    CHECK(j["reasons"].size() > 0);
    CHECK(j["reasons"].dump().find("СекретЗначение") == std::string::npos);
}

TEST(CheckQuery, UnlabelledBatchResultIsConfirm) {
    auto a = nlohmann::json::parse(CheckQueryImpl(
        "ВЫБРАТЬ А.Имя ИЗ Справочник.А КАК А;"
        "ВЫБРАТЬ Б.Сумма ИЗ Справочник.Б КАК Б", kPolicyABJson));
    CHECK_EQ(a["verdict"].get<std::string>(), std::string("confirm"));
    CHECK_EQ(a["reasons"][0]["code"].get<std::string>(), std::string("Q_BATCH_RESULT"));
    auto b = nlohmann::json::parse(CheckQueryImpl(
        "ВЫБРАТЬ Б.Сумма КАК Сумма ПОМЕСТИТЬ Т ИЗ Справочник.Б КАК Б;"
        "УНИЧТОЖИТЬ Т", kPolicyABJson));
    CHECK_EQ(b["verdict"].get<std::string>(), std::string("confirm"));
    CHECK_EQ(b["reasons"][0]["code"].get<std::string>(), std::string("Q_BATCH_RESULT"));
}
