#include "test_framework.h"
#include "strict/field_policy.h"

#include <string>

using namespace lineage::strict;

TEST(Policy, ParseAndLookup) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"Справочник.А":{"presentation":"protected",
        "fields":{"Имя":{"class":"protected"},"Ссылка":{"class":"open","refs":["Справочник.А"]}}}},"params":{"П":"client"}})");
    CHECK(p.ok);
    CHECK(p.policy.ClassOf("справочник.а", "имя") == FieldClass::Protected);   // case-insensitive
    CHECK(p.policy.ClassOf("Справочник.А", "Нет") == FieldClass::Unknown);
    CHECK(!p.policy.HasTable("Справочник.Б"));
    CHECK(p.policy.HasTable("СПРАВОЧНИК.а"));
    CHECK(p.policy.OriginOfParam("П") == ParamOrigin::Client);
    CHECK(p.policy.OriginOfParam("Нет") == ParamOrigin::Missing);
}

TEST(Policy, MalformedIsError) {
    CHECK(!FieldPolicy::FromJson("{").ok);
    CHECK(!FieldPolicy::FromJson("").ok);
    CHECK(!FieldPolicy::FromJson("[]").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":2})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"tables":{}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":"1"})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"А":{"fields":{"Х":{"class":"weird"}}}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"А":{"fields":{"Х":{}}}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"А":{"fields":{"Х":"open"}}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"А":{"presentation":"weird","fields":{}}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"А":{"fields":{"Х":{"class":"open","refs":"Б"}}}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"А":{"fields":{"Х":{"class":"open","refs":[1]}}}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":[]})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"params":{"П":"open"}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"params":{"П":5}})").ok);
}

TEST(Policy, PresentationRules) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{
        "Справочник.А":{"presentation":"protected","fields":{"Представление":{"class":"open"}}},
        "Перечисление.Б":{"presentation":"open","fields":{}},
        "Справочник.В":{"fields":{}}}})");
    CHECK(p.ok);
    CHECK(p.policy.PresentationClass("Справочник.А") == FieldClass::Protected);
    CHECK(p.policy.ClassOf("Справочник.А", "Представление") == FieldClass::Protected);   // never loosened by fields
    CHECK(p.policy.PresentationClass("Перечисление.Б") == FieldClass::Open);
    CHECK(p.policy.ClassOf("Перечисление.Б", "представление") == FieldClass::Open);
    CHECK(p.policy.PresentationClass("Справочник.В") == FieldClass::Protected);          // absent -> protected
    CHECK(p.policy.PresentationClass("Справочник.Нет") == FieldClass::Unknown);
    CHECK(p.policy.ClassOf("Справочник.Нет", "Представление") == FieldClass::Unknown);
}

TEST(Policy, RefsAndFieldInfo) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"Справочник.А":{"presentation":"protected",
        "fields":{"Ссылка":{"class":"open","refs":["Справочник.А","Справочник.Б"]},"Код":{"class":"open"}}}}})");
    CHECK(p.ok);
    const FieldInfo* f = p.policy.Field("справочник.а", "ссылка");
    CHECK(f != nullptr);
    CHECK(f->cls == FieldClass::Open);
    CHECK_EQ(f->refs.size(), size_t(2));
    CHECK(p.policy.Field("Справочник.А", "Нет") == nullptr);
    CHECK(p.policy.Field("Справочник.Нет", "Код") == nullptr);
}

TEST(Policy, TabularSections) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"Документ.Д":{"presentation":"protected",
        "fields":{"Номер":{"class":"open"}},
        "tabular_sections":{"Товары":{"fields":{"Комментарий":{"class":"protected"},"Сумма":{"class":"open"}}}}}}})");
    CHECK(p.ok);
    CHECK(p.policy.HasTable("Документ.Д.Товары"));
    CHECK(p.policy.ClassOf("документ.д.товары", "комментарий") == FieldClass::Protected);
    CHECK(p.policy.ClassOf("Документ.Д.Товары", "Сумма") == FieldClass::Open);
    CHECK(p.policy.PresentationClass("Документ.Д.Товары") == FieldClass::Protected);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"tables":{"Д":{"tabular_sections":{"Т":[]}}}})").ok);
}

TEST(Policy, DuplicateAfterNormalizationOnlyTightens) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"Справочник.А":{"presentation":"open",
        "fields":{"Имя":{"class":"open"},"ИМЯ":{"class":"protected"},"Код":{"class":"protected"},"код":{"class":"open"},
                  "Х":{"class":"open"},"х":{"class":"unknown"}}}}})");
    CHECK(p.ok);
    CHECK(p.policy.ClassOf("Справочник.А", "Имя") == FieldClass::Protected);
    CHECK(p.policy.ClassOf("Справочник.А", "Код") == FieldClass::Protected);
    CHECK(p.policy.ClassOf("Справочник.А", "Х") == FieldClass::Unknown);
}

TEST(Policy, VirtualTables) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"tables":{"РегистрНакопления.Р":{"presentation":"protected",
        "fields":{"Контрагент":{"class":"open","refs":["Справочник.К"]},"Комментарий":{"class":"protected"}}}},
        "virtual_tables":{"РегистрНакопления.Р.Остатки":{"base":"РегистрНакопления.Р",
        "extra_fields":{"СуммаОстаток":{"class":"open"}}}}})");
    CHECK(p.ok);
    CHECK_EQ(p.policy.ResolveVirtualBase("регистрнакопления.р.остатки"), std::string("РегистрНакопления.Р"));
    CHECK_EQ(p.policy.ResolveVirtualBase("РегистрНакопления.Р"), std::string());
    CHECK_EQ(p.policy.ResolveVirtualBase("Нет"), std::string());
    CHECK(p.policy.ClassOf("РегистрНакопления.Р.Остатки", "СуммаОстаток") == FieldClass::Open);
    CHECK(p.policy.ClassOf("РегистрНакопления.Р.Остатки", "Комментарий") == FieldClass::Protected);   // from base
    CHECK(p.policy.ClassOf("РегистрНакопления.Р.Остатки", "Нет") == FieldClass::Unknown);
    CHECK(p.policy.PresentationClass("РегистрНакопления.Р.Остатки") == FieldClass::Protected);
    CHECK(!p.policy.HasTable("РегистрНакопления.Р.Остатки"));
    // the base must be a declared table
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"virtual_tables":{"В":{"base":"Нет"}}})").ok);
    CHECK(!FieldPolicy::FromJson(R"({"version":1,"virtual_tables":{"В":{}}})").ok);
}

TEST(Policy, ParamOrigins) {
    auto p = FieldPolicy::FromJson(R"({"version":1,"params":{"Контр":"token_protected","Дата":"client",
        "МСПТокен1":"token_protected","Х":"token_unknown"}})");
    CHECK(p.ok);
    CHECK(p.policy.OriginOfParam("контр") == ParamOrigin::TokenProtected);
    CHECK(p.policy.OriginOfParam("Дата") == ParamOrigin::Client);
    CHECK(p.policy.OriginOfParam("х") == ParamOrigin::TokenUnknown);
    CHECK(p.policy.OriginOfParam("Другой") == ParamOrigin::Missing);
}
