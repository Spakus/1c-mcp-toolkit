#include <nlohmann/json.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "bsl/check_code.h"
#include "strict/check_query.h"
#include "test_framework.h"

// Strict gate without false confirmations: the checker. Positive controls (what must pass
// without a window), negative controls (what must stay under a window), the oracle reasons with their field and
// operation, the policy keys "compare_allowed" and "deny_effects", and the defect fixes.

namespace {

using Json = nlohmann::json;

const char* const kPolicy = R"({
  "version": 1,
  "tables": {
    "Справочник.Контрагенты": {"presentation": "protected", "fields": {
      "Ссылка": {"class": "open", "refs": ["Справочник.Контрагенты"]},
      "Наименование": {"class": "protected"}, "ИНН": {"class": "protected"},
      "Порядок": {"class": "open"}, "Группа": {"class": "open", "refs": ["Справочник.Группы"]}}},
    "Справочник.Группы": {"presentation": "open", "fields": {
      "Ссылка": {"class": "open", "refs": ["Справочник.Группы"]}, "Наименование": {"class": "open"}}},
    "РегистрСведений.Правила": {"presentation": "protected", "fields": {
      "ИмяПравила": {"class": "protected"}, "Порядок": {"class": "open"}, "Загружено": {"class": "open"},
      "Текст": {"class": "protected"}}}
  },
  "params": {"П": "client"}
})";

const char* const kNameField = "Справочник.Контрагенты.Наименование";
const char* const kInnField = "Справочник.Контрагенты.ИНН";

// kPolicy with "compare_allowed" on the given fields ("Таблица.Поле") and, when `deny` is not null, "deny_effects".
std::string Policy(const std::vector<std::string>& allowed = {}, const Json* deny = nullptr) {
    Json p = Json::parse(kPolicy);
    for (const std::string& f : allowed) {
        const size_t dot = f.rfind('.');
        p["tables"][f.substr(0, dot)]["fields"][f.substr(dot + 1)]["compare_allowed"] = true;
    }
    if (deny) p["deny_effects"] = *deny;
    return p.dump();
}

Json Q(const std::string& text, const std::string& policy = Policy()) {
    return Json::parse(lineage::strict::CheckQueryImpl(text, policy));
}

Json C(const std::string& text, const std::string& policy = Policy()) {
    return Json::parse(lineage::bsl::CheckCodeImpl(text, policy));
}

std::string V(const Json& j) { return j["verdict"].get<std::string>(); }

bool Has(const Json& j, const std::string& code) {
    for (const Json& r : j["reasons"]) {
        if (r["code"].get<std::string>() == code) return true;
    }
    return false;
}

// "code/op@field" of every reason that carries an op.
std::set<std::string> Oracles(const Json& j) {
    std::set<std::string> out;
    for (const Json& r : j["reasons"]) {
        if (!r.contains("op")) continue;
        out.insert(r["code"].get<std::string>() + "/" + r["op"].get<std::string>() +
                   (r.contains("field") ? "@" + r["field"].get<std::string>() : std::string()));
    }
    return out;
}

const std::string kWhere = "ВЫБРАТЬ К.Ссылка КАК С ИЗ Справочник.Контрагенты КАК К ГДЕ ";
const std::string kCode =
    "З = Новый Запрос(\"ВЫБРАТЬ К.Ссылка КАК С, К.Наименование КАК Имя, К.ИНН КАК Инн, К.Порядок КАК Порядок "
    "ИЗ Справочник.Контрагенты КАК К\"); Т = З.Выполнить().Выгрузить(); Р = Т[0];\n";

}  // namespace

// ---- equality is a normal filter ----

TEST(StrictGate, EqualityFiltersPassWithoutWindow) {
    for (const char* cond : {"К.ИНН = \"123\"", "К.ИНН <> \"123\"", "\"123\" = К.ИНН", "К.ИНН = &П",
                             "К.Наименование В (\"а\", \"б\")", "К.Наименование В (&П, \"б\")"}) {
        CHECK_EQ(V(Q(kWhere + cond)), std::string("safe"));
    }
    // a count over rows chosen by equality is the same bit as the rows themselves
    CHECK_EQ(V(Q("ВЫБРАТЬ КОЛИЧЕСТВО(*) КАК К ИЗ Справочник.Контрагенты КАК К ГДЕ К.ИНН = \"1\"")), std::string("safe"));
    // in code
    CHECK_EQ(V(C(kCode + "Если Р.Инн = \"123\" Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;")), std::string("safe"));
    CHECK_EQ(V(C(kCode + "Если Р.Инн <> \"123\" Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;")), std::string("safe"));
}

// A loop must not enumerate guesses: only constant client text is an equality filter in code.
TEST(StrictGate, EqualityWithComputedClientTextStaysUnderWindow) {
    const std::string loop = "Для Н = 1 По 99999 Цикл К = \"А\" + Строка(Н); Если Р.Инн = К Тогда Результат = Н; КонецЕсли; КонецЦикла;";
    CHECK_EQ(V(C(kCode + "Результат = 0;\n" + loop)), std::string("confirm"));
    CHECK_EQ(V(C(kCode + "К = \"А\" + \"Б\"; Если Р.Инн = К Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;")),
             std::string("safe"));   // folded literals are one guess in the text
}

TEST(StrictGate, PiecewiseComparisonsStayUnderWindow) {
    CHECK(Has(Q(kWhere + "К.Наименование ПОДОБНО \"Аб%\""), "Q_LIKE_PROTECTED"));
    CHECK(Has(Q(kWhere + "К.Наименование > \"М\""), "Q_COMPARE_PROTECTED"));
    CHECK(Has(Q(kWhere + "К.Наименование МЕЖДУ \"А\" И \"Б\""), "Q_COMPARE_PROTECTED"));
    CHECK(Has(Q(kWhere + "ПОДСТРОКА(К.Наименование, 1, 1) = \"А\""), "Q_FUNC_OVER_PROTECTED"));
    CHECK(Has(Q(kWhere + "ДЛИНАСТРОКИ(К.Наименование) > 3"), "Q_FUNC_OVER_PROTECTED"));
    // equality with a column of another table is a join key, not a filter by a client value
    CHECK(Has(Q("ВЫБРАТЬ К.Ссылка КАК С ИЗ Справочник.Контрагенты КАК К ВНУТРЕННЕЕ СОЕДИНЕНИЕ Справочник.Группы КАК Г "
                "ПО К.Наименование = Г.Наименование"), "Q_EQ_CLIENT_PARAM"));
    // in code: a piece of the value, a range comparison, a string function whose result leaves as a number
    CHECK_EQ(V(C(kCode + "Если Лев(Р.Имя, 1) = \"А\" Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;")),
             std::string("confirm"));
    CHECK_EQ(V(C(kCode + "Если Р.Имя > \"М\" Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;")), std::string("confirm"));
    CHECK_EQ(V(C(kCode + "Результат = СтрДлина(Р.Имя);")), std::string("confirm"));
    CHECK_EQ(V(C(kCode + "Результат = КодСимвола(Сред(Р.Имя, 1, 1));")), std::string("confirm"));
}

// ---- oracle reasons carry the operation and the field ----

TEST(StrictGate, OracleReasonsNameOperationAndField) {
    const std::string name = kNameField;
    const std::string inn = kInnField;
    CHECK(Oracles(Q(kWhere + "К.Наименование ПОДОБНО \"Аб%\"")) ==
          (std::set<std::string>{"Q_LIKE_PROTECTED/like@" + name}));
    CHECK(Oracles(Q(kWhere + "К.Наименование > \"М\"")) == (std::set<std::string>{"Q_COMPARE_PROTECTED/range@" + name}));
    CHECK(Oracles(Q(kWhere + "ПОДСТРОКА(К.Наименование, 1, 1) = \"А\"")).count("Q_FUNC_OVER_PROTECTED/strfunc@" + name) == 1);
    // two fields in one condition: one reason per field, nothing is dropped as a duplicate
    CHECK(Oracles(Q(kWhere + "К.Наименование ПОДОБНО \"А%\" ИЛИ К.ИНН ПОДОБНО \"1%\"")) ==
          (std::set<std::string>{"Q_LIKE_PROTECTED/like@" + name, "Q_LIKE_PROTECTED/like@" + inn}));
    // ordering by a protected string
    CHECK(Oracles(Q("ВЫБРАТЬ К.Порядок КАК П ИЗ Справочник.Контрагенты КАК К УПОРЯДОЧИТЬ ПО К.Наименование")) ==
          (std::set<std::string>{"Q_ORDER_PROTECTED/range@" + name}));
    // a parse refusal carries no field and no op
    const Json parse = Q("ВЫБРАТЬ ВЫБРАТЬ");
    CHECK(!parse["reasons"][0].contains("field"));
    CHECK(!parse["reasons"][0].contains("op"));
}

// ---- compare_allowed ----

TEST(StrictGate, CompareAllowedOpensOnlyItsOwnField) {
    const std::vector<std::string> name_only{kNameField};
    CHECK_EQ(V(Q(kWhere + "К.Наименование ПОДОБНО \"Аб%\"", Policy(name_only))), std::string("safe"));
    CHECK_EQ(V(Q(kWhere + "К.Наименование > \"М\"", Policy(name_only))), std::string("safe"));
    CHECK_EQ(V(Q(kWhere + "К.Наименование МЕЖДУ \"А\" И \"Б\"", Policy(name_only))), std::string("safe"));
    CHECK_EQ(V(Q(kWhere + "ПОДСТРОКА(К.Наименование, 1, 1) = \"А\"", Policy(name_only))), std::string("safe"));
    CHECK_EQ(V(Q(kWhere + "ДЛИНАСТРОКИ(К.Наименование) > 3", Policy(name_only))), std::string("safe"));
    // another field is not opened by it
    const Json other = Q(kWhere + "К.ИНН ПОДОБНО \"1%\"", Policy(name_only));
    CHECK_EQ(V(other), std::string("confirm"));
    CHECK(Oracles(other) == (std::set<std::string>{std::string("Q_LIKE_PROTECTED/like@") + kInnField}));
    // one allowed and one not: the reason of the second remains, the first is gone
    const Json two = Q(kWhere + "К.Наименование ПОДОБНО \"А%\" ИЛИ К.ИНН ПОДОБНО \"1%\"", Policy(name_only));
    CHECK(Oracles(two) == (std::set<std::string>{std::string("Q_LIKE_PROTECTED/like@") + kInnField}));
    // the row set no longer counts as protected: a count over it passes
    CHECK_EQ(V(Q("ВЫБРАТЬ КОЛИЧЕСТВО(*) КАК К ИЗ Справочник.Контрагенты КАК К ГДЕ К.Наименование ПОДОБНО \"А%\"",
                 Policy(name_only))), std::string("safe"));
    // the value itself stays protected for the output labelling: a string function result leaving as a column is not open
    CHECK_EQ(V(Q("ВЫБРАТЬ ПОДСТРОКА(К.Наименование, 1, 1) КАК Х ИЗ Справочник.Контрагенты КАК К", Policy(name_only))),
             std::string("confirm"));
    CHECK_EQ(V(Q("ВЫБРАТЬ К.Наименование КАК Х ИЗ Справочник.Контрагенты КАК К", Policy(name_only))), std::string("safe"));
}

TEST(StrictGate, CompareAllowedMustBeBoolean) {
    Json p = Json::parse(kPolicy);
    p["tables"]["Справочник.Контрагенты"]["fields"]["ИНН"]["compare_allowed"] = "yes";
    const Json bad = Q(kWhere + "К.ИНН = \"1\"", p.dump());
    CHECK(Has(bad, "Q_POLICY_INVALID"));
    CHECK_EQ(V(bad), std::string("confirm"));
}

// ---- A fixes ----

TEST(StrictGate, NumbersOverOpenColumnsAreOpen) {
    CHECK_EQ(V(C(kCode + "Результат = СтрДлина(Р.Порядок) + Р.Порядок + 1;")), std::string("safe"));
    CHECK_EQ(V(C(kCode + "Результат = Р.Порядок + 1;")), std::string("safe"));
    CHECK_EQ(V(C(kCode + "Результат = Строка(Р.Порядок);")), std::string("safe"));
    // a cell joined with an object on two paths is not a cell
    CHECK_EQ(V(C(kCode + "Если Р.Порядок = 1 Тогда Х = Р.Порядок; Иначе Х = Т; КонецЕсли; Результат = Х;")),
             std::string("confirm"));
}

TEST(StrictGate, MetadataMembersAndIteration) {
    CHECK_EQ(V(C("Результат = 0; Для Каждого Р Из Метаданные.РегистрыСведений.Правила.Измерения Цикл "
                 "Если СтрНайти(НРег(Р.Имя), \"rmq\") > 0 Тогда Результат = Результат + 1; КонецЕсли; КонецЦикла;")),
             std::string("safe"));
    CHECK_EQ(V(C("Мет = Метаданные.РегистрыСведений.Правила; "
                 "Результат = Мет.Измерения.Количество() * 100 + Мет.Ресурсы.Количество();")), std::string("safe"));
}

TEST(StrictGate, TypeOfIsNotAnOracle) {
    CHECK_EQ(V(C(kCode + "Если ТипЗнч(Р.Имя) = Тип(\"Строка\") Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;")),
             std::string("safe"));
    CHECK_EQ(V(Q("ВЫБРАТЬ ТИПЗНАЧЕНИЯ(К.Наименование) = ТИП(Строка) КАК Т ИЗ Справочник.Контрагенты КАК К")),
             std::string("safe"));
}

TEST(StrictGate, OrderingByReferencePasses) {
    CHECK_EQ(V(Q("ВЫБРАТЬ К.Группа КАК Г ИЗ Справочник.Контрагенты КАК К УПОРЯДОЧИТЬ ПО К.Группа")), std::string("safe"));
    CHECK_EQ(V(Q("ВЫБРАТЬ ПЕРВЫЕ 5 К.Ссылка КАК С ИЗ Справочник.Контрагенты КАК К УПОРЯДОЧИТЬ ПО К.Ссылка")),
             std::string("safe"));
    CHECK(Has(Q("ВЫБРАТЬ К.Порядок КАК П ИЗ Справочник.Контрагенты КАК К УПОРЯДОЧИТЬ ПО К.Наименование"),
              "Q_ORDER_PROTECTED"));
}

TEST(StrictGate, EmptinessThroughCastToString) {
    const std::string head = "ВЫБРАТЬ ВЫБОР КОГДА ";
    const std::string tail = " ТОГДА 0 ИНАЧЕ 1 КОНЕЦ КАК Ф ИЗ РегистрСведений.Правила КАК П";
    CHECK_EQ(V(Q(head + "ВЫРАЗИТЬ(П.Текст КАК СТРОКА(100)) = \"\"" + tail)), std::string("safe"));
    CHECK_EQ(V(Q(head + "ВЫРАЗИТЬ(П.Текст КАК СТРОКА) <> \"\"" + tail)), std::string("safe"));
    // a piece of the value cast to a string is not an emptiness test
    CHECK_EQ(V(Q(head + "ВЫРАЗИТЬ(ПОДСТРОКА(П.Текст, 2, 1) КАК СТРОКА(100)) = \"\"" + tail)), std::string("confirm"));
    // a cast to a number is not one either
    CHECK_EQ(V(Q(head + "ВЫРАЗИТЬ(П.Текст КАК ЧИСЛО(10)) = 0" + tail)), std::string("confirm"));
}

TEST(StrictGate, KeywordAliasesStayRefused) {
    for (const char* alias : {"Есть", "И", "Истина"}) {
        CHECK(Has(Q(std::string("ВЫБРАТЬ К.Порядок КАК ") + alias + " ИЗ Справочник.Контрагенты КАК К"), "Q_PARSE_EXPECTED"));
    }
    CHECK(Has(C("И = 0; Результат = И;"), "C_PARSE"));
}
