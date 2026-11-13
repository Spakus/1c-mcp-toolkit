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

// kPolicy with "compare_allowed" on the given fields ("Таблица.Поле", or "Таблица|Секция|Поле" with the policy keys) and, when `deny` is not null, "deny_effects".
std::string Policy(const std::vector<std::string>& allowed = {}, const Json* deny = nullptr) {
    Json p = Json::parse(kPolicy);
    for (const std::string& f : allowed) {
        // "Таблица|Поле" or "Таблица|Секция|Поле" names the keys of the policy; "Таблица.Поле" splits at the last dot
        const size_t first = f.find('|');
        if (first != std::string::npos) {
            const size_t last = f.rfind('|');
            if (first == last) {
                p["tables"][f.substr(0, first)]["fields"][f.substr(first + 1)]["compare_allowed"] = true;
            } else {
                p["tables"][f.substr(0, first)]["tabular_sections"][f.substr(first + 1, last - first - 1)]["fields"]
                 [f.substr(last + 1)]["compare_allowed"] = true;
            }
            continue;
        }
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
    CHECK_EQ(V(C("ДлительныеОперации.Выполнить(Неопределено);")), std::string("deny"));
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
    // in code the fields are those of the code's queries (a superset), the op is the primitive
    const Json j = C(kCode + "Результат = СтрДлина(Р.Имя);");
    CHECK(Oracles(j) == (std::set<std::string>{"C_FUNC_OVER_PROTECTED/strfunc@" + name,
                                               "C_FUNC_OVER_PROTECTED/strfunc@" + inn}));
    // a parse refusal carries no field and no op
    const Json parse = Q("ВЫБРАТЬ ВЫБРАТЬ");
    CHECK(!parse["reasons"][0].contains("field"));
    CHECK(!parse["reasons"][0].contains("op"));
}

TEST(StrictGate, ApiIsTwo) {
    CHECK_EQ(Q("ВЫБРАТЬ 1 КАК А")["api"].get<int>(), 2);
    CHECK_EQ(C("Результат = 1;")["api"].get<int>(), 2);
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

TEST(StrictGate, CompareAllowedInCodeNeedsEveryProtectedSourceAllowed) {
    const std::vector<std::string> both{kNameField, kInnField};
    CHECK_EQ(V(C(kCode + "Результат = СтрДлина(Р.Имя);", Policy(both))), std::string("safe"));
    CHECK_EQ(V(C(kCode + "Если Лев(Р.Имя, 1) = \"А\" Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;", Policy(both))),
             std::string("safe"));
    CHECK_EQ(V(C(kCode + "Если Р.Имя > \"М\" Тогда Результат = 1; Иначе Результат = 0; КонецЕсли;", Policy(both))),
             std::string("safe"));
    // the code reads two protected columns, one is allowed: the code path attributes coarsely, so it is not enough
    CHECK_EQ(V(C(kCode + "Результат = СтрДлина(Р.Имя);", Policy({kNameField}))), std::string("confirm"));
    // the allowed comparison does not unprotect the value: a derived string leaving as Результат is still stopped
    const Json derived = C(kCode + "Результат = Лев(Р.Имя, 1);", Policy(both));
    CHECK_EQ(V(derived), std::string("confirm"));
    CHECK(!Has(derived, "C_FUNC_OVER_PROTECTED"));
}

TEST(StrictGate, CompareAllowedMustBeBoolean) {
    Json p = Json::parse(kPolicy);
    p["tables"]["Справочник.Контрагенты"]["fields"]["ИНН"]["compare_allowed"] = "yes";
    const Json bad = Q(kWhere + "К.ИНН = \"1\"", p.dump());
    CHECK(Has(bad, "Q_POLICY_INVALID"));
    CHECK_EQ(V(bad), std::string("confirm"));
}

// ---- deny_effects ----

TEST(StrictGate, DeniedEffectsAreDeniedNotConfirmed) {
    CHECK_EQ(V(C("ФоновыеЗадания.Выполнить(\"Х\");")), std::string("deny"));          // the default list
    CHECK(Has(C("ФоновыеЗадания.Выполнить(\"Х\");"), "C_EFFECT_DENIED"));
    CHECK_EQ(V(C("Результат = BackgroundJobs.GetBackgroundJobs();")), std::string("deny"));
    CHECK_EQ(V(C("Выполнить(\"ФоновыеЗадания.Выполнить()\");")), std::string("deny"));   // executed text is searched
    CHECK_EQ(V(C("Выполнить(\"Фоновые\" + \"Задания.Выполнить()\");")), std::string("deny"));
    CHECK_EQ(V(C("Результат = \"ФоновыеЗадания\";")), std::string("safe"));            // an ordinary string is just a string
    // the host's list replaces the default: a prefix, an empty list
    const Json prefix = Json::array({"Пользовател*"});
    CHECK_EQ(V(C("Результат = Пользователи1;", Policy({}, &prefix))), std::string("deny"));
    CHECK_EQ(V(C("ФоновыеЗадания.Выполнить(\"Х\");", Policy({}, &prefix))) == "deny", false);
    const Json none = Json::array();
    CHECK_EQ(V(C("ФоновыеЗадания.Выполнить(\"Х\");", Policy({}, &none))), std::string("confirm"));
    // a deny list that is not an array of names is a malformed policy
    const Json bad = Json::array({"не имя"});
    CHECK(Has(C("Результат = 1;", Policy({}, &bad)), "C_POLICY_INVALID"));
}

TEST(StrictGate, RisksAreShownButDoNotDecide) {
    const Json j = C("Записать = 1; Результат = Записать;");
    CHECK_EQ(V(j), std::string("safe"));
    bool shown = false;
    for (const Json& r : j["risks"]) shown = shown || r["code"].get<std::string>() == "R_WRITE";
    CHECK(shown);
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

// ---- D: pure read platform functions ----

TEST(StrictGate, PureReadFunctionsAreAllowlisted) {
    CHECK_EQ(V(C("М = Новый Массив; Для Каждого Имя Из СтрРазделить(\"а,б\", \",\") Цикл М.Добавить(Имя); КонецЦикла; Результат = М;")),
             std::string("safe"));
    CHECK_EQ(V(C("Результат = Pow(2, 3) + СтрСравнить(\"a\", \"b\");")), std::string("safe"));
    CHECK_EQ(V(C("Р = Справочники.Контрагенты.НайтиПоКоду(\"1\"); Результат = Р.Пустая();")), std::string("safe"));
    // over protected data they are string functions, like Найти and Сред
    CHECK_EQ(V(C(kCode + "М = Новый Массив; Для Каждого Ч Из СтрРазделить(Р.Имя, \",\") Цикл М.Добавить(СтрДлина(Ч)); "
                         "КонецЦикла; Результат = М;")), std::string("confirm"));
    CHECK_EQ(V(C(kCode + "Результат = СтрСравнить(Р.Имя, \"М\");")), std::string("confirm"));
    // not allowlisted: a prefix search is possible
    CHECK(Has(C("Результат = Справочники.Контрагенты.НайтиПоНаименованию(\"А\");"), "C_UNKNOWN_METHOD"));
    // an equality lookup by a protected value is an oracle between protected values
    CHECK_EQ(V(C(kCode + "Результат = Справочники.Контрагенты.НайтиПоКоду(Р.Имя);")), std::string("confirm"));
}

// ---- F: valid 1C only ----

TEST(StrictGate, OmittedArgumentsRoundTrip) {
    const Json j = C("Результат = Дата(2020, 1, 1, , , );");
    CHECK_EQ(V(j), std::string("safe"));
    CHECK(j["canonical"].get<std::string>().find("Дата(2020, 1, 1, , , )") != std::string::npos);
}

TEST(StrictGate, MixedScriptNamesTheTextDefinesItself) {
    CHECK_EQ(V(C("Рq = 1; Результат = Рq;")), std::string("safe"));
    CHECK_EQ(V(Q("ВЫБРАТЬ К.Порядок КАК RMQЖивых ИЗ Справочник.Контрагенты КАК К")), std::string("safe"));
    // a name the text does not define stays refused
    CHECK(Has(C("Результат = Рq;"), "C_PARSE"));
    CHECK(Has(Q("ВЫБРАТЬ Кoнтрагенты.Порядок КАК Х ИЗ Справочник.Контрагенты КАК К"), "Q_PARSE_MIXED_SCRIPT"));
    // a look-alike of another name of the same text stays refused: Latin "e" in the first Результат
    CHECK(Has(C("Рeзультат = 1; Результат = 2;"), "C_PARSE"));
    CHECK(Has(Q("ВЫБРАТЬ К.Порядок КАК Kонтрагенты ИЗ Справочник.Контрагенты КАК Контрагенты"),
              "Q_PARSE_MIXED_SCRIPT"));
}

TEST(StrictGate, KeywordAliasesStayRefused) {
    for (const char* alias : {"Есть", "И", "Истина"}) {
        CHECK(Has(Q(std::string("ВЫБРАТЬ К.Порядок КАК ") + alias + " ИЗ Справочник.Контрагенты КАК К"), "Q_PARSE_EXPECTED"));
    }
    CHECK(Has(C("И = 0; Результат = И;"), "C_PARSE"));
}

// ---- the field of a reason is the host's origin id ----

namespace {

// A policy with a tabular section, registers, a virtual table and a constant; `with_ids` adds the host's origin_id.
Json OriginPolicy(bool with_ids) {
    Json p = Json::parse(R"({
      "version": 1,
      "tables": {
        "Документ.Заказ": {"presentation": "protected",
          "fields": {"Номер": {"class": "protected"}},
          "tabular_sections": {"Товары": {"fields": {"Комментарий": {"class": "protected"}}}}},
        "РегистрБухгалтерии.Хозрасчетный": {"presentation": "open", "fields": {
          "СуммаДт": {"class": "protected"}, "Субконто1": {"class": "protected"}}},
        "РегистрСведений.Правила": {"presentation": "open", "fields": {"ИмяПравила": {"class": "protected"}}},
        "РегистрНакопления.Товары": {"presentation": "open", "fields": {"Количество": {"class": "protected"}}},
        "Константа.Префикс": {"presentation": "open", "fields": {"Значение": {"class": "protected"}}}
      },
      "virtual_tables": {"РегистрНакопления.Товары.Остатки": {"base": "РегистрНакопления.Товары",
        "extra_fields": {"КоличествоОстаток": {"class": "protected"}}}}
    })");
    if (!with_ids) return p;
    Json& t = p["tables"];
    t["Документ.Заказ"]["fields"]["Номер"]["origin_id"] = "Документ.Заказ.Номер";
    t["Документ.Заказ"]["tabular_sections"]["Товары"]["fields"]["Комментарий"]["origin_id"] =
        "Документ.Заказ.Товары.Комментарий";
    t["РегистрБухгалтерии.Хозрасчетный"]["fields"]["СуммаДт"]["origin_id"] = "РегистрБухгалтерии.Хозрасчетный.СуммаДт";
    t["РегистрБухгалтерии.Хозрасчетный"]["fields"]["Субконто1"]["origin_id"] = "РегистрБухгалтерии.Хозрасчетный.Субконто1";
    t["РегистрСведений.Правила"]["fields"]["ИмяПравила"]["origin_id"] = "РегистрСведений.Правила.ИмяПравила";
    t["РегистрНакопления.Товары"]["fields"]["Количество"]["origin_id"] = "РегистрНакопления.Товары.Количество";
    p["virtual_tables"]["РегистрНакопления.Товары.Остатки"]["extra_fields"]["КоличествоОстаток"]["origin_id"] =
        "РегистрНакопления.Товары.Количество";
    t["Константа.Префикс"]["fields"]["Значение"]["origin_id"] = "Константа.Префикс";
    return p;
}

std::string LikeOn(const std::string& table, const std::string& field) {
    return "ВЫБРАТЬ 1 КАК Х ИЗ " + table + " КАК Т ГДЕ Т." + field + " ПОДОБНО \"а%\"";
}

std::set<std::string> Fields(const Json& j) {
    std::set<std::string> out;
    for (const Json& r : j["reasons"]) {
        if (r.contains("field")) out.insert(r["field"].get<std::string>());
    }
    return out;
}

}  // namespace

TEST(StrictGate, ReasonFieldEchoesOriginId) {
    const std::string pol = OriginPolicy(true).dump();
    // a tabular section, an accounting register (Дт, Субконто), an information register dimension
    CHECK(Fields(Q(LikeOn("Документ.Заказ.Товары", "Комментарий"), pol)) ==
          (std::set<std::string>{"Документ.Заказ.Товары.Комментарий"}));
    CHECK(Fields(Q(LikeOn("РегистрБухгалтерии.Хозрасчетный", "СуммаДт"), pol)) ==
          (std::set<std::string>{"РегистрБухгалтерии.Хозрасчетный.СуммаДт"}));
    CHECK(Fields(Q(LikeOn("РегистрБухгалтерии.Хозрасчетный", "Субконто1"), pol)) ==
          (std::set<std::string>{"РегистрБухгалтерии.Хозрасчетный.Субконто1"}));
    CHECK(Fields(Q(LikeOn("РегистрСведений.Правила", "ИмяПравила"), pol)) ==
          (std::set<std::string>{"РегистрСведений.Правила.ИмяПравила"}));
    // the virtual table's extra field reports the base origin the host gave it
    CHECK(Fields(Q(LikeOn("РегистрНакопления.Товары.Остатки", "КоличествоОстаток"), pol)) ==
          (std::set<std::string>{"РегистрНакопления.Товары.Количество"}));
    // a constant
    CHECK(Fields(Q(LikeOn("Константа.Префикс", "Значение"), pol)) == (std::set<std::string>{"Константа.Префикс"}));
}

TEST(StrictGate, ReasonFieldKeepsPolicySpellingWithoutOriginId) {
    const std::string pol = OriginPolicy(false).dump();
    CHECK(Fields(Q(LikeOn("Документ.Заказ.Товары", "Комментарий"), pol)) ==
          (std::set<std::string>{"Документ.Заказ.Товары.Комментарий"}));
    CHECK(Fields(Q(LikeOn("РегистрБухгалтерии.Хозрасчетный", "СуммаДт"), pol)) ==
          (std::set<std::string>{"РегистрБухгалтерии.Хозрасчетный.СуммаДт"}));
    CHECK(Fields(Q(LikeOn("РегистрНакопления.Товары.Остатки", "КоличествоОстаток"), pol)) ==
          (std::set<std::string>{"РегистрНакопления.Товары.Остатки.КоличествоОстаток"}));
    CHECK(Fields(Q(LikeOn("Константа.Префикс", "Значение"), pol)) == (std::set<std::string>{"Константа.Префикс.Значение"}));
}

TEST(StrictGate, ReasonFieldIgnoresQueryCase) {
    const std::string pol = OriginPolicy(true).dump();
    CHECK(Fields(Q(LikeOn("документ.заказ.товары", "комментарий"), pol)) ==
          (std::set<std::string>{"Документ.Заказ.Товары.Комментарий"}));
}

TEST(StrictGate, CompareAllowedFollowsOriginId) {
    // allowed on a tabular key
    Json p = OriginPolicy(true);
    p["tables"]["Документ.Заказ"]["tabular_sections"]["Товары"]["fields"]["Комментарий"]["compare_allowed"] = true;
    CHECK_EQ(V(Q(LikeOn("Документ.Заказ.Товары", "Комментарий"), p.dump())), std::string("safe"));
    // the same through the helper: a key path of the policy
    CHECK_EQ(V(Q(kWhere + "К.Наименование ПОДОБНО \"а%\"", Policy({"Справочник.Контрагенты|Наименование"}))), std::string("safe"));
    // the virtual extra shares the base origin: both copies allowed opens it, one copy denied closes it (AND)
    Json v = OriginPolicy(true);
    v["tables"]["РегистрНакопления.Товары"]["fields"]["Количество"]["compare_allowed"] = true;
    v["virtual_tables"]["РегистрНакопления.Товары.Остатки"]["extra_fields"]["КоличествоОстаток"]["compare_allowed"] = true;
    CHECK_EQ(V(Q(LikeOn("РегистрНакопления.Товары.Остатки", "КоличествоОстаток"), v.dump())), std::string("safe"));
    Json m = v;
    m["virtual_tables"]["РегистрНакопления.Товары.Остатки"]["extra_fields"]["КоличествоОстаток"]["compare_allowed"] = false;
    CHECK_EQ(V(Q(LikeOn("РегистрНакопления.Товары", "Количество"), m.dump())), std::string("confirm"));
    // a Cyrillic/Latin mixed table key
    Json x = Json::parse(R"({"version": 1, "tables": {"Документ.Zаказ": {"presentation": "open", "fields": {
        "Номер": {"class": "protected", "compare_allowed": true, "origin_id": "Документ.Zаказ.Номер"}}}}})");
    CHECK_EQ(V(Q(LikeOn("Документ.Zаказ", "Номер"), x.dump())), std::string("safe"));
}

TEST(StrictGate, OriginIdOfWrongTypeIsPolicyShapeError) {
    for (const char* bad : {"5", "true", "null", "[\"а\"]", "{}"}) {
        Json p = OriginPolicy(false);
        p["tables"]["Документ.Заказ"]["fields"]["Номер"]["origin_id"] = Json::parse(bad);
        CHECK(Has(Q("ВЫБРАТЬ 1 КАК Х", p.dump()), "Q_POLICY_INVALID"));
        CHECK(Has(C("Результат = 1;", p.dump()), "C_POLICY_INVALID"));
    }
    // inside a tabular section too
    Json s = OriginPolicy(false);
    s["tables"]["Документ.Заказ"]["tabular_sections"]["Товары"]["fields"]["Комментарий"]["origin_id"] = 1;
    CHECK(Has(Q("ВЫБРАТЬ 1 КАК Х", s.dump()), "Q_POLICY_INVALID"));
}
