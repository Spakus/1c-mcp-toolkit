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
      "Наименование": {"class": "protected"}, "ИНН": {"class": "protected"}, "Код": {"class": "protected"},
      "Порядок": {"class": "open"}, "Группа": {"class": "open", "refs": ["Справочник.Группы"]}}},
    "Справочник.Группы": {"presentation": "open", "fields": {
      "Ссылка": {"class": "open", "refs": ["Справочник.Группы"]}, "Наименование": {"class": "open"}}},
    "Документ.Реализация": {"presentation": "protected", "fields": {
      "Ссылка": {"class": "open", "refs": ["Документ.Реализация"]}, "Номер": {"class": "open"},
      "Контрагент": {"class": "open", "refs": ["Справочник.Контрагенты"]}}},
    "РегистрНакопления.Взаиморасчеты": {"presentation": "protected", "fields": {
      "Контрагент": {"class": "open", "refs": ["Справочник.Контрагенты"]}, "Сумма": {"class": "open"}}},
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
    // the host's list is added to the default (see HostDenyListIsAddedToTheDefaultNeverReplacesIt)
    const Json prefix = Json::array({"Пользовател*"});
    CHECK_EQ(V(C("Результат = Пользователи1;", Policy({}, &prefix))), std::string("deny"));
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

// ---- deny_effects: qualified entries, reserved tokens, external processing ----

namespace {

std::string DenyOf(const std::vector<std::string>& names, const std::string& code) {
    const Json deny = names;
    return V(C(code, Policy({}, &deny)));
}

bool Rejected(const std::string& entry) {
    const Json deny = Json::array({entry});
    return Has(C("Результат = 1;", Policy({}, &deny)), "C_POLICY_INVALID");
}

}  // namespace

TEST(StrictGate, QualifiedDenyEntryMatchesTheManagerMethodPair) {
    const std::vector<std::string> save{"МенеджерНастроек.Сохранить"};
    CHECK_EQ(DenyOf(save, "МенеджерНастроек.Сохранить(\"а\", \"б\", 1);"), std::string("deny"));
    CHECK(Has(C("ХранилищеОбщихНастроек.Сохранить(\"а\", \"б\", 1);", Policy({}, nullptr)), "C_EFFECT_DENIED"));   // default list: any mention
    // the other method of the same manager is not denied by this entry
    const Json deny = Json(save);
    const Json load = C("Результат = МенеджерНастроек.Загрузить(\"а\", \"б\");", Policy({}, &deny));
    CHECK(V(load) != "deny");
    CHECK(!Has(load, "C_EFFECT_DENIED"));
    // case, yo and spaces around the dot are folded like a plain name
    CHECK_EQ(DenyOf(save, "менеджернастроек . сохранить(1);"), std::string("deny"));
    CHECK_EQ(DenyOf({"Менеджер.Счёт"}, "Менеджер.Счет(1);"), std::string("deny"));
    // a Latin look-alike letter inside the name is folded
    CHECK_EQ(DenyOf(save, "МенеджерНастр" "o" "ек.Сохранить(1);"), std::string("deny"));
    // the pair is matched wherever it stands in a chain, and as a property read too
    CHECK_EQ(DenyOf(save, "Результат = Х.МенеджерНастроек.Сохранить;"), std::string("deny"));
    // the English pair
    CHECK_EQ(DenyOf({"SettingsManager.Save"}, "SettingsManager.Save(\"a\", \"b\", 1);"), std::string("deny"));
    // a star on the method part is a prefix
    CHECK_EQ(DenyOf({"МенеджерНастроек.Сохран*"}, "МенеджерНастроек.Сохранить(1);"), std::string("deny"));
    CHECK(DenyOf({"МенеджерНастроек.Сохран*"}, "МенеджерНастроек.Загрузить(1);") != "deny");
    // the manager alone (carried under another name) is denied, the method alone is not the pair
    CHECK_EQ(DenyOf(save, "МенеджерНастроек = 1; Результат = МенеджерНастроек;"), std::string("deny"));
    CHECK(DenyOf(save, "Сохранить = 1; Результат = Сохранить;") != "deny");
    // an executed string is searched for the pair
    CHECK_EQ(DenyOf(save, "Выполнить(\"МенеджерНастроек.Сохранить(1)\");"), std::string("deny"));
    CHECK(DenyOf(save, "Выполнить(\"МенеджерНастроек.Загрузить(1)\");") != "deny");
}

TEST(StrictGate, QualifiedDenyEntryShapes) {
    CHECK(!Rejected("Менеджер.Метод"));
    CHECK(!Rejected("Менеджер.Метод*"));
    CHECK(Rejected("А.Б.В"));        // two dots
    CHECK(Rejected(".Метод"));
    CHECK(Rejected("Менеджер."));
    CHECK(Rejected("Менеджер.*"));   // nothing before the star
    CHECK(Rejected("Менеджер*.Метод"));
    CHECK(Rejected("*.Метод"));
    CHECK(Rejected("Менеджер. Метод"));
    CHECK(Rejected("Менеджер.Ме-тод"));
    CHECK(Rejected("."));
}

// The exact list the host builds in ЗапрещенныеДействияСтрогогоРежима (1C object module): every entry must pass the validator,
// otherwise the whole policy is malformed and every code check answers C_POLICY_INVALID.
namespace {

std::vector<std::string> HostDenyList() {
    return {
    "common_module_call", "typed_object_write", "УстановитьОтключениеБезопасногоРежима", "SetSafeModeDisabled",
    "УстановитьБезопасныйРежим", "SetSafeMode", "УстановитьБезопасныйРежимРазделенияДанных",
    "SetDataSeparationSafeMode", "УстановитьПривилегированныйРежим", "SetPrivilegedMode", "НачатьТранзакцию",
    "BeginTransaction", "ЗафиксироватьТранзакцию", "CommitTransaction", "ОтменитьТранзакцию", "RollbackTransaction",
    "ФоновыеЗадания", "BackgroundJobs", "РегламентныеЗадания", "ScheduledJobs", "ЗаписьЖурналаРегистрации",
    "WriteLogEvent", "УстановитьИспользованиеСобытияЖурналаРегистрации", "SetEventLogEventUse",
    "ОчиститьЖурналРегистрации", "ClearEventLog", "ПользователиИнформационнойБазы", "InfoBaseUsers",
    "УстановитьМонопольныйРежим", "SetExclusiveMode", "ВнешниеОбработки", "ExternalDataProcessors", "ВнешниеОтчеты",
    "ExternalReports", "ПодключитьВнешнююОбработку", "ДополнительныеОтчетыИОбработки",
    "ХранилищеОбщихНастроек.Сохранить", "ХранилищеОбщихНастроек.Save", "ХранилищеОбщихНастроек.Удалить",
    "ХранилищеОбщихНастроек.Delete", "CommonSettingsStorage.Сохранить", "CommonSettingsStorage.Save",
    "CommonSettingsStorage.Удалить", "CommonSettingsStorage.Delete", "ХранилищеСистемныхНастроек.Сохранить",
    "ХранилищеСистемныхНастроек.Save", "ХранилищеСистемныхНастроек.Удалить", "ХранилищеСистемныхНастроек.Delete",
    "SystemSettingsStorage.Сохранить", "SystemSettingsStorage.Save", "SystemSettingsStorage.Удалить",
    "SystemSettingsStorage.Delete", "ХранилищеПользовательскихНастроекОтчетов.Сохранить",
    "ХранилищеПользовательскихНастроекОтчетов.Save", "ХранилищеПользовательскихНастроекОтчетов.Удалить",
    "ХранилищеПользовательскихНастроекОтчетов.Delete", "ReportsUserSettingsStorage.Сохранить",
    "ReportsUserSettingsStorage.Save", "ReportsUserSettingsStorage.Удалить", "ReportsUserSettingsStorage.Delete",
    "ХранилищеПользовательскихНастроекДинамическихСписков.Сохранить",
    "ХранилищеПользовательскихНастроекДинамическихСписков.Save",
    "ХранилищеПользовательскихНастроекДинамическихСписков.Удалить",
    "ХранилищеПользовательскихНастроекДинамическихСписков.Delete", "DynamicListsUserSettingsStorage.Сохранить",
    "DynamicListsUserSettingsStorage.Save", "DynamicListsUserSettingsStorage.Удалить",
    "DynamicListsUserSettingsStorage.Delete", "ХранилищеНастроекДанныхФорм.Сохранить",
    "ХранилищеНастроекДанныхФорм.Save", "ХранилищеНастроекДанныхФорм.Удалить", "ХранилищеНастроекДанныхФорм.Delete",
    "FormDataSettingsStorage.Сохранить", "FormDataSettingsStorage.Save", "FormDataSettingsStorage.Удалить",
    "FormDataSettingsStorage.Delete",
    "COMОбъект", "COMObject", "HTTPСоединение", "HTTPConnection", "FTPСоединение", "FTPConnection", "ИнтернетПочта",
    "InternetMail", "WSПрокси", "WSProxy", "WSОпределения", "WSDefinitions", "ЗащищенноеСоединениеOpenSSL",
    "OpenSSLSecureConnection", "ЗапуститьПриложение", "RunApp", "НачатьЗапускПриложения", "BeginRunningApplication",
    "КомандаСистемы", "System", "ЗапуститьСистему", "RunSystem", "ПодключитьВнешнююКомпоненту", "AttachAddIn",
    "НачатьПодключениеВнешнейКомпоненты", "BeginAttachingAddIn", "ЗагрузитьВнешнююКомпоненту", "LoadAddIn",
    "УстановитьВнешнююКомпоненту", "InstallAddIn"};
}

}  // namespace

TEST(StrictGate, HostDenyListIsAcceptedByThePolicyValidator) {
    const Json deny = HostDenyList();
    CHECK(!Has(C("Результат = 1;", Policy({}, &deny)), "C_POLICY_INVALID"));
    CHECK_EQ(DenyOf(deny.get<std::vector<std::string>>(), "Результат = 1;"), std::string("safe"));
    CHECK_EQ(DenyOf(deny.get<std::vector<std::string>>(), "ХранилищеОбщихНастроек.Сохранить(\"а\", \"б\", 1);"),
             std::string("deny"));
    CHECK_EQ(DenyOf(deny.get<std::vector<std::string>>(), "ПодключитьВнешнююОбработку(\"а\");"), std::string("deny"));
    const std::vector<std::string> list = deny.get<std::vector<std::string>>();
    CHECK_EQ(DenyOf(list, "О = Новый COMОбъект(\"Scripting.FileSystemObject\"); Результат = 1;"), std::string("deny"));
    CHECK_EQ(DenyOf(list, "С = Новый HTTPСоединение(\"127.0.0.1\", 9); Результат = 1;"), std::string("deny"));
    CHECK_EQ(DenyOf(list, "ЗапуститьПриложение(\"cmd.exe /c exit\"); Результат = 1;"), std::string("deny"));
    CHECK_EQ(DenyOf(list, "Результат = 1;"), std::string("safe"));
}

TEST(StrictGate, HostPolicyShapeKeepsSelfCallsAndSessionWritesOutOfSafe) {
    const std::vector<std::string> list = HostDenyList();
    const std::vector<std::string> unsafe{
        "ЭтотОбъект.ВыполнитьКомандуНаСервере(\"execute_code\", 1);", "ThisObject.ВыполнитьКомандуНаСервере(1);",
        "ПараметрыСеанса.Х = 1; Результат = 1;"};
    for (const std::string& code : unsafe) CHECK(DenyOf(list, code) != "safe");
    // transactions are named in the list: unbalanced commit then begin (the count is restored) is denied
    CHECK_EQ(DenyOf(list, "ЗафиксироватьТранзакцию(); НачатьТранзакцию(); Результат = 1;"), std::string("deny"));
}

TEST(StrictGate, PlainDenyEntryDeniesAnyMentionIncludingALocalVariable) {
    const std::vector<std::string> plain{"Пользователи1"};
    CHECK_EQ(DenyOf(plain, "Пользователи1 = 1; Результат = Пользователи1;"), std::string("deny"));
    CHECK_EQ(C("ФоновыеЗадания = 1; Результат = ФоновыеЗадания;").at("verdict").get<std::string>(), std::string("deny"));
}

TEST(StrictGate, ReservedCommonModuleCallToken) {
    const std::string call = "Результат = МойМодуль.Функция(1);";
    const Json with_token = Json::array({"common_module_call"});
    const Json other = C(call, Policy({}, &with_token));
    CHECK_EQ(V(other), std::string("deny"));
    CHECK(Has(other, "C_EFFECT_DENIED"));
    CHECK(!Has(other, "C_COMMON_MODULE"));
    // a context name is not a module call
    CHECK(V(C("Результат = ЭтотОбъект.Функция(1);", Policy({}, &with_token))) != "deny");
    // without the token, or with the key absent, the module call is a window, as before
    const Json without = Json::array({"ФоновыеЗадания"});
    const Json plain = C(call, Policy({}, &without));
    CHECK_EQ(V(plain), std::string("confirm"));
    CHECK(Has(plain, "C_COMMON_MODULE"));
    CHECK_EQ(V(C(call)), std::string("confirm"));
    // only the whole string is the token: a variable of that name is just a variable
    CHECK_EQ(V(C("common_module_call = 1; Результат = common_module_call;", Policy({}, &with_token))), std::string("safe"));
}

TEST(StrictGate, ReservedTypedObjectWriteToken) {
    const Json token = Json::array({"typed_object_write"});
    const std::string head = "Объект = Справочники.Контрагенты.СоздатьЭлемент(); ";
    for (const char* method : {"Записать", "Write", "Провести", "Post", "Удалить", "Delete", "УстановитьПометкуУдаления",
                               "SetDeletionMark", "ОтменитьПроведение", "UndoPosting", "записать", "ПРОВЕСТИ"}) {
        const Json j = C(head + "Объект." + method + "();", Policy({}, &token));
        CHECK_EQ(V(j), std::string("deny"));
        CHECK(Has(j, "C_EFFECT_DENIED"));
    }
    // without the token nothing changes
    const Json none = Json::array();
    CHECK_EQ(V(C(head + "Объект.Записать();", Policy({}, &none))), std::string("confirm"));
    CHECK_EQ(V(C(head + "Объект.Записать();")), std::string("confirm"));
    // a known type is not an object: Array.Удалить is not denied by the token (it stays a window as an unknown method)
    for (const char* known : {"Новый Массив", "Новый Соответствие", "Новый Структура", "Новый СписокЗначений",
                              "Новый ТаблицаЗначений"}) {
        const Json j = C(std::string("М = ") + known + "; М.Удалить(0); Результат = 1;", Policy({}, &token));
        CHECK(V(j) != "deny");
        CHECK(!Has(j, "C_EFFECT_DENIED"));
    }
    // another method on an unknown receiver is not a write
    CHECK(V(C(head + "Результат = Объект.Количество();", Policy({}, &token))) != "deny");
    // the token as an identifier is not the token
    CHECK_EQ(V(C("typed_object_write = 1; Результат = typed_object_write;", Policy({}, &token))), std::string("safe"));
}

TEST(StrictGate, ExternalProcessingIsDeniedByDefault) {
    CHECK_EQ(V(C("ВнешниеОбработки.Создать(\"x\", Ложь);")), std::string("deny"));
    CHECK_EQ(V(C("ExternalDataProcessors.Create(\"x\", False);")), std::string("deny"));
    CHECK_EQ(V(C("Выполнить(\"ВнешниеОтчеты.Создать(1)\");")), std::string("deny"));
    CHECK_EQ(V(C("ExternalReports.Create(1);")), std::string("deny"));
    CHECK_EQ(V(C("ПодключитьВнешнююОбработку(\"x\");")), std::string("deny"));
    CHECK_EQ(V(C("ДополнительныеОтчетыИОбработки.СоздатьВнешнююОбработку(1);")), std::string("deny"));
    CHECK_EQ(V(C("ВнешниеОбработки = 1; Результат = ВнешниеОбработки;")), std::string("deny"));   // a variable too
}

TEST(StrictGate, FullHostDenyListParsesAndIsSafeForPlainCode) {
    const Json deny = Json::parse(R"([
      "УстановитьОтключениеБезопасногоРежима","SetSafeModeDisabled","УстановитьБезопасныйРежим","SetSafeMode",
      "УстановитьБезопасныйРежимРазделенияДанных","SetDataSeparationSafeMode",
      "УстановитьПривилегированныйРежим","SetPrivilegedMode","НачатьТранзакцию","BeginTransaction",
      "ЗафиксироватьТранзакцию","CommitTransaction","ОтменитьТранзакцию","RollbackTransaction",
      "ФоновыеЗадания","BackgroundJobs","РегламентныеЗадания","ScheduledJobs","ЗаписьЖурналаРегистрации","WriteLogEvent",
      "УстановитьИспользованиеСобытияЖурналаРегистрации","SetEventLogEventUse","ОчиститьЖурналРегистрации","ClearEventLog",
      "ПользователиИнформационнойБазы","InfoBaseUsers","УстановитьМонопольныйРежим","SetExclusiveMode",
      "ХранилищеОбщихНастроек.Сохранить","CommonSettingsStorage.Save",
      "ХранилищеОбщихНастроек.Удалить","CommonSettingsStorage.Delete",
      "ХранилищеСистемныхНастроек.Сохранить","SystemSettingsStorage.Save",
      "ХранилищеСистемныхНастроек.Удалить","SystemSettingsStorage.Delete",
      "ВнешниеОбработки","ExternalDataProcessors","ВнешниеОтчеты","ExternalReports",
      "common_module_call","typed_object_write"])");
    const std::string pol = Policy({}, &deny);
    const Json safe = C("Результат = 1;", pol);
    CHECK(!Has(safe, "C_POLICY_INVALID"));
    CHECK_EQ(V(safe), std::string("safe"));
    CHECK_EQ(V(C("ХранилищеСистемныхНастроек.Удалить(1);", pol)), std::string("deny"));
    CHECK_EQ(V(C("SystemSettingsStorage.Save(1);", pol)), std::string("deny"));
    CHECK_EQ(V(C("ВнешниеОбработки.Создать(\"x\");", pol)), std::string("deny"));
}

// ---- computed values reaching a protected field by equality are an oracle ----

namespace {

const std::string kParamHead =
    "З = Новый Запрос(\"ВЫБРАТЬ К.Ссылка КАК С ИЗ Справочник.Контрагенты КАК К ГДЕ К.Код = &Код\");\n";

std::string EqOracle(const char* field) { return std::string("C_FUNC_OVER_PROTECTED/eq@") + field; }
std::string QEqOracle(const char* field) { return std::string("Q_EQ_CLIENT_PARAM/eq@") + field; }

}  // namespace

TEST(StrictGate, ComputedQueryParameterBindingIsAnEqualityOracle) {
    const std::string loop =
        "Р = Новый Массив;\nДля Н = 1 По 100 Цикл\n    З.УстановитьПараметр(\"Код\", Формат(Н, \"ЧГ=\"));\n"
        "    Если Не З.Выполнить().Пустой() Тогда Р.Добавить(Н); КонецЕсли;\nКонецЦикла;\nРезультат = Р;\n";
    const Json j = C(kParamHead + loop);
    CHECK_EQ(V(j), std::string("confirm"));
    CHECK(Oracles(j).count(QEqOracle("Справочник.Контрагенты.Код")) == 1);
    // a concatenation with a loop counter
    CHECK_EQ(V(C(kParamHead + "Для Н = 1 По 9 Цикл З.УстановитьПараметр(\"Код\", \"А\" + Строка(Н)); "
                              "Результат = З.Выполнить().Пустой(); КонецЦикла;")), std::string("confirm"));
    // a list built in a loop
    const std::string list =
        "М = Новый Массив;\nДля Ит = 1 По 100 Цикл М.Добавить(Формат(Ит, \"ЧГ=\")); КонецЦикла;\n"
        "З = Новый Запрос(\"ВЫБРАТЬ К.Ссылка ИЗ Справочник.Контрагенты КАК К ГДЕ К.Наименование В (&Список)\");\n"
        "З.УстановитьПараметр(\"Список\", М);\nРезультат = З.Выполнить().Выгрузить().Количество();\n";
    const Json l = C(list);
    CHECK_EQ(V(l), std::string("confirm"));
    CHECK(Oracles(l).count(QEqOracle(kNameField)) == 1);
    // a computed value joined with a literal on another path is still computed
    CHECK_EQ(V(C(kParamHead + "Если Истина Тогда З.УстановитьПараметр(\"Код\", Формат(1, \"ЧГ=\")); "
                              "Иначе З.УстановитьПараметр(\"Код\", \"1\"); КонецЕсли; Результат = З.Выполнить().Пустой();")),
             std::string("confirm"));
}

TEST(StrictGate, ConstantQueryParameterBindingStaysSafe) {
    CHECK_EQ(V(C(kParamHead + "З.УстановитьПараметр(\"Код\", \"0000123\"); Результат = З.Выполнить().Пустой();")),
             std::string("safe"));
    CHECK_EQ(V(C(kParamHead + "К = \"00\" + \"123\"; З.УстановитьПараметр(\"Код\", К); Результат = З.Выполнить().Пустой();")),
             std::string("safe"));
    // a literal inside a loop is one guess, not an enumeration
    CHECK_EQ(V(C(kParamHead + "Для Н = 1 По 3 Цикл З.УстановитьПараметр(\"Код\", \"7\"); КонецЦикла; "
                              "Результат = З.Выполнить().Пустой();")), std::string("safe"));
    // an array of literals
    CHECK_EQ(V(C("М = Новый Массив; М.Добавить(\"а\"); М.Добавить(\"б\");\n"
                 "З = Новый Запрос(\"ВЫБРАТЬ К.Ссылка ИЗ Справочник.Контрагенты КАК К ГДЕ К.Наименование В (&Список)\");\n"
                 "З.УстановитьПараметр(\"Список\", М); Результат = З.Выполнить().Пустой();")), std::string("safe"));
    // an identifier written as a literal is a literal
    CHECK_EQ(V(C("З = Новый Запрос(\"ВЫБРАТЬ К.Ссылка ИЗ Справочник.Контрагенты КАК К ГДЕ К.Код = &Код\");\n"
                 "З.УстановитьПараметр(\"Код\", Новый УникальныйИдентификатор(\"21fd4a09-90ac-11f1-9570-005056bcee09\"));\n"
                 "Результат = З.Выполнить().Пустой();")), std::string("safe"));
    // a client parameter of the request (query check): a value the caller wrote
    CHECK_EQ(V(Q(kWhere + "К.Код = &П")), std::string("safe"));
}

TEST(StrictGate, ComputedFindByCodeArgumentIsAnEqualityOracle) {
    const std::string loop =
        "Р = Новый Массив;\nДля Н = 1 По 100 Цикл\n"
        "    Если Не Справочники.Контрагенты.НайтиПоКоду(Формат(Н, \"ЧГ=\")).Пустая() Тогда Р.Добавить(Н); КонецЕсли;\n"
        "КонецЦикла;\nРезультат = Р;\n";
    const Json j = C(loop);
    CHECK_EQ(V(j), std::string("confirm"));
    CHECK(Oracles(j).count(EqOracle("Справочник.Контрагенты.Код")) == 1);
    CHECK_EQ(V(C("Результат = ЗначениеЗаполнено(Справочники.Контрагенты.НайтиПоКоду(Строка(5)));")), std::string("confirm"));
    // a literal, or a folded constant, stays safe
    CHECK_EQ(V(C("Результат = Справочники.Контрагенты.НайтиПоКоду(\"0000123\").Пустая();")), std::string("safe"));
    CHECK_EQ(V(C("Результат = Справочники.Контрагенты.НайтиПоКоду(\"00\" + \"123\").Пустая();")), std::string("safe"));
}

TEST(StrictGate, ComputedFindRowsFilterOverProtectedColumnIsAnEqualityOracle) {
    const std::string table =
        "З = Новый Запрос(\"ВЫБРАТЬ К.Наименование КАК Наим, К.ИНН КАК Инн, К.Порядок КАК Порядок "
        "ИЗ Справочник.Контрагенты КАК К\");\nТЗ = З.Выполнить().Выгрузить();\nР = Новый Массив;\n";
    const std::string loop = "Для Н = 1 По 100 Цикл Р.Добавить(ТЗ.НайтиСтроки(Новый Структура(\"%K%\", Строка(Н))).Количество()); "
                             "КонецЦикла;\nРезультат = Р;\n";
    for (const char* key : {"Наим", "Инн"}) {
        std::string code = table + loop;
        code.replace(code.find("%K%"), 3, key);
        const Json j = C(code);
        CHECK_EQ(V(j), std::string("confirm"));
        CHECK(Oracles(j).count(EqOracle(std::string(key) == "Инн" ? kInnField : kNameField)) == 1);
    }
    // a literal filter value, or a computed value over an open column, is fine
    CHECK_EQ(V(C(table + "Результат = ТЗ.НайтиСтроки(Новый Структура(\"Инн\", \"7700000000\")).Количество();")),
             std::string("safe"));
    CHECK_EQ(V(C(table + "Для Н = 1 По 5 Цикл Р.Добавить(ТЗ.НайтиСтроки(Новый Структура(\"Порядок\", Н)).Количество()); "
                         "КонецЦикла;\nРезультат = Р;")), std::string("safe"));
}

// ---- АВТОУПОРЯДОЧИВАНИЕ sorts a reference by its presentation ----

TEST(StrictGate, AutoorderByReferenceWithProtectedPresentationAsksSelectedOrNot) {
    for (const char* text : {
             "ВЫБРАТЬ ПЕРВЫЕ 1 Д.Номер КАК Н ИЗ Документ.Реализация КАК Д УПОРЯДОЧИТЬ ПО Д.Контрагент АВТОУПОРЯДОЧИВАНИЕ",
             "ВЫБРАТЬ Д.Номер КАК Н ИЗ Документ.Реализация КАК Д УПОРЯДОЧИТЬ ПО Д.Контрагент АВТОУПОРЯДОЧИВАНИЕ",
             "ВЫБРАТЬ ПЕРВЫЕ 1 В.Сумма КАК Н ИЗ РегистрНакопления.Взаиморасчеты КАК В УПОРЯДОЧИТЬ ПО В.Контрагент "
             "АВТОУПОРЯДОЧИВАНИЕ",
             "ВЫБРАТЬ Д.Контрагент КАК К, Д.Номер КАК Н ИЗ Документ.Реализация КАК Д УПОРЯДОЧИТЬ ПО К АВТОУПОРЯДОЧИВАНИЕ"}) {
        const Json j = Q(text);
        CHECK_EQ(V(j), std::string("confirm"));
        CHECK(Has(j, "Q_ORDER_PROTECTED"));
    }
    // a reference whose presentation is open sorts by it without a window
    CHECK_EQ(V(Q("ВЫБРАТЬ К.Порядок КАК П ИЗ Справочник.Контрагенты КАК К УПОРЯДОЧИТЬ ПО К.Группа АВТОУПОРЯДОЧИВАНИЕ")),
             std::string("safe"));
    // a plain ordering by a reference (no autoorder) stays open until the platform proves what it sorts by
    CHECK_EQ(V(Q("ВЫБРАТЬ ПЕРВЫЕ 1 Д.Номер КАК Н ИЗ Документ.Реализация КАК Д УПОРЯДОЧИТЬ ПО Д.Контрагент")),
             std::string("safe"));
    CHECK_EQ(V(Q("ВЫБРАТЬ Д.Номер КАК Н ИЗ Документ.Реализация КАК Д УПОРЯДОЧИТЬ ПО Д.Номер АВТОУПОРЯДОЧИВАНИЕ")),
             std::string("safe"));
}

// ---- computed code or type names are denied ----

TEST(StrictGate, ComputedExecutionTextIsDenied) {
    for (const char* code : {
             "Выполнить(\"Фон\" + СтрЗаменить(\"ZZ\", \"ZZ\", \"\") + \"овыеЗадания.Выполнить(1)\");",
             "Выполнить(Символ(1060) + \"оновыеЗадания.Выполнить(1)\");",
             "Новый(СтрЗаменить(\"ЗаписьХМL\", \"Х\", \"X\"));",
             "Вычислить(СтрЗаменить(\"Фон_овыеЗадания.Выполнить\", \"_\", \"\"));",
             "Выполнить(СтрЗаменить(\"ЗафиксироватьТранзакцию_()\", \"_\", \"\"));",
             "А = \"Фоновые\"; Б = \"Задания\"; Выполнить(А + Б + \".Выполнить(1)\");",
             "Х = Новый Массив; Результат = 1; Выполнить(Х[0]);"}) {
        const Json j = C(code);
        CHECK_EQ(V(j), std::string("deny"));
        CHECK(Has(j, "C_EFFECT_DENIED"));
    }
    // the host's own list does not switch the rule off
    const Json none = Json::array();
    CHECK_EQ(V(C("Выполнить(СтрЗаменить(\"а\", \"а\", \"б\"));", Policy({}, &none))), std::string("deny"));
}

TEST(StrictGate, ConstantExecutionTextKeepsItsOwnVerdict) {
    // a literal, or literals joined: the text is checked as before (a window, or deny when it names a denied effect)
    CHECK_EQ(V(C("Выполнить(\"Результат = 1;\");")), std::string("confirm"));
    CHECK_EQ(V(C("Выполнить(\"Результат = \" + \"1;\");")), std::string("confirm"));
    CHECK_EQ(V(C("Вычислить(\"1 + 1\");")), std::string("confirm"));
    CHECK_EQ(V(C("Результат = Новый(\"Массив\");")), std::string("confirm"));
    CHECK_EQ(V(C("Выполнить(\"Фоновые\" + \"Задания.Выполнить(1)\");")), std::string("deny"));
    CHECK(!Has(C("Выполнить(\"Результат = 1;\");"), "C_EFFECT_DENIED"));
}

// ---- the default deny list is complete and the host list adds to it ----

TEST(StrictGate, DefaultDenyListNamesEveryUncoveredEffect) {
    for (const char* name : {"НачатьТранзакцию", "BeginTransaction", "ЗафиксироватьТранзакцию", "CommitTransaction",
                             "ОтменитьТранзакцию", "RollbackTransaction", "ХранилищеПользовательскихНастроекОтчетов",
                             "ReportsUserSettingsStorage", "ХранилищеВариантовОтчетов", "ReportsVariantsStorage",
                             "ХранилищеПользовательскихНастроекДинамическихСписков", "DynamicListsUserSettingsStorage",
                             "Exit", "Terminate", "SetExclusiveMode", "ЗавершитьРаботуСистемы", "ПрекратитьРаботуСистемы",
                             "УстановитьПривилегированныйРежим", "SetPrivilegedMode", "УстановитьОтключениеБезопасногоРежима",
                             "SetSafeModeDisabled", "УстановитьБезопасныйРежим", "SetSafeMode"}) {
        const Json j = C(std::string("Х = ") + name + "(1);");
        CHECK_EQ(V(j), std::string("deny"));
        CHECK(Has(j, "C_EFFECT_DENIED"));
    }
    for (const char* storage : {"ХранилищеПользовательскихНастроекОтчетов", "ХранилищеВариантовОтчетов",
                                "ХранилищеПользовательскихНастроекДинамическихСписков"}) {
        CHECK_EQ(V(C(std::string(storage) + ".Сохранить(\"а\", \"б\", 1);")), std::string("deny"));
    }
}

TEST(StrictGate, HostDenyListIsAddedToTheDefaultNeverReplacesIt) {
    const Json reserved = Json::array({"common_module_call", "typed_object_write"});
    CHECK_EQ(V(C("ФоновыеЗадания.Выполнить(\"Х\");", Policy({}, &reserved))), std::string("deny"));
    const Json prefix = Json::array({"Пользовател*"});
    CHECK_EQ(V(C("Результат = Пользователи1;", Policy({}, &prefix))), std::string("deny"));
    CHECK_EQ(V(C("ФоновыеЗадания.Выполнить(\"Х\");", Policy({}, &prefix))), std::string("deny"));
    const Json none = Json::array();
    CHECK_EQ(V(C("ФоновыеЗадания.Выполнить(\"Х\");", Policy({}, &none))), std::string("deny"));
    CHECK_EQ(V(C("Результат = 1;", Policy({}, &none))), std::string("safe"));
}

// ---- a manager named by a qualified entry cannot be carried around under another name ----

TEST(StrictGate, QualifiedDenyEntryIsNotBypassedByAliasing) {
    const std::vector<std::string> entry{"МойМенеджер.Выполнить"};
    for (const char* code : {"М = МойМенеджер; М.Выполнить(1);",
                             "Х = Новый Массив; Х.Добавить(МойМенеджер); Результат = 1;",
                             "Результат = Тип(МойМенеджер);",
                             "(МойМенеджер).Выполнить(1);",
                             "Выполнить(\"М = МойМенеджер;\");"}) {
        CHECK_EQ(DenyOf(entry, code), std::string("deny"));
    }
    // the other method of the manager, called directly, is still allowed
    const Json deny = Json(entry);
    const Json other = C("Результат = МойМенеджер.Прочитать(1);", Policy({}, &deny));
    CHECK(!Has(other, "C_EFFECT_DENIED"));
    CHECK(V(other) != "deny");
    CHECK(DenyOf(entry, "Выполнить(\"МойМенеджер.Прочитать(1)\");") != "deny");
    // a star entry on the method part behaves the same
    CHECK_EQ(DenyOf({"МойМенеджер.Выпол*"}, "М = МойМенеджер; М.Выполнить(1);"), std::string("deny"));
    // another name that merely contains the manager's name is not the manager
    CHECK(DenyOf(entry, "МойМенеджерДва = 1; Результат = МойМенеджерДва;") != "deny");
}

// ---- a string function over a reference reads its presentation ----

TEST(StrictGate, StringFunctionOverReferenceTakesThePresentationLabel) {
    for (const char* text : {
             "ВЫБРАТЬ ДЛИНАСТРОКИ(Д.Контрагент) КАК Д ИЗ Документ.Реализация КАК Д",
             "ВЫБРАТЬ Д.Номер КАК Н ИЗ Документ.Реализация КАК Д ГДЕ ДЛИНАСТРОКИ(Д.Контрагент) > 3",
             "ВЫБРАТЬ ПОДСТРОКА(Д.Контрагент, 1, 1) КАК П ИЗ Документ.Реализация КАК Д"}) {
        const Json j = Q(text);
        CHECK_EQ(V(j), std::string("confirm"));
    }
    // a reference whose presentation is open, and a string function over an open string column
    CHECK_EQ(V(Q("ВЫБРАТЬ ДЛИНАСТРОКИ(К.Группа) КАК Д ИЗ Справочник.Контрагенты КАК К")), std::string("safe"));
    CHECK_EQ(V(Q("ВЫБРАТЬ ДЛИНАСТРОКИ(Г.Наименование) КАК Д ИЗ Справочник.Группы КАК Г")), std::string("safe"));
    CHECK_EQ(V(Q("ВЫБРАТЬ ПОДСТРОКА(Г.Наименование, 1, 2) КАК Д ИЗ Справочник.Группы КАК Г")), std::string("safe"));
}

// ---- a computed scalar is computed even when its variable may also hold a collection ----

TEST(StrictGate, ComputedScalarJoinedWithACollectionStaysComputed) {
    const std::string head =
        "З = Новый Запрос(\"ВЫБРАТЬ К.Ссылка ИЗ Справочник.Контрагенты КАК К ГДЕ К.Наименование = &П\");\n";
    const std::string tail = "З.УстановитьПараметр(\"П\", П);\nР = З.Выполнить().Выгрузить();\nКонецЦикла;\nРезультат = 1;\n";
    for (const char* collection : {"Новый Массив", "Новый Структура"}) {
        const Json j = C(head + "Для Сч = 1 По 100 Цикл\nП = Строка(Сч);\nЕсли Сч > 1000 Тогда П = " + collection +
                         "; КонецЕсли;\n" + tail);
        CHECK_EQ(V(j), std::string("confirm"));
        CHECK(Oracles(j).count(std::string("Q_EQ_CLIENT_PARAM/eq@") + kNameField) == 1);
    }
    const Json branches = C(head + "Для Сч = 1 По 100 Цикл\nЕсли Сч > 5 Тогда\nП = Новый Массив;\nП.Добавить(\"а\");\n"
                                   "Иначе\nП = Строка(Сч);\nКонецЕсли;\n" + tail);
    CHECK_EQ(V(branches), std::string("confirm"));
    CHECK(Oracles(branches).count(std::string("Q_EQ_CLIENT_PARAM/eq@") + kNameField) == 1);
    // НайтиПоКоду over such a variable
    const Json find = C("Для Сч = 1 По 100 Цикл\nК = Строка(Сч);\nЕсли Сч > 1000 Тогда К = Новый Массив; КонецЕсли;\n"
                        "Р = Справочники.Контрагенты.НайтиПоКоду(К);\nКонецЦикла;\nРезультат = 1;\n");
    CHECK_EQ(V(find), std::string("confirm"));
    CHECK(Oracles(find).count("C_FUNC_OVER_PROTECTED/eq@Справочник.Контрагенты.Код") == 1);
    // a literal scalar joined with a collection of literals is constant
    CHECK_EQ(V(C(head + "Для Сч = 1 По 3 Цикл\nП = \"а\";\nЕсли Сч > 1 Тогда П = Новый Массив; П.Добавить(\"б\"); КонецЕсли;\n" +
                 tail)), std::string("safe"));
}

// ---- qualified deny entries fold RU / EN spellings and the module named by a string ----

TEST(StrictGate, QualifiedDenyEntryFoldsRussianAndEnglishSpellings) {
    const std::vector<std::string> entry{"Документы.ЗаписатьВсё"};
    CHECK_EQ(DenyOf(entry, "Документы.ЗаписатьВсё();"), std::string("deny"));
    CHECK_EQ(DenyOf(entry, "Documents.ЗаписатьВсё();"), std::string("deny"));
    CHECK_EQ(DenyOf(entry, "Документы.WriteAll();"), std::string("deny"));
    CHECK_EQ(DenyOf(entry, "Documents.WriteAll();"), std::string("deny"));
    CHECK_EQ(DenyOf({"Documents.WriteAll"}, "Документы.ЗаписатьВсё();"), std::string("deny"));
    CHECK_EQ(DenyOf({"Справочники.Удалить"}, "Catalogs.Delete(1);"), std::string("deny"));
    CHECK_EQ(DenyOf({"Catalogs.Delete"}, "Справочники.Удалить(1);"), std::string("deny"));
    // another method of the same manager, in either language, is not the pair
    const Json deny = Json(entry);
    CHECK(V(C("Результат = Documents.FindByCode(\"1\");", Policy({}, &deny))) != "deny");
    CHECK(V(C("Результат = Документы.НайтиПоКоду(\"1\");", Policy({}, &deny))) != "deny");
    // an executed string
    CHECK_EQ(DenyOf(entry, "Выполнить(\"Documents.WriteAll()\");"), std::string("deny"));
}

TEST(StrictGate, QualifiedDenyEntryReadsAModuleNamedByAString) {
    const std::vector<std::string> entry{"ОбщегоНазначения.ЗаписатьОбъект"};
    CHECK_EQ(DenyOf(entry, "ПолучитьОбщийМодуль(\"ОбщегоНазначения\").ЗаписатьОбъект(1);"), std::string("deny"));
    CHECK_EQ(DenyOf(entry, "ОбщийМодуль(\"ОбщегоНазначения\").ЗаписатьОбъект(1);"), std::string("deny"));
    CHECK_EQ(DenyOf(entry, "GetCommonModule(\"общегоназначения\").ЗаписатьОбъект(1);"), std::string("deny"));
    // carried under a variable
    CHECK_EQ(DenyOf(entry, "М = ПолучитьОбщийМодуль(\"ОбщегоНазначения\"); М.ЗаписатьОбъект(1);"), std::string("deny"));
    // another method of the module, or another module
    const Json deny = Json(entry);
    CHECK(V(C("Результат = ПолучитьОбщийМодуль(\"ОбщегоНазначения\").Прочитать(1);", Policy({}, &deny))) != "deny");
    CHECK(V(C("Результат = ПолучитьОбщийМодуль(\"Другой\").ЗаписатьОбъект(1);", Policy({}, &deny))) != "deny");
}

TEST(StrictGate, SettingsStoragesCollectionAndSecureStorageAreDeniedByDefault) {
    for (const char* name : {"ХранилищаНастроек", "SettingsStorages", "БезопасноеХранилище", "SecureStorage"}) {
        const Json j = C(std::string("Результат = ") + name + ".Х;");
        CHECK_EQ(V(j), std::string("deny"));
        CHECK(Has(j, "C_EFFECT_DENIED"));
    }
    // session parameters are not on the list
    CHECK(V(C("Результат = ПараметрыСеанса.Х;")) != "deny");
}
