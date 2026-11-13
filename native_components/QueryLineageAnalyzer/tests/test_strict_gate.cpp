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

TEST(StrictGate, KeywordAliasesStayRefused) {
    for (const char* alias : {"Есть", "И", "Истина"}) {
        CHECK(Has(Q(std::string("ВЫБРАТЬ К.Порядок КАК ") + alias + " ИЗ Справочник.Контрагенты КАК К"), "Q_PARSE_EXPECTED"));
    }
    CHECK(Has(C("И = 0; Результат = И;"), "C_PARSE"));
}
