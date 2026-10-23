#pragma once
#include <stdexcept>
#include <string>
#include <utility>

#include "strict/field_policy.h"

// Test policies shared by the strict-checker suites. Task 18 adds kPolicyVTJson / kPolicyVT.

namespace lineage::strict {

inline const std::string kPolicyABJson = R"({
  "version": 1,
  "tables": {
    "Справочник.А": {
      "presentation": "protected",
      "fields": {
        "Имя": {"class": "protected"},
        "Ссылка": {"class": "open", "refs": ["Справочник.А"]},
        "Код": {"class": "protected"}
      }
    },
    "Справочник.Б": {
      "presentation": "protected",
      "fields": {
        "СсылкаНаА": {"class": "open", "refs": ["Справочник.А"]},
        "Сумма": {"class": "open"},
        "Код": {"class": "open"},
        "Ссылка": {"class": "open", "refs": ["Справочник.Б"]}
      }
    }
  },
  "params": {"П": "client", "МСПТокен1": "token_protected"}
})";

inline FieldPolicy ParsePolicyOrDie(const std::string& json) {
    FieldPolicy::Parsed p = FieldPolicy::FromJson(json);
    if (!p.ok) throw std::runtime_error("test policy is malformed: " + p.error);
    return std::move(p.policy);
}

inline const FieldPolicy kPolicyAB = ParsePolicyOrDie(kPolicyABJson);

}  // namespace lineage::strict
