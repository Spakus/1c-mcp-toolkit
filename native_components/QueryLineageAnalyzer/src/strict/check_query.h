#pragma once
#include <string>

// Strict query check, the entry point behind the CheckQuery component method. Returns a JSON object:
//   {"api":1,"verdict":"safe|confirm|incomplete","reasons":[{"code","line","col","offset"}],
//    "canonical":"...","columns":[{"name","origin","direct"}],"missing_tables":[...]}
// "canonical" is empty unless the query parsed and printed; "incomplete" means the policy lacks tables
// (listed in "missing_tables") and the host should retry with them added. Reasons carry fixed codes and
// positions only; the only client text in the output is the canonical text, column names and table names.
// "incomplete" is never safe: retry with the missing tables, the retry's verdict decides.
// The BSL caller must execute the canonical text with Запрос.Выполнить() (not ВыполнитьПакет): only the last
// statement's result is labelled, so a non-final select without ПОМЕСТИТЬ, or a final УНИЧТОЖИТЬ, is Q_BATCH_RESULT.
// A malformed policy is Q_POLICY_INVALID / confirm. Never throws: an internal failure is Q_INTERNAL / confirm.
namespace lineage::strict {

std::string CheckQueryImpl(const std::string& query_utf8, const std::string& policy_json);

}  // namespace lineage::strict
