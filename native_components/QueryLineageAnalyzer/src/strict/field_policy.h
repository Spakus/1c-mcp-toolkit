#pragma once
#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <vector>

// Field policy of the strict checker: which fields of which tables carry protected data, built by the host from
// metadata and passed in as JSON (version 1). The component never guesses:
//   - a table, field or parameter the policy does not name is "missing"/Unknown, never open;
//   - a malformed policy (bad JSON, wrong version, unknown class or origin, wrong value type) is an error, and the
//     caller treats it as a reason to ask for confirmation;
//   - names are matched case-insensitively (NormalizeIdentifierKey); two table or field names that collide after
//     normalization merge to the stricter class (Protected over Unknown over Open), so a duplicate can only tighten;
//     two parameter names that collide must carry the same origin, otherwise the policy is malformed (the host binds
//     one value to both, and no merged origin would describe it); for this rule only, names that differ in yo / ie
//     (U+0401 / U+0415 after normalization) collide too, the lookup still tells them apart;
//   - a parameter name must be spelled in the alphabet of a query parameter (IsIdentifierName of strict_tokenizer.h:
//     ASCII and Russian letters, '_', digits after the first character), otherwise the policy is malformed.
// A missing "presentation" of a table means Protected. The field "Представление" always has the class of the
// table's presentation, whatever the "fields" map says. A tabular section is addressed as "<Table>.<Section>".
// A virtual table resolves its own "extra_fields" first, then the fields of its base table.
// Change tables: for every object or register table T of the policy (Справочник, Документ, ПланВидовХарактеристик,
// ПланСчетов, БизнесПроцесс, Задача, РегистрСведений, РегистрНакопления, РегистрБухгалтерии, Константа) the policy also
// knows "T.Изменения", the exchange-plan change-registration table, as a virtual table over T with the extra fields
// Узел (open, a reference to an exchange-plan node whose plan is not known: refs_known false) and НомерСообщения
// (open). Its other fields are T's (Ссылка, Регистратор, dimensions); a field T has but the change table lacks makes
// the platform fail the query, it never returns data. A host entry of that name wins.

namespace lineage::strict {

enum class FieldClass { Open, Protected, Unknown };
// ClientComputed (code checker only, never parsed from the policy): a client value the code computed (a loop counter,
// a concatenation, a function result). It is labelled like Client, but it is not a literal of the caller: compared with
// a protected field it is an equality oracle (a loop enumerates guesses), not a filter.
enum class ParamOrigin { Client, TokenProtected, TokenUnknown, Missing, ClientComputed };

struct FieldInfo {
    FieldClass cls = FieldClass::Unknown;
    std::vector<std::string> refs;   // target tables of a reference field (original spelling)
    // false: a reference whose targets the policy does not list (Узел of a change table); its presentation is not
    // known, so it is never read as a string or ordered by without confirmation.
    bool refs_known = true;
    // The field's "origin_id" when the host sent one; else "<Table>.<Field>" (a tabular section:
    // "<Table>.<Section>.<Field>") spelled as the host wrote the policy. The name an oracle reason reports and the key
    // "compare_allowed" is looked up by (CompareAllowed).
    std::string display;
    // The host lets the model compare this field in parts (ПОДОБНО, <, >, МЕЖДУ, string functions): oracle primitives
    // over it add no reason. The value stays protected for the output labelling. Colliding names merge to false.
    bool compare_allowed = false;
};

// Reserved tokens of "deny_effects" (whole strings): the code checker denies a class of calls, not a name.
enum class ReservedEffect { CommonModuleCall, TypedObjectWrite };

class FieldPolicy {
public:
    struct Parsed;   // defined below: it holds a FieldPolicy by value

    static Parsed FromJson(const std::string& json);

    bool HasTable(const std::string& table) const;
    // Not "FieldClass(...)": GCC rejects a member named like its type.
    FieldClass ClassOf(const std::string& table, const std::string& field) const;
    const FieldInfo* Field(const std::string& table, const std::string& field) const;
    FieldClass PresentationClass(const std::string& table) const;   // Unknown if the table is missing
    ParamOrigin OriginOfParam(const std::string& name) const;       // name without '&'
    std::string ResolveVirtualBase(const std::string& vt) const;    // "" if not virtual
    // Policy field named by its display name (FieldInfo::display, matched after normalization): the host allows oracle
    // primitives over it. False for a name the policy does not list.
    bool CompareAllowed(const std::string& display) const;

    // The effect names the host does not cover by the runtime sandbox ("deny_effects" of the policy: exact names, or
    // a prefix when the pattern ends with '*'): code that mentions one is denied, never confirmed. The key absent:
    // kDefaultDenyEffects (provisional); an empty array: nothing is denied.
    // An entry is a name, a prefix ("Name*"), or "Manager.Method" (the method part may end with '*'): the pair
    // `Manager . Method` in the code is denied, the manager with another method is not.
    std::vector<std::string> DenyEffects() const;
    // The reserved tokens "common_module_call" (a call of a method of a name the code never assigned) and
    // "typed_object_write" (Записать / Провести / Удалить / ... on a value that is not a known allowlist type) were
    // listed in "deny_effects". False when the key is absent.
    bool DeniesReserved(ReservedEffect effect) const;

    // Normalized keys of every name the policy lists (a dot segment of a table or virtual table, a field, an extra
    // field) that mixes Latin and Cyrillic letters: real configuration names, not look-alikes (mixed_script.h).
    std::set<std::string> MixedScriptNames() const;

    // Replaces every parameter origin (names normalized as in the JSON). Colliding names of different origins (yo /
    // ie variants included), and names outside the parameter alphabet, are false and change nothing, as in the JSON. The code checker uses it: a query built in client code knows only
    // the parameters the code sets.
    bool SetParams(const std::map<std::string, ParamOrigin>& params);
    // Gives the parameter `name` the origin `origin` if the policy does not name it. A name already present, or one
    // differing from it only in yo / ie, must carry the same origin: false otherwise (nothing changes), whichever of
    // the two origins is stricter. A name
    // outside the parameter alphabet is false too.
    bool AgreeParam(const std::string& name, ParamOrigin origin);

    struct TableData {
        FieldClass presentation = FieldClass::Protected;
        std::map<std::string, FieldInfo> fields;
    };
    struct VirtualData {
        std::string base;
        std::map<std::string, FieldInfo> extra_fields;
    };

private:
    friend class PolicyReader;

    std::map<std::string, TableData> tables_;
    std::map<std::string, VirtualData> virtuals_;
    std::map<std::string, ParamOrigin> params_;
    std::map<std::string, ParamOrigin> param_folds_;   // collision key (yo folded) -> the origin of its names
    std::map<std::string, bool> compare_allowed_;      // normalized display name -> allowed
    bool has_deny_effects_ = false;
    std::vector<std::string> deny_effects_;
    bool deny_common_module_call_ = false;
    bool deny_typed_object_write_ = false;
};

// Names of the effects denied when the policy has no "deny_effects" (background work runs in its own session and
// transaction, so the rollback of the sandbox does not reach it). Provisional until the platform check of the safe
// mode.
extern const char* const kDefaultDenyEffects[];
extern const size_t kDefaultDenyEffectsCount;

// The table the host must add for `table` to resolve: "<T>" for the change table "<T>.Изменения" (the host builds T,
// the policy derives the change table), `table` itself otherwise.
std::string TableToRequest(const std::string& table);

struct FieldPolicy::Parsed {
    bool ok = false;
    FieldPolicy policy;
    std::string error;   // fixed text without echoing policy content
};

}  // namespace lineage::strict
