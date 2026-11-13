#pragma once
#include <set>
#include <string>

#include "utf_utils.h"

// Identifiers that mix Latin and Cyrillic letters are a homoglyph vector (a Latin "K" inside "Kонтрагенты" names a
// different object than the one the reader sees), so both strict parsers and both canonical printers refuse them.
// Two kinds of mixed names are real, not look-alikes, and pass:
//   - platform names spelled that way by 1C itself (ЗаписьJSON, HTTPСоединение, ...): kPlatformMixedNames;
//   - names the configuration really has, as the host's field policy lists them (a table such as
//     Справочник.сл_ТомаS3, a field such as ПравилаXMLКорреспондента). The check entry points install them for the
//     duration of one check with KnownMixedNamesScope; without a scope only the platform list passes.
// Matching is case-insensitive (NormalizeIdentifierKey) and exact: a name that differs from a listed one by a single
// substituted letter is still refused. Whether a passed name is allowed in its position is decided later by the
// allowlists (a platform type that is not allowlisted stays C_UNKNOWN_TYPE / R_*), never here.

namespace lineage {

// Latin letter and Cyrillic lead byte (0xD0 / 0xD1) in one name. Digits and '_' are neutral.
inline bool HasLatinAndCyrillic(const std::string& s) {
    bool latin = false;
    bool cyrillic = false;
    for (const char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) latin = true;
        else if (c == 0xD0 || c == 0xD1) cyrillic = true;
    }
    return latin && cyrillic;
}

inline constexpr const char* kPlatformMixedNames[] = {
    "ЕСТЬNULL",
    "ЗаписьJSON", "ЧтениеJSON", "ЗаписатьJSON", "ПрочитатьJSON", "ПараметрыЗаписиJSON", "ПараметрыЧтенияJSON",
    "ЗаписьXML", "ЧтениеXML", "ЗаписатьXML", "ПрочитатьXML", "ПараметрыЗаписиXML", "ПараметрыЧтенияXML",
    "XMLСтрока", "XMLЗначение", "XMLТип", "XMLТипЗнч", "СхемаXML", "ПостроительСхемXML",
    "ФабрикаXDTO", "СериализаторXDTO", "ОбъектXDTO", "ТипОбъектаXDTO", "ТипЗначенияXDTO", "ПакетXDTO",
    "ДокументDOM", "ПостроительDOM", "ЗаписьDOM", "ЗаписьFastInfoset", "ЧтениеFastInfoset", "ПреобразованиеXSL",
    "HTTPСоединение", "HTTPЗапрос", "HTTPОтвет", "HTTPСервисОтвет", "COMОбъект", "WSПрокси", "WSОпределения",
};

namespace detail {
inline thread_local const std::set<std::string>* g_known_mixed_names = nullptr;   // NormalizeIdentifierKey keys
}

// Installs the configuration's mixed names (normalized keys) for one check on this thread; restores on exit.
class KnownMixedNamesScope {
public:
    explicit KnownMixedNamesScope(const std::set<std::string>* keys) : saved_(detail::g_known_mixed_names) {
        detail::g_known_mixed_names = keys;
    }
    ~KnownMixedNamesScope() { detail::g_known_mixed_names = saved_; }
    KnownMixedNamesScope(const KnownMixedNamesScope&) = delete;
    KnownMixedNamesScope& operator=(const KnownMixedNamesScope&) = delete;

private:
    const std::set<std::string>* saved_;
};

inline bool IsPlatformMixedName(const std::string& s) {
    static const std::set<std::string> keys = [] {
        std::set<std::string> k;
        for (const char* n : kPlatformMixedNames) k.insert(NormalizeIdentifierKey(n));
        return k;
    }();
    return keys.count(NormalizeIdentifierKey(s)) != 0;
}

// True when `s` mixes scripts and is neither a platform name nor a configuration name of the current check.
inline bool IsRefusedMixedScript(const std::string& s) {
    if (!HasLatinAndCyrillic(s) || IsPlatformMixedName(s)) return false;
    const std::set<std::string>* known = detail::g_known_mixed_names;
    return known == nullptr || known->count(NormalizeIdentifierKey(s)) == 0;
}

// Characters that look alike across scripts: Latin capitals with their Cyrillic (including Ukrainian / Serbian) and
// Greek twins. A mixed-script identifier is refused by the parser, but the gate still has to show what it imitates.
struct Lookalike {
    wchar_t latin, cyrillic, greek;
};
inline constexpr Lookalike kLookalikes[] = {
    {L'A', 0x0410, 0x0391}, {L'B', 0x0412, 0x0392}, {L'C', 0x0421, 0},      {L'E', 0x0415, 0x0395},
    {L'H', 0x041D, 0x0397}, {L'K', 0x041A, 0x039A}, {L'M', 0x041C, 0x039C}, {L'O', 0x041E, 0x039F},
    {L'P', 0x0420, 0x03A1}, {L'T', 0x0422, 0x03A4}, {L'X', 0x0425, 0x03A7}, {L'Y', 0x0423, 0x03A5},
    {L'I', 0x0406, 0x0399}, {L'S', 0x0405, 0},      {L'J', 0x0408, 0},      {L'Z', 0, 0x0396},
    {L'N', 0, 0x039D},
};

// Greek twins always become Latin; then Latin <-> Cyrillic in the requested direction.
inline std::string FoldHomoglyphs(const std::string& key, bool to_cyrillic) {
    std::wstring units = Utf8ToUtf16Units(key);
    for (wchar_t& u : units) {
        for (const Lookalike& l : kLookalikes) {
            if (l.greek != 0 && u == l.greek) u = l.latin;
        }
        for (const Lookalike& l : kLookalikes) {
            if (l.cyrillic == 0) continue;
            if (to_cyrillic && u == l.latin) { u = l.cyrillic; break; }
            if (!to_cyrillic && u == l.cyrillic) { u = l.latin; break; }
        }
    }
    return Utf16UnitsToUtf8(units);
}


// A name a text defines itself (an alias, a variable) that looks like another name of the same text: some homoglyph
// folding makes the two equal while the spellings differ (`Рeзультат` with a Latin "e" next to `Результат`). `keys` are
// the NormalizeIdentifierKey keys of every identifier of the text. Such a name stays refused: the reader sees one
// name, the platform two.
inline bool LooksLikeAnother(const std::string& name, const std::set<std::string>& keys) {
    const std::string key = NormalizeIdentifierKey(name);
    const std::string cyr = NormalizeIdentifierKey(FoldHomoglyphs(key, true));
    const std::string lat = NormalizeIdentifierKey(FoldHomoglyphs(key, false));
    for (const std::string& other : keys) {
        if (other == key) continue;
        if (NormalizeIdentifierKey(FoldHomoglyphs(other, true)) == cyr ||
            NormalizeIdentifierKey(FoldHomoglyphs(other, false)) == lat) {
            return true;
        }
    }
    return false;
}

}  // namespace lineage
