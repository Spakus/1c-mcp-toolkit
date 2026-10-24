#pragma once
#include <cstddef>
#include <cstdint>

// Allowlist data of the strict BSL checker (plan Task 24). Data only: no logic, no lookups; bsl_types.cpp builds
// its tables from the arrays below. Default deny: a global function, a "Новый" type, a member or a method that is
// not listed here is a reason code and a confirmation, never a pass. Every name is given in Russian and in the
// English platform synonym; matching is case-insensitive and folds ё to е (AllowlistKey in bsl_types.h).
//
// A method is matched by the receiver's TRACKED type, never by name alone. Rules for the result type:
//   - a column of a query result is a Ref when the label step reports target tables, otherwise Unknown;
//   - the element of a collection (Array.Получить, Структура[...], Соответствие.Получить) is Unknown.
//
// Taint (consumed by Tasks 25/26, not by the type pass):
//   Propagate: the result carries the labels of the receiver and the arguments (values move, nothing is derived);
//   Open:      the arguments must be open or client data; over protected data the call needs confirmation
//              (C_FUNC_OVER_PROTECTED); the result is open;
//   Confirm:   always needs confirmation.
// Hand-off (Task 25): a Ref argument to Строка / Формат / Лев / ... reads its presentation from the database; it must be
// labelled as the target table's presentation class (protected unless the policy says open). The Open rows below apply
// only to non-reference arguments.
// Task 25 may refine individual rows (for example the one-bit results of ЗначениеЗаполнено and Количество).

namespace lineage::bsl {

enum class Ty : uint8_t {
    Unknown,          // nothing can be proven: no member, method or index is allowed on it
    Undefined,
    Null,
    Boolean,
    Number,
    String,
    Date,
    TypeValue,        // result of Тип / ТипЗнч
    Query,            // Запрос
    QueryResult,      // РезультатЗапроса
    Selection,        // ВыборкаИзРезультатаЗапроса
    ValueTable,       // ТаблицаЗначений
    TableRow,         // СтрокаТаблицыЗначений
    ColumnCollection, // КоллекцияКолонокТаблицыЗначений (the .Колонки property)
    Array,
    Structure,
    Map,
    ValueList,        // created, but no member is allowed on it
    Uuid,
    Ref,              // a reference value (a column that the label step reports as a reference)
    MetaObject        // result of Ref.Метаданные()
};

enum class Taint : uint8_t { Propagate, Open, Confirm };

// Constraint on the first argument of a method or function.
enum class ArgRule : uint8_t {
    Any,
    LiteralString   // must be a string literal (a name: query parameter, structure key, type name, column)
};

struct GlobalRule {
    const char* ru;
    const char* en;
    Ty result;
    Taint taint;
    int min_args;
    int max_args;
    ArgRule arg0;
};

struct NewRule {
    const char* ru;
    const char* en;
    Ty result;
    int min_args;
    int max_args;
};

struct MethodRule {
    Ty receiver;
    const char* ru;
    const char* en;
    Ty result;
    Taint taint;
    int min_args;
    int max_args;
    ArgRule arg0;
};

// A property read without a call (".Колонки"). Columns of a selection or a row are handled by the column set.
struct PropertyRule {
    Ty receiver;
    const char* ru;
    const char* en;
    Ty result;
};

// Writable property: only Запрос.Текст, handled by the checker (a constant-folded literal is required).
inline constexpr const char* kQueryTextRu = "Текст";
inline constexpr const char* kQueryTextEn = "Text";

// Out-parameter method: Структура.Свойство("Ключ", Переменная) assigns the second argument.
inline constexpr const char* kPropertyMethodRu = "Свойство";
inline constexpr const char* kPropertyMethodEn = "Property";

// Evaluation members: refused with C_EVAL on any receiver, whatever its type.
inline constexpr const char* kEvalMemberRu = "Вычислить";
inline constexpr const char* kEvalMemberEn = "Eval";

// Names that denote the execution context rather than a module: an unassigned use is C_UNKNOWN_IDENT, not
// C_COMMON_MODULE.
inline constexpr const char* kContextNames[] = {"ЭтотОбъект", "ЭтаФорма", "ThisObject", "ThisForm"};

inline constexpr GlobalRule kGlobalRules[] = {
    {"ЗначениеЗаполнено", "ValueIsFilled", Ty::Boolean, Taint::Propagate, 1, 1, ArgRule::Any},
    {"ТипЗнч", "TypeOf", Ty::TypeValue, Taint::Propagate, 1, 1, ArgRule::Any},
    {"Тип", "Type", Ty::TypeValue, Taint::Propagate, 1, 1, ArgRule::LiteralString},
    {"Строка", "String", Ty::String, Taint::Open, 1, 1, ArgRule::Any},
    {"Число", "Number", Ty::Number, Taint::Open, 1, 1, ArgRule::Any},
    {"Дата", "Date", Ty::Date, Taint::Open, 1, 6, ArgRule::Any},
    {"Формат", "Format", Ty::String, Taint::Open, 2, 2, ArgRule::Any},
    {"Мин", "Min", Ty::Unknown, Taint::Open, 1, 64, ArgRule::Any},
    {"Макс", "Max", Ty::Unknown, Taint::Open, 1, 64, ArgRule::Any},
    {"Окр", "Round", Ty::Number, Taint::Open, 1, 3, ArgRule::Any},
    {"Цел", "Int", Ty::Number, Taint::Open, 1, 1, ArgRule::Any},
    {"Лев", "Left", Ty::String, Taint::Open, 2, 2, ArgRule::Any},
    {"Прав", "Right", Ty::String, Taint::Open, 2, 2, ArgRule::Any},
    {"Сред", "Mid", Ty::String, Taint::Open, 2, 3, ArgRule::Any},
    {"СтрДлина", "StrLen", Ty::Number, Taint::Open, 1, 1, ArgRule::Any},
    {"ВРег", "Upper", Ty::String, Taint::Open, 1, 1, ArgRule::Any},
    {"НРег", "Lower", Ty::String, Taint::Open, 1, 1, ArgRule::Any},
    {"СокрЛП", "TrimAll", Ty::String, Taint::Open, 1, 1, ArgRule::Any},
    {"СтрЗаменить", "StrReplace", Ty::String, Taint::Open, 3, 3, ArgRule::Any},
    {"Найти", "Find", Ty::Number, Taint::Open, 2, 2, ArgRule::Any},
    {"КодСимвола", "CharCode", Ty::Number, Taint::Open, 1, 2, ArgRule::Any},
    {"Символ", "Char", Ty::String, Taint::Open, 1, 1, ArgRule::Any},
};

inline constexpr NewRule kNewRules[] = {
    {"Запрос", "Query", Ty::Query, 0, 1},
    {"Массив", "Array", Ty::Array, 0, 1},
    {"Структура", "Structure", Ty::Structure, 0, 64},
    {"Соответствие", "Map", Ty::Map, 0, 1},
    {"ТаблицаЗначений", "ValueTable", Ty::ValueTable, 0, 0},
    {"СписокЗначений", "ValueList", Ty::ValueList, 0, 0},
    {"УникальныйИдентификатор", "UUID", Ty::Uuid, 0, 1},
};

inline constexpr MethodRule kMethodRules[] = {
    {Ty::Query, "Выполнить", "Execute", Ty::QueryResult, Taint::Propagate, 0, 0, ArgRule::Any},
    {Ty::Query, "УстановитьПараметр", "SetParameter", Ty::Undefined, Taint::Propagate, 2, 2, ArgRule::LiteralString},

    {Ty::QueryResult, "Выбрать", "Select", Ty::Selection, Taint::Propagate, 0, 0, ArgRule::Any},
    {Ty::QueryResult, "Выгрузить", "Unload", Ty::ValueTable, Taint::Propagate, 0, 0, ArgRule::Any},
    {Ty::QueryResult, "Пустой", "IsEmpty", Ty::Boolean, Taint::Open, 0, 0, ArgRule::Any},

    {Ty::Selection, "Следующий", "Next", Ty::Boolean, Taint::Open, 0, 0, ArgRule::Any},
    {Ty::Selection, "Количество", "Count", Ty::Number, Taint::Open, 0, 0, ArgRule::Any},

    {Ty::ValueTable, "Количество", "Count", Ty::Number, Taint::Open, 0, 0, ArgRule::Any},
    {Ty::ValueTable, "ВыгрузитьКолонку", "UnloadColumn", Ty::Array, Taint::Propagate, 1, 1, ArgRule::LiteralString},
    {Ty::ColumnCollection, "Количество", "Count", Ty::Number, Taint::Open, 0, 0, ArgRule::Any},

    {Ty::Array, "Добавить", "Add", Ty::Undefined, Taint::Propagate, 1, 1, ArgRule::Any},
    {Ty::Array, "Количество", "Count", Ty::Number, Taint::Open, 0, 0, ArgRule::Any},
    {Ty::Array, "Получить", "Get", Ty::Unknown, Taint::Propagate, 1, 1, ArgRule::Any},

    {Ty::Structure, "Вставить", "Insert", Ty::Undefined, Taint::Propagate, 2, 2, ArgRule::Any},
    {Ty::Structure, "Свойство", "Property", Ty::Boolean, Taint::Propagate, 1, 2, ArgRule::LiteralString},
    {Ty::Structure, "Количество", "Count", Ty::Number, Taint::Open, 0, 0, ArgRule::Any},

    {Ty::Map, "Вставить", "Insert", Ty::Undefined, Taint::Propagate, 2, 2, ArgRule::Any},
    {Ty::Map, "Получить", "Get", Ty::Unknown, Taint::Propagate, 1, 2, ArgRule::Any},
    {Ty::Map, "Количество", "Count", Ty::Number, Taint::Open, 0, 0, ArgRule::Any},

    {Ty::Ref, "УникальныйИдентификатор", "UniqueIdentifier", Ty::Uuid, Taint::Open, 0, 0, ArgRule::Any},
    {Ty::Ref, "Пустая", "IsEmpty", Ty::Boolean, Taint::Open, 0, 0, ArgRule::Any},
    {Ty::Ref, "Метаданные", "Metadata", Ty::MetaObject, Taint::Open, 0, 0, ArgRule::Any},
    {Ty::MetaObject, "ПолноеИмя", "FullName", Ty::String, Taint::Open, 0, 0, ArgRule::Any},
};

inline constexpr PropertyRule kPropertyRules[] = {
    {Ty::ValueTable, "Колонки", "Columns", Ty::ColumnCollection},
};

}  // namespace lineage::bsl
