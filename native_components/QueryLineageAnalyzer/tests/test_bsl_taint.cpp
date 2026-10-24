#include "test_framework.h"
#include "analysis_helpers.h"
#include "policy_fixture.h"

#include <memory>
#include <string>

using namespace lineage::bsl;
using namespace lineage::strict;

namespace {

// Stands in for the CheckQuery column labels (Task 25): every executed query yields columns С (a reference to
// Справочник.А) and И (a plain value).
TypeCheckOptions WithColumns() {
    TypeCheckOptions o;
    o.columns_for_query = [](const lineage::bsl::Expr*) {
        auto set = std::make_shared<ColumnSet>();
        ColumnInfo ref;
        ref.refs.push_back("Справочник.А");
        set->columns["С"] = ref;
        set->columns["И"] = ColumnInfo();
        return std::shared_ptr<const ColumnSet>(set);
    };
    return o;
}

void Dump(const std::string& code, const CodeAnalysis& r) {
    std::cout << "  refused: " << code << std::endl << "   ";
    for (const CodeReason& reason : r.reasons) {
        std::cout << " " << reason.code << "@" << reason.pos.line << ":" << reason.pos.col;
    }
    std::cout << std::endl;
}

bool Safe(const std::string& code, const TypeCheckOptions& o = TypeCheckOptions()) {
    const CodeAnalysis r = CheckCodeForTest(kPolicyAB, code, o);
    if (r.verdict != CodeVerdict::Safe) Dump(code, r);
    return r.verdict == CodeVerdict::Safe && r.reasons.empty();
}

bool Denied(const std::string& code, const char* reason, const TypeCheckOptions& o = TypeCheckOptions()) {
    const CodeAnalysis r = CheckCodeForTest(kPolicyAB, code, o);
    const bool ok = r.verdict == CodeVerdict::Confirm && HasCodeReason(r, reason);
    if (!ok) Dump(code, r);
    return ok;
}

const char* kQ = "З = Новый Запрос(\"ВЫБРАТЬ А.Ссылка КАК С, А.Имя КАК И ИЗ Справочник.А КАК А\");\n";

}  // namespace

TEST(BslTaint, UnknownIdentifiersAndReceivers) {
    CHECK(HasCodeReason(CheckCodeForTest(kPolicyAB, "Результат = ЭтотОбъект;"), "C_UNKNOWN_IDENT"));
    // The parser already refuses the reserved name, with its own code (the plan expected C_UNKNOWN_IDENT here).
    CHECK(HasCodeReason(CheckCodeForTest(kPolicyAB, "Результат = МСПЗначенияТокенов[0];"), "C_RESERVED"));
    CHECK(HasCodeReason(CheckCodeForTest(kPolicyAB, "Х = ПолучитьОбъект(); Результат = Х.Имя;"), "C_UNKNOWN_IDENT"));
    CHECK(HasCodeReason(CheckCodeForTest(kPolicyAB, "Результат = ОбщегоНазначения.Ч();"), "C_COMMON_MODULE"));
}

TEST(BslTaint, ContextObjectsAreNotModules) {
    CHECK(Denied("Результат = ЭтотОбъект.Метод();", "C_UNKNOWN_IDENT"));
    CHECK(!HasCodeReason(CheckCodeForTest(kPolicyAB, "Результат = ЭтаФорма.Метод();"), "C_COMMON_MODULE"));
    CHECK(Denied("ЭтотОбъект = 1; Результат = 1;", "C_UNKNOWN_IDENT"));
    CHECK(Denied("Результат = Код;", "C_UNKNOWN_IDENT"));
}

TEST(BslTaint, AcceptsLegitimateQueryFlow) {
    const std::string code = std::string(kQ) +
        "Т = З.Выполнить().Выгрузить();\n"
        "М = Новый Массив;\n"
        "Для Каждого Стр Из Т Цикл М.Добавить(Новый Структура(\"С, И\", Стр.С, Стр.И)); КонецЦикла;\n"
        "Результат = М;";
    CHECK(Safe(code, WithColumns()));
    const std::string sel = std::string(kQ) +
        "В = З.Выполнить().Выбрать(); М = Новый Массив;\n"
        "Пока В.Следующий() Цикл М.Добавить(В.И); КонецЦикла; Результат = М;";
    CHECK(Safe(sel, WithColumns()));
    CHECK(Safe("З = Новый Запрос; З.Текст = \"ВЫБРАТЬ 1\" + \" КАК А\"; З.УстановитьПараметр(\"П\", 1);\n"
               "Результат = З.Выполнить().Пустой();"));
}

TEST(BslTaint, ColumnsNeedKnownColumnSet) {
    // Without labels from the query check a column read is refused, not guessed.
    CHECK(Denied(std::string(kQ) + "В = З.Выполнить().Выбрать(); Результат = В.И;", "C_UNKNOWN_MEMBER"));
    CHECK(Denied(std::string(kQ) + "В = З.Выполнить().Выбрать(); Результат = В.Нет;", "C_UNKNOWN_MEMBER", WithColumns()));
    CHECK(Denied(std::string(kQ) + "Т = З.Выполнить().Выгрузить(); Результат = Т[0].Нет;", "C_UNKNOWN_MEMBER", WithColumns()));
    CHECK(Safe(std::string(kQ) + "Т = З.Выполнить().Выгрузить(); Результат = Т[0].И;", WithColumns()));
    CHECK(Safe(std::string(kQ) + "В = З.Выполнить().Выбрать(); Результат = В.и;", WithColumns()));
}

TEST(BslTaint, ReferenceMethodsOnlyOnReferenceColumns) {
    const std::string pre = std::string(kQ) + "Т = З.Выполнить().Выгрузить(); Р = Т[0];\n";
    CHECK(Safe(pre + "Результат = Р.С.УникальныйИдентификатор();", WithColumns()));
    CHECK(Safe(pre + "Результат = Р.С.Метаданные().ПолноеИмя();", WithColumns()));
    CHECK(Safe(pre + "Результат = Р.С.Пустая();", WithColumns()));
    CHECK(Denied(pre + "Результат = Р.И.УникальныйИдентификатор();", "C_UNKNOWN_RECEIVER", WithColumns()));
    CHECK(Denied(pre + "Результат = Р.С.ПолучитьОбъект();", "C_UNKNOWN_METHOD", WithColumns()));
    CHECK(Denied(pre + "Результат = Р.С.Метаданные().Имя();", "C_UNKNOWN_METHOD", WithColumns()));
}

TEST(BslTaint, MethodsOnUnknownAreDenied) {
    CHECK(Denied("М = Новый Массив; Х = М.Получить(0); Результат = Х.Метод();", "C_UNKNOWN_RECEIVER"));
    CHECK(Denied("С = Новый Структура(\"К\", 1); Х = С[\"К\"]; Результат = Х.Выполнить();", "C_UNKNOWN_RECEIVER"));
    CHECK(Denied("Результат = Неопределено.Метод();", "C_UNKNOWN_METHOD"));
    CHECK(Denied("Х = 1; Результат = Х.Метод();", "C_UNKNOWN_METHOD"));
    CHECK(Denied("Х = ПолучитьОбъект(); Результат = Х[0];", "C_UNKNOWN_RECEIVER"));
}

TEST(BslTaint, EvalAndHandlersAsMembersAreDenied) {
    CHECK(Denied("М = Новый Массив; Результат = М.Вычислить(\"1\");", "C_EVAL"));
    CHECK(Denied("М = Новый Массив; Результат = М.Eval(\"1\");", "C_EVAL"));
    CHECK(Denied("М = Новый Массив; М.Выполнить(); Результат = 1;", "C_UNKNOWN_METHOD"));
    CHECK(Denied("З = Новый Запрос; Результат = З.Вычислить(\"1\");", "C_EVAL"));
    CHECK(Denied("Х = ПолучитьОбъект(); Результат = Х.Вычислить(\"1\");", "C_EVAL"));
}

TEST(BslTaint, StringNamedCallbacksAndGlobalsAreDenied) {
    CHECK(Denied("О = Новый ОписаниеОповещения(\"Имя\", ЭтотОбъект); Результат = 1;", "C_UNKNOWN_TYPE"));
    CHECK(Denied("ПодключитьОбработчикОжидания(\"Имя\", 1); Результат = 1;", "C_UNKNOWN_IDENT"));
    CHECK(Denied("Результат = Новый HTTPСоединение(\"x\");", "C_PARSE"));
    CHECK(Denied("Результат = Новый ЧтениеТекста;", "C_UNKNOWN_TYPE"));
    CHECK(Denied("Результат = Справочники.А.НайтиПоКоду(\"1\");", "C_UNKNOWN_IDENT"));
}

TEST(BslTaint, NewTypeAllowlist) {
    for (const char* ok : {"Результат = Новый Массив;", "Результат = Новый Структура;", "Результат = Новый Соответствие;",
                           "Результат = Новый ТаблицаЗначений;", "Результат = Новый СписокЗначений;",
                           "Результат = Новый УникальныйИдентификатор;", "Результат = Новый Структура(\"А\", 1);"})
        CHECK(Safe(ok));
    CHECK(Denied("Результат = Новый Запрос(\"а\", \"б\");", "C_BAD_ARGS"));
}

TEST(BslTaint, YoIsEquivalentToYe) {
    // ё and е are one letter in allowlist keys and in variable names.
    CHECK(Safe("Х = Новый Массив; Х.добавить(1); Результат = Х.Количество();"));
    CHECK(Safe("Еж = Новый Массив; Результат = еж.Количество();"));
    CHECK(Denied("Ёж = Новый Массив; Результат = Еж.Количество();", "C_AMBIGUOUS_IDENT"));
}

TEST(BslTaint, ReassignmentAlongBranchesLosesTheType) {
    CHECK(Denied("Если Истина Тогда Х = Новый Массив; Иначе Х = Новый Структура; КонецЕсли; Х.Добавить(1); Результат = 1;",
                 "C_UNKNOWN_RECEIVER"));
    CHECK(Safe("Если Истина Тогда Х = Новый Массив; Иначе Х = Новый Массив; КонецЕсли; Х.Добавить(1); Результат = 1;"));
    // Assigned on one path only: may be a module variable on the other.
    CHECK(Denied("Если Истина Тогда Х = Новый Массив; КонецЕсли; Результат = Х.Количество();", "C_UNKNOWN_IDENT"));
    CHECK(Denied("Попытка Х = Новый Массив; Исключение Х = 1; КонецПопытки; Х.Добавить(1); Результат = 1;",
                 "C_UNKNOWN_RECEIVER"));
    CHECK(Denied("Х = Новый Массив; Попытка Х = Новый Структура; Исключение Х.Добавить(1); КонецПопытки; Результат = 1;",
                 "C_UNKNOWN_RECEIVER"));
}

TEST(BslTaint, LoopCarriedTypesAreUnknown) {
    // The first iteration sees a Запрос, the second the Массив from the first.
    CHECK(Denied("Х = Новый Запрос; Для Н = 1 По 3 Цикл Х.Выполнить(); Х = Новый Массив; КонецЦикла; Результат = 1;",
                 "C_UNKNOWN_RECEIVER"));
    CHECK(Denied("Х = Новый Массив; Пока Ложь Цикл Х = 1; КонецЦикла; Х.Добавить(1); Результат = 1;", "C_UNKNOWN_RECEIVER"));
    // Reassigned before use in the same iteration: fine.
    CHECK(Safe("Для Н = 1 По 3 Цикл Х = Новый Массив; Х.Добавить(Н); КонецЦикла; Результат = 1;"));
    // The loop variable after the loop may be unassigned (zero iterations).
    CHECK(Denied("Для Н = 1 По 3 Цикл КонецЦикла; Результат = Н;", "C_UNKNOWN_IDENT"));
    CHECK(Safe("М = Новый Массив; Для Каждого Э Из М Цикл Результат = 1; КонецЦикла;"));
}

TEST(BslTaint, ShortCircuitOutParameter) {
    CHECK(Safe("С = Новый Структура(\"К\", 1); Если С.Свойство(\"К\", Х) Тогда Результат = Х; Иначе Результат = 0; КонецЕсли;"));
    // Х set only if the left side is true: unassigned on the other path.
    CHECK(Denied("С = Новый Структура; Л = Истина; Если Л И С.Свойство(\"К\", Х) Тогда Результат = 1; КонецЕсли; Р = Х;",
                 "C_UNKNOWN_IDENT"));
    CHECK(Denied("С = Новый Структура; Если С.Свойство(\"К\", 5) Тогда Результат = 1; КонецЕсли;", "C_BAD_ARGS"));
}

TEST(BslTaint, QueryTextRules) {
    CHECK(Safe("З = Новый Запрос; З.Текст = \"ВЫБРАТЬ 1\"; Результат = 1;"));
    CHECK(Denied("Т = \"ВЫБРАТЬ 1\"; З = Новый Запрос; З.Текст = Т + \"\"; Результат = 1;", "C_DYNAMIC_QUERY"));
    CHECK(Denied("Т = \"ВЫБРАТЬ 1\"; З = Новый Запрос(Т); Результат = 1;", "C_DYNAMIC_QUERY"));
    CHECK(Denied("З = Новый Запрос; З.Параметры = 1; Результат = 1;", "C_UNKNOWN_MEMBER"));
    CHECK(Denied("З = Новый Запрос; Н = \"П\"; З.УстановитьПараметр(Н, 1); Результат = 1;", "C_DYNAMIC_PARAM"));
    CHECK(Denied("З = Новый Запрос; Результат = З.Текст;", "C_UNKNOWN_MEMBER"));
    const CodeAnalysis r = CheckCodeForTest(kPolicyAB,
        "З = Новый Запрос(\"ВЫБРАТЬ 1\"); З.Текст = \"ВЫБРАТЬ 2\" + \" \" + \"КАК А\"; Результат = 1;");
    CHECK_EQ(r.query_texts.size(), static_cast<size_t>(2));
    CHECK_EQ(r.query_texts[0].text, std::string("ВЫБРАТЬ 1"));
    CHECK_EQ(r.query_texts[1].text, std::string("ВЫБРАТЬ 2 КАК А"));
    CHECK(r.query_texts[0].site == r.query_texts[1].site);
}

TEST(BslTaint, QueryObjectDoesNotEscape) {
    // A copy would let a text change reach the object the checker never saw.
    CHECK(Denied("З = Новый Запрос(\"ВЫБРАТЬ 1\"); Д = З; Д.Текст = \"ВЫБРАТЬ 2\"; Результат = З.Выполнить();",
                 "C_QUERY_ESCAPES"));
    CHECK(Denied("З = Новый Запрос; М = Новый Массив; М.Добавить(З); Результат = 1;", "C_QUERY_ESCAPES"));
    CHECK(Denied("З = Новый Запрос; Результат = З;", "C_QUERY_ESCAPES"));
    CHECK(Denied("М = Новый Массив(Новый Запрос(\"ВЫБРАТЬ 1\")); Результат = 1;", "C_QUERY_ESCAPES"));
    CHECK(Denied("Результат = Строка(Новый Запрос(\"ВЫБРАТЬ 1\"));", "C_QUERY_ESCAPES"));
    CHECK(Safe("З = Новый Запрос(\"ВЫБРАТЬ 1\"); Результат = З.Выполнить().Пустой();"));
}

TEST(BslTaint, ContainerRules) {
    CHECK(Safe("С = Новый Структура; С.Вставить(\"К\", 1); Результат = С[\"К\"];"));
    CHECK(Safe("С = Новый Соответствие; С.Вставить(1, 2); Результат = С.Получить(1);"));
    CHECK(Denied("С = Новый Структура; К = \"К\"; Результат = С[К];", "C_DYNAMIC_KEY"));
    CHECK(Denied("С = Новый Структура; К = \"К\"; Результат = С.Свойство(К);", "C_DYNAMIC_KEY"));
    CHECK(Denied("С = Новый Структура(\"К\", 1); Результат = С.К;", "C_UNKNOWN_MEMBER"));
    CHECK(Safe("М = Новый Массив; М.Добавить(1); М[0] = 2; Результат = М[0];"));
    CHECK(Denied("М = Новый Массив; М.Очистить(); Результат = 1;", "C_UNKNOWN_METHOD"));
    CHECK(Denied("С = Новый Структура; Для Каждого Э Из С Цикл КонецЦикла; Результат = 1;", "C_UNKNOWN_ITER"));
    CHECK(Denied("Для Каждого Э Из Х Цикл КонецЦикла; Результат = 1;", "C_UNKNOWN_IDENT"));
}

TEST(BslTaint, GlobalFunctionAllowlist) {
    for (const char* ok : {"Результат = ЗначениеЗаполнено(1);", "Результат = ТипЗнч(1);", "Результат = Тип(\"Строка\");",
                           "Результат = Строка(1);", "Результат = Число(\"1\");", "Результат = Формат(1, \"ЧГ=0\");",
                           "Результат = Макс(1, 2);", "Результат = Окр(1.5, 0);", "Результат = Лев(\"abc\", 1);",
                           "Результат = СтрДлина(\"abc\") + 1;", "Результат = ValueIsFilled(1);"})
        CHECK(Safe(ok));
    for (const char* bad : {"Результат = Сообщить(\"x\");", "Результат = УстановитьПривилегированныйРежим(Истина);",
                            "Результат = СтрНайти(\"a\", \"b\");", "Результат = ОписаниеОшибки();"})
        CHECK(Denied(bad, "C_UNKNOWN_IDENT"));
    CHECK(Denied("Н = \"Строка\"; Результат = Тип(Н);", "C_DYNAMIC_KEY"));
}

TEST(BslTaint, ScalarArithmeticTypes) {
    CHECK(Safe("Х = 1 + 2; Результат = Х;"));
    CHECK(Denied("Х = 1 + 2; Результат = Х.Метод();", "C_UNKNOWN_METHOD"));
    CHECK(Safe("Результат = ?(Истина, 1, 2);"));
    CHECK(Denied("Результат = ?(Истина, Новый Массив, 2).Количество();", "C_UNKNOWN_RECEIVER"));
}
