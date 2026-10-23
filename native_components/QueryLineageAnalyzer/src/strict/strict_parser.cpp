#include "strict/strict_parser.h"

#include <algorithm>
#include <iterator>
#include <unordered_map>
#include <utility>
#include <vector>

#include "utf_utils.h"

namespace lineage::strict {

namespace {

using AstExpr = lineage::strict::Expr;

struct Fail {
    ParseError e;
};

// An identifier mixing Latin and Cyrillic letters is a homoglyph vector (a Cyrillic "а" inside a Latin name and
// the like). Digits and '_' are neutral. Non-ASCII letters other than Cyrillic never reach this point: the
// tokenizer turns them into Tk::Unknown.
bool IsMixedScript(const std::string& s) {
    bool latin = false;
    bool cyrillic = false;
    for (size_t i = 0; i < s.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
            latin = true;
        } else if (c == 0xD0 || c == 0xD1) {
            cyrillic = true;
            ++i;
        }
    }
    return latin && cyrillic;
}

// Keywords accepted as a path segment AFTER a dot (Т.Ссылка, Т.Представление, ...); never as the first segment.
bool IsAllowedKeywordSegment(Kw kw) {
    return kw == Kw::Refs || kw == Kw::Presentation || kw == Kw::RefPresentation || kw == Kw::Value;
}

bool IsCountName(const std::string& key) { return key == "КОЛИЧЕСТВО" || key == "COUNT"; }

bool IsComparisonOp(const Token& t) {
    return t.kind == Tk::Op &&
           (t.text == "=" || t.text == "<>" || t.text == "<" || t.text == ">" || t.text == "<=" || t.text == ">=");
}

bool IsIntegerText(const std::string& s);

bool IsIdentChar(const std::string& s, size_t i, size_t& len, bool first) {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    len = 1;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_') return true;
    if (!first && c >= '0' && c <= '9') return true;
    if (i + 1 < s.size()) {
        const unsigned char b = static_cast<unsigned char>(s[i + 1]);
        if ((c == 0xD0 && (b == 0x81 || (b >= 0x90 && b <= 0xBF))) || (c == 0xD1 && ((b >= 0x80 && b <= 0x8F) || b == 0x91))) {
            len = 2;
            return true;
        }
    }
    return false;
}

// Tokenizer identifier charset + no Latin/Cyrillic mixing. ЕСТЬNULL is the one canonical keyword that is mixed.
bool IsValidIdent(const std::string& s) {
    if (s.empty()) return false;
    for (size_t i = 0, len = 1; i < s.size(); i += len) {
        if (!IsIdentChar(s, i, len, i == 0)) return false;
    }
    return s == "ЕСТЬNULL" || !IsMixedScript(s);
}

bool IsValidDotted(const std::string& s) {
    size_t start = 0;
    for (;;) {
        const size_t dot = s.find('.', start);
        if (!IsValidIdent(s.substr(start, dot == std::string::npos ? std::string::npos : dot - start))) return false;
        if (dot == std::string::npos) return true;
        start = dot + 1;
    }
}

bool IsNumberText(const std::string& s) {
    const size_t dot = s.find('.');
    if (dot == std::string::npos) return IsIntegerText(s);
    return IsIntegerText(s.substr(0, dot)) && IsIntegerText(s.substr(dot + 1));
}

bool IsIntegerText(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
}

class P {
public:
    explicit P(std::vector<Token> t) : t_(std::move(t)) {}

    // Any token the tokenizer could not classify rejects the whole text, before any grammar decision.
    void Prescan() const {
        for (const Token& t : t_) {
            if (t.kind != Tk::Unknown) continue;
            const bool limit = t.text == "<size>" || t.text == "<limit>";
            throw Fail{{limit ? "Q_PARSE_LIMIT" : "Q_PARSE_TOKEN", {t.pos, t.line, t.col}, limit ? t.text : ""}};
        }
    }

    ExprP Expr() {
        Guard g(*this);
        return Or();
    }

    void ExpectEnd() {
        if (Peek().kind != Tk::End) Error("Q_PARSE_UNEXPECTED");
    }

    // ---- helpers ----
    const Token& Peek(size_t k = 0) const { return t_[std::min(i_ + k, t_.size() - 1)]; }
    bool IsKw(Kw kw, size_t k = 0) const { return Peek(k).kind == Tk::Keyword && Peek(k).kw == kw; }
    bool IsOp(const char* op) const { return Peek().kind == Tk::Op && Peek().text == op; }
    bool AcceptKw(Kw kw) {
        if (!IsKw(kw)) return false;
        ++i_;
        return true;
    }
    bool Accept(Tk k) {
        if (Peek().kind != k) return false;
        ++i_;
        return true;
    }
    const Token& Next() {
        if (Peek().kind == Tk::Unknown) Error("Q_PARSE_TOKEN");
        return t_[i_ < t_.size() - 1 ? i_++ : i_];
    }
    void ExpectKw(Kw kw) {
        if (!AcceptKw(kw)) Error("Q_PARSE_EXPECTED");
    }
    void Expect(Tk k) {
        if (Peek().kind != k) Error("Q_PARSE_EXPECTED");
        Next();
    }
    [[noreturn]] void Error(const char* code, const char* detail = "") {
        const Token& tok = Peek();
        const bool unknown = tok.kind == Tk::Unknown;
        throw Fail{{unknown ? "Q_PARSE_TOKEN" : code, {tok.pos, tok.line, tok.col}, unknown ? "unknown token" : detail}};
    }
    Pos Here() const { return {Peek().pos, Peek().line, Peek().col}; }

    struct Guard {
        P& p;
        explicit Guard(P& pp) : p(pp) {
            if (++p.depth_ > kMaxParseDepth) p.Error("Q_PARSE_LIMIT", "nesting too deep");
        }
        ~Guard() { --p.depth_; }
    };

    // ---- nodes: every node is created with a concrete kind and sealed (tree depth accounted) ----
    ExprP Node(AstExpr::K kind, Pos pos, std::vector<ExprP> args = {}) {
        auto e = std::make_shared<AstExpr>();
        e->kind = kind;
        e->pos = pos;
        e->args = std::move(args);
        return e;
    }
    ExprP Seal(ExprP e) {
        int d = 0;
        for (const ExprP& a : e->args) {
            const auto it = depth_of_.find(a.get());
            if (it == depth_of_.end()) Error("Q_PARSE_INTERNAL", "unsealed child");
            d = std::max(d, it->second);
        }
        ++d;
        if (d > kMaxExprDepth) Error("Q_PARSE_LIMIT", "expression too deep");
        depth_of_[e.get()] = d;
        return e;
    }
    ExprP Leaf(AstExpr::K kind, Pos pos, std::string text) {
        ExprP e = Node(kind, pos);
        e->text = std::move(text);
        return Seal(std::move(e));
    }
    ExprP Bin(std::string op, ExprP l, ExprP r) {
        const Pos pos = l->pos;
        ExprP e = Node(AstExpr::K::Binary, pos, {std::move(l), std::move(r)});
        e->text = std::move(op);
        return Seal(std::move(e));
    }
    ExprP Un(std::string op, ExprP a, Pos p) {
        ExprP e = Node(AstExpr::K::Unary, p, {std::move(a)});
        e->text = std::move(op);
        return Seal(std::move(e));
    }

    // ---- precedence ladder: ИЛИ < И < НЕ < predicate < additive < multiplicative < unary < primary ----
    ExprP Or() {
        ExprP l = And();
        while (AcceptKw(Kw::Or)) l = Bin("ИЛИ", l, And());
        return l;
    }
    ExprP And() {
        ExprP l = Not();
        while (AcceptKw(Kw::And)) l = Bin("И", l, Not());
        return l;
    }
    ExprP Not() {
        if (!IsKw(Kw::Not)) return Predicate();
        Guard g(*this);
        const Pos p = Here();
        Next();
        return Un("НЕ", Not(), p);
    }
    ExprP Additive() {
        ExprP l = Mul();
        while (IsOp("+") || IsOp("-")) {
            std::string op = Next().text;
            l = Bin(std::move(op), l, Mul());
        }
        return l;
    }
    ExprP Mul() {
        ExprP l = Unary();
        while (IsOp("*") || IsOp("/")) {
            std::string op = Next().text;
            l = Bin(std::move(op), l, Unary());
        }
        return l;
    }
    ExprP Unary() {
        if (!IsOp("-")) return Primary();
        Guard g(*this);
        const Pos p = Here();
        Next();
        return Un("-", Unary(), p);
    }

    ExprP Predicate();
    ExprP Primary();

    std::shared_ptr<Select> SelectStmt() {
        // Subquery bodies belong to the statement grammar (a later task). Until then they are rejected.
        Error("Q_PARSE_UNSUPPORTED", "subquery");
    }

private:
    // True when the next tokens start another predicate: a chain such as `a = b = c` or `x В (1) В (2)`.
    bool AtPredicateStart() const {
        if (IsComparisonOp(Peek())) return true;
        const size_t k = IsKw(Kw::Not) ? 1 : 0;
        if (Peek(k).kind != Tk::Keyword) return false;
        const Kw kw = Peek(k).kw;
        return kw == Kw::In || kw == Kw::Between || kw == Kw::Like || kw == Kw::Refs || (k == 0 && kw == Kw::Is);
    }
    // Called right after the token was consumed with Next(); reports at that token.
    void CheckName(const Token& t) {
        if (IsMixedScript(t.text)) {
            --i_;
            Error("Q_PARSE_MIXED_SCRIPT");
        }
    }
    // Dotted name: every segment is an identifier (a keyword segment is rejected unless allowlisted).
    std::string DottedName(size_t min_segments) {
        if (Peek().kind != Tk::Identifier) Error("Q_PARSE_EXPECTED");
        const Token& first = Next();
        CheckName(first);
        std::string name = first.text;
        size_t n = 1;
        while (Peek().kind == Tk::Dot) {
            Next();
            const Token& seg = Peek();
            if (seg.kind == Tk::Keyword && !IsAllowedKeywordSegment(seg.kw)) Error("Q_PARSE_KEYWORD_SEGMENT");
            if (seg.kind != Tk::Identifier && seg.kind != Tk::Keyword) Error("Q_PARSE_EXPECTED");
            Next();
            if (seg.kind == Tk::Identifier) CheckName(seg);
            name += "." + seg.text;
            ++n;
        }
        if (n < min_segments) Error("Q_PARSE_EXPECTED", "qualified name expected");
        return name;
    }
    bool AtHierarchyWord() const {
        const Token& t = Peek();
        if (t.kind == Tk::Identifier) return NormalizeIdentifierKey(t.text) == "ИЕРАРХИИ";
        return t.kind == Tk::Keyword && t.kw == Kw::Hierarchy && NormalizeIdentifierKey(t.text) == "HIERARCHY";
    }

    ExprP IdentifierExpr();
    ExprP KeywordExpr();
    ExprP CallArgs(const Token& name_tok, std::string name);
    ExprP CaseExpr();
    ExprP CastExpr();
    ExprP FixedCall(Kw kw, size_t arity);
    ExprP Paren();

    std::vector<Token> t_;
    size_t i_ = 0;
    int depth_ = 0;
    std::unordered_map<const AstExpr*, int> depth_of_;
};

ExprP P::Predicate() {
    ExprP l = Additive();
    const Pos pos = l->pos;

    if (IsComparisonOp(Peek())) {
        std::string op = Next().text;
        ExprP r = Additive();
        ExprP e = Bin(std::move(op), l, r);
        if (AtPredicateStart()) Error("Q_PARSE_CHAIN");
        return e;
    }

    bool negated = false;
    if (IsKw(Kw::Not)) {
        const bool ok = Peek(1).kind == Tk::Keyword &&
                        (Peek(1).kw == Kw::In || Peek(1).kw == Kw::Between || Peek(1).kw == Kw::Like ||
                         Peek(1).kw == Kw::Refs);
        if (!ok) Error("Q_PARSE_UNEXPECTED");
        Next();
        negated = true;
    }
    if (Peek().kind != Tk::Keyword) return l;

    ExprP e;
    switch (Peek().kw) {
        case Kw::In: {
            Next();
            const bool hier = AtHierarchyWord();
            if (hier) Next();
            Expect(Tk::LParen);
            if (IsKw(Kw::Select)) {
                std::shared_ptr<Select> sub = SelectStmt();
                Expect(Tk::RParen);
                e = Node(hier ? AstExpr::K::InHierarchy : AstExpr::K::InSubquery, pos, {l});
                e->subquery = std::move(sub);
            } else {
                if (l->kind == AstExpr::K::Row) Error("Q_PARSE_ROW_POSITION", "row operand needs a subquery");
                std::vector<ExprP> args{l};
                do {
                    args.push_back(Expr());
                } while (Accept(Tk::Comma));
                Expect(Tk::RParen);
                e = Node(hier ? AstExpr::K::InHierarchy : AstExpr::K::InList, pos, std::move(args));
            }
            e->negated = negated;
            break;
        }
        case Kw::Between: {
            Next();
            ExprP lo = Additive();
            ExpectKw(Kw::And);
            ExprP hi = Additive();
            e = Node(AstExpr::K::Between, pos, {l, lo, hi});
            e->negated = negated;
            break;
        }
        case Kw::Like: {
            Next();
            std::vector<ExprP> args{l, Additive()};
            if (AcceptKw(Kw::Escape)) args.push_back(Additive());
            e = Node(AstExpr::K::Like, pos, std::move(args));
            e->negated = negated;
            break;
        }
        case Kw::Is: {
            Next();
            const bool not_null = AcceptKw(Kw::Not);
            ExpectKw(Kw::Null);
            e = Node(AstExpr::K::IsNullTest, pos, {l});
            e->negated = not_null;
            break;
        }
        case Kw::Refs: {
            Next();
            e = Node(AstExpr::K::RefsTest, pos, {l});
            e->type_name = DottedName(2);
            e->negated = negated;
            break;
        }
        default:
            return l;   // a keyword that continues an enclosing production (И, ИЛИ, ТОГДА, КАК, ...)
    }
    Seal(e);
    if (AtPredicateStart()) Error("Q_PARSE_CHAIN");
    return e;
}

ExprP P::Primary() {
    const Token& t = Peek();
    const Pos pos = Here();
    switch (t.kind) {
        case Tk::String:
            Next();
            return Leaf(AstExpr::K::StringLit, pos, t.value);
        case Tk::Number:
            Next();
            return Leaf(AstExpr::K::NumberLit, pos, t.text);
        case Tk::Parameter:
            Next();
            CheckName(t);
            return Leaf(AstExpr::K::Param, pos, t.text.substr(1));
        case Tk::Identifier:
            return IdentifierExpr();
        case Tk::Keyword:
            return KeywordExpr();
        case Tk::LParen:
            return Paren();
        default:
            Error("Q_PARSE_UNEXPECTED");
    }
}

ExprP P::IdentifierExpr() {
    const Token& first = Next();
    CheckName(first);
    const Pos pos{first.pos, first.line, first.col};
    if (Peek().kind == Tk::LParen) return CallArgs(first, NormalizeIdentifierKey(first.text));

    ExprP e = Node(AstExpr::K::Field, pos);
    e->parts.push_back(first.text);
    while (Peek().kind == Tk::Dot) {
        Next();
        const Token& seg = Peek();
        if (seg.kind == Tk::Keyword && !IsAllowedKeywordSegment(seg.kw)) Error("Q_PARSE_KEYWORD_SEGMENT");
        if (seg.kind != Tk::Identifier && seg.kind != Tk::Keyword) Error("Q_PARSE_EXPECTED");
        Next();
        if (seg.kind == Tk::Identifier) CheckName(seg);
        e->parts.push_back(seg.text);
    }
    if (Peek().kind == Tk::LParen) Error("Q_PARSE_UNEXPECTED", "call on a path");
    return Seal(std::move(e));
}

// Call syntax after the name: ( [РАЗЛИЧНЫЕ] args ) with the КОЛИЧЕСТВО(*) form.
ExprP P::CallArgs(const Token& name_tok, std::string name) {
    const Pos pos{name_tok.pos, name_tok.line, name_tok.col};
    const bool is_count = IsCountName(name);
    ExprP e = Node(AstExpr::K::Call, pos);
    e->text = std::move(name);
    Expect(Tk::LParen);
    if (Peek().kind == Tk::RParen) {
        // КОЛИЧЕСТВО() would collide with the КОЛИЧЕСТВО(*) representation (no args): not a valid call anyway.
        if (is_count) Error("Q_PARSE_EXPECTED", "argument expected");
        Next();
        return Seal(std::move(e));
    }
    if (IsKw(Kw::Distinct)) {
        if (!is_count) Error("Q_PARSE_UNEXPECTED", "РАЗЛИЧНЫЕ outside КОЛИЧЕСТВО");
        Next();
        e->distinct = true;
    } else if (IsOp("*")) {
        if (!is_count) Error("Q_PARSE_UNEXPECTED", "* outside КОЛИЧЕСТВО");
        Next();
        Expect(Tk::RParen);
        return Seal(std::move(e));   // COUNT(*): a Call with no arguments
    }
    do {
        e->args.push_back(Expr());
    } while (Accept(Tk::Comma));
    Expect(Tk::RParen);
    if (e->distinct && e->args.size() != 1) Error("Q_PARSE_UNEXPECTED", "РАЗЛИЧНЫЕ takes one argument");
    return Seal(std::move(e));
}

ExprP P::FixedCall(Kw kw, size_t arity) {
    const Token& tok = Next();
    const Pos pos{tok.pos, tok.line, tok.col};
    ExprP e = Node(AstExpr::K::Call, pos);
    e->text = CanonicalKeyword(kw);
    Expect(Tk::LParen);
    for (size_t k = 0; k < arity; ++k) {
        if (k != 0) Expect(Tk::Comma);
        e->args.push_back(Expr());
    }
    Expect(Tk::RParen);
    return Seal(std::move(e));
}

ExprP P::KeywordExpr() {
    const Pos pos = Here();
    switch (Peek().kw) {
        case Kw::True:
            Next();
            return Leaf(AstExpr::K::BoolLit, pos, "ИСТИНА");
        case Kw::False:
            Next();
            return Leaf(AstExpr::K::BoolLit, pos, "ЛОЖЬ");
        case Kw::Null:
            Next();
            return Leaf(AstExpr::K::NullLit, pos, "NULL");
        case Kw::Undefined:
            Next();
            return Leaf(AstExpr::K::UndefinedLit, pos, "НЕОПРЕДЕЛЕНО");
        case Kw::Case:
            return CaseExpr();
        case Kw::Cast:
            return CastExpr();
        case Kw::Value:
        case Kw::Type: {
            const bool is_value = Peek().kw == Kw::Value;
            Next();
            Expect(Tk::LParen);
            ExprP e = Node(is_value ? AstExpr::K::ValueFn : AstExpr::K::TypeFn, pos);
            e->type_name = DottedName(is_value ? 2 : 1);
            Expect(Tk::RParen);
            return Seal(std::move(e));
        }
        case Kw::ValueType:
        case Kw::Presentation:
        case Kw::RefPresentation:
            return FixedCall(Peek().kw, 1);
        case Kw::IsNull:
            return FixedCall(Kw::IsNull, 2);
        default:
            Error("Q_PARSE_UNEXPECTED");
    }
}

ExprP P::CaseExpr() {
    const Pos pos = Here();
    Next();   // ВЫБОР
    ExprP e = Node(AstExpr::K::Case, pos);
    if (!IsKw(Kw::When)) {
        e->args.push_back(Expr());
        e->has_operand = true;
    }
    if (!IsKw(Kw::When)) Error("Q_PARSE_EXPECTED", "КОГДА expected");
    while (AcceptKw(Kw::When)) {
        e->args.push_back(Expr());
        ExpectKw(Kw::Then);
        e->args.push_back(Expr());
    }
    if (AcceptKw(Kw::Else)) {
        e->args.push_back(Expr());
        e->has_else = true;
    }
    ExpectKw(Kw::End);
    return Seal(std::move(e));
}

ExprP P::CastExpr() {
    const Pos pos = Here();
    Next();   // ВЫРАЗИТЬ
    Expect(Tk::LParen);
    ExprP e = Node(AstExpr::K::Cast, pos);
    e->args.push_back(Expr());
    ExpectKw(Kw::As);
    e->type_name = DottedName(1);
    if (Accept(Tk::LParen)) {
        for (int k = 0; k < 2; ++k) {
            if (k != 0 && !Accept(Tk::Comma)) break;
            if (Peek().kind != Tk::Number || !IsIntegerText(Peek().text)) Error("Q_PARSE_EXPECTED", "integer expected");
            e->type_args.push_back(Next().text);
        }
        Expect(Tk::RParen);
    }
    Expect(Tk::RParen);
    return Seal(std::move(e));
}

// ( expr ) or ( a, b, ... ) row. A subquery here is not allowed: it is valid only as the right side of В.
ExprP P::Paren() {
    const Pos pos = Here();
    Next();   // (
    if (IsKw(Kw::Select)) Error("Q_PARSE_SUBQUERY_POSITION");
    ExprP first = Expr();
    if (Peek().kind != Tk::Comma) {
        Expect(Tk::RParen);
        return first;
    }
    ExprP row = Node(AstExpr::K::Row, pos, {first});
    while (Accept(Tk::Comma)) row->args.push_back(Expr());
    Expect(Tk::RParen);
    return Seal(std::move(row));
}

}  // namespace

bool ValidateExpr(const ExprP& root, ParseError& err) {
    struct Item {
        const Expr* e;
        int depth;
        bool row_ok;
    };
    auto bad = [&](const Expr* e, const char* why) {
        err = ParseError{"Q_PARSE_INVALID_NODE", e ? e->pos : Pos{}, why};
        return false;
    };
    if (!root) return bad(nullptr, "null expression");

    size_t visited = 0;
    std::vector<Item> stack{{root.get(), 1, false}};
    while (!stack.empty()) {
        const Item it = stack.back();
        stack.pop_back();
        const Expr& e = *it.e;
        if (it.depth > kMaxExprDepth || ++visited > kMaxExprNodes) {
            err = ParseError{"Q_PARSE_LIMIT", e.pos, "expression too large"};
            return false;
        }
        for (const ExprP& a : e.args) {
            if (!a) return bad(&e, "null child");
        }
        const size_t n = e.args.size();
        const AstExpr::K k = e.kind;
        const bool sub_kind = k == AstExpr::K::InSubquery || k == AstExpr::K::InHierarchy;
        if (e.subquery && !sub_kind) return bad(&e, "unexpected subquery");

        // Payload fields are legal only on the kinds that use them.
        const bool negatable = k == AstExpr::K::InList || sub_kind || k == AstExpr::K::Between ||
                               k == AstExpr::K::Like || k == AstExpr::K::IsNullTest || k == AstExpr::K::RefsTest;
        if (e.negated && !negatable) return bad(&e, "negated on wrong kind");
        if (e.distinct && k != AstExpr::K::Call) return bad(&e, "distinct on wrong kind");
        if ((e.has_operand || e.has_else) && k != AstExpr::K::Case) return bad(&e, "case flag on wrong kind");
        const bool typed = k == AstExpr::K::Cast || k == AstExpr::K::RefsTest || k == AstExpr::K::ValueFn ||
                           k == AstExpr::K::TypeFn;
        if (!typed && !e.type_name.empty()) return bad(&e, "type name on wrong kind");
        if (typed && !IsValidDotted(e.type_name)) return bad(&e, "type name");
        if (k != AstExpr::K::Cast && !e.type_args.empty()) return bad(&e, "type args on wrong kind");
        if (e.type_args.size() > 2) return bad(&e, "too many type args");
        for (const std::string& ta : e.type_args) {
            if (!IsIntegerText(ta)) return bad(&e, "type arg");
        }
        if (k != AstExpr::K::Field && !e.parts.empty()) return bad(&e, "path on wrong kind");
        const bool texted = k == AstExpr::K::Param || k == AstExpr::K::StringLit || k == AstExpr::K::NumberLit ||
                            k == AstExpr::K::BoolLit || k == AstExpr::K::NullLit ||
                            k == AstExpr::K::UndefinedLit || k == AstExpr::K::Unary ||
                            k == AstExpr::K::Binary || k == AstExpr::K::Call;
        if (!texted && !e.text.empty()) return bad(&e, "text on wrong kind");

        switch (k) {
            case AstExpr::K::Unset:
                return bad(&e, "unset node");
            case AstExpr::K::Field:
                if (n != 0 || e.parts.empty()) return bad(&e, "field");
                for (const std::string& p : e.parts) {
                    if (!IsValidIdent(p)) return bad(&e, "field segment");
                }
                break;
            case AstExpr::K::Param:
                if (n != 0 || !IsValidIdent(e.text)) return bad(&e, "parameter name");
                break;
            case AstExpr::K::NumberLit:
                if (n != 0 || !IsNumberText(e.text)) return bad(&e, "number literal");
                break;
            case AstExpr::K::StringLit:
                if (n != 0) return bad(&e, "literal with children");
                break;
            case AstExpr::K::NullLit:
                if (n != 0 || e.text != "NULL") return bad(&e, "null literal");
                break;
            case AstExpr::K::UndefinedLit:
                if (n != 0 || e.text != "НЕОПРЕДЕЛЕНО") return bad(&e, "undefined literal");
                break;
            case AstExpr::K::BoolLit:
                if (n != 0 || (e.text != "ИСТИНА" && e.text != "ЛОЖЬ")) return bad(&e, "bool literal");
                break;
            case AstExpr::K::Unary:
                if (n != 1 || (e.text != "-" && e.text != "НЕ")) return bad(&e, "unary");
                break;
            case AstExpr::K::Binary: {
                static const char* const ops[] = {"+", "-", "*", "/", "=", "<>", "<", ">", "<=", ">=", "И", "ИЛИ"};
                if (n != 2 || std::find(std::begin(ops), std::end(ops), e.text) == std::end(ops)) {
                    return bad(&e, "binary");
                }
                break;
            }
            case AstExpr::K::Call:
                if (!IsValidIdent(e.text)) return bad(&e, "call name");
                if (e.distinct && (!IsCountName(e.text) || n != 1)) return bad(&e, "distinct call");
                break;
            case AstExpr::K::Case: {
                const size_t fixed = (e.has_operand ? 1 : 0) + (e.has_else ? 1 : 0);
                if (n < fixed + 2 || (n - fixed) % 2 != 0) return bad(&e, "case shape");
                break;
            }
            case AstExpr::K::Cast:
                if (n != 1) return bad(&e, "cast");
                break;
            case AstExpr::K::InList:
                if (n < 2) return bad(&e, "in list");
                break;
            case AstExpr::K::InSubquery:
                if (n != 1 || !e.subquery) return bad(&e, "in subquery");
                break;
            case AstExpr::K::InHierarchy:
                if (e.subquery ? n != 1 : n < 2) return bad(&e, "in hierarchy");
                break;
            case AstExpr::K::Between:
                if (n != 3) return bad(&e, "between");
                break;
            case AstExpr::K::Like:
                if (n != 2 && n != 3) return bad(&e, "like");
                break;
            case AstExpr::K::IsNullTest:
                if (n != 1) return bad(&e, "is null");
                break;
            case AstExpr::K::RefsTest:
                if (n != 1) return bad(&e, "refs");
                break;
            case AstExpr::K::ValueFn:
            case AstExpr::K::TypeFn:
                if (n != 0) return bad(&e, "type function");
                break;
            case AstExpr::K::Row:
                if (!it.row_ok) return bad(&e, "row outside the left side of a subquery В");
                if (n < 2) return bad(&e, "row");
                break;
        }
        for (size_t i = 0; i < n; ++i) {
            const bool row_ok = i == 0 && sub_kind && e.subquery != nullptr;
            stack.push_back({e.args[i].get(), it.depth + 1, row_ok});
        }
    }
    return true;
}

ExprResult ParseExpressionForTest(const std::string& utf8) {
    ExprResult r;
    try {
        P p(Tokenize(utf8));
        p.Prescan();
        r.expr = p.Expr();
        p.ExpectEnd();
        ParseError err;
        if (!ValidateExpr(r.expr, err)) throw Fail{err};
        r.ok = true;
    } catch (const Fail& f) {
        r.ok = false;
        r.expr = nullptr;
        r.error = f.e;
    } catch (...) {
        r.ok = false;
        r.expr = nullptr;
        r.error = ParseError{"Q_PARSE_INTERNAL", Pos{0, 1, 1}, "internal error"};
    }
    return r;
}

ParseResult ParseBatchStrict(const std::string& utf8) {
    // The statement grammar (batches, clauses, subqueries) is a later task: until it lands, nothing parses.
    ParseResult r;
    r.error = ParseError{"Q_PARSE_UNSUPPORTED", Pos{}, "statement grammar not implemented"};
    try {
        for (const Token& t : Tokenize(utf8)) {
            if (t.kind != Tk::Unknown) continue;
            const bool limit = t.text == "<size>" || t.text == "<limit>";
            r.error = ParseError{limit ? "Q_PARSE_LIMIT" : "Q_PARSE_TOKEN", Pos{t.pos, t.line, t.col}, ""};
            break;
        }
    } catch (...) {
        r.error = ParseError{"Q_PARSE_INTERNAL", Pos{0, 1, 1}, "internal error"};
    }
    return r;
}

}  // namespace lineage::strict
