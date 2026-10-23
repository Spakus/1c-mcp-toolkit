#pragma once
#include <ostream>

namespace lineage::strict {

enum class Origin { Open, Client, ProtectedDirect, ProtectedDerived, Mixed, Unknown };

// Named JoinOrigin: lineage::strict::Join is the AST join clause.
// Partial order: Unknown is top. Mixed = protected and non-protected may coexist in one column.
inline Origin JoinOrigin(Origin a, Origin b) {
    if (a == b) return a;
    if (a == Origin::Unknown || b == Origin::Unknown) return Origin::Unknown;
    auto prot = [](Origin o) { return o == Origin::ProtectedDirect || o == Origin::ProtectedDerived; };
    if (prot(a) && prot(b)) return Origin::ProtectedDerived;
    if (prot(a) || prot(b) || a == Origin::Mixed || b == Origin::Mixed) return Origin::Mixed;
    return Origin::Client;   // {Open, Client}: no protected content; client values are returned as is
}

inline Origin Transform(Origin a) { return a == Origin::ProtectedDirect ? Origin::ProtectedDerived : a; }

const char* OriginName(Origin o);   // "open" "client" "protected" "protected_derived" "mixed" "unknown"

inline std::ostream& operator<<(std::ostream& os, Origin o) { return os << OriginName(o); }

}  // namespace lineage::strict
