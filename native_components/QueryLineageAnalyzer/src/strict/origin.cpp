#include "strict/origin.h"

namespace lineage::strict {

const char* OriginName(Origin o) {
    switch (o) {
        case Origin::Open: return "open";
        case Origin::Client: return "client";
        case Origin::ProtectedDirect: return "protected";
        case Origin::ProtectedDerived: return "protected_derived";
        case Origin::Mixed: return "mixed";
        case Origin::Unknown: return "unknown";
    }
    return "unknown";
}

}  // namespace lineage::strict
