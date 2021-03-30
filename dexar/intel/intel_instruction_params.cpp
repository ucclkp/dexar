// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/intel_instruction_params.h"


namespace dexar {
namespace intel {

    uint32_t selectOperandSize(bool d, const Prefix& p) {
        if (d) {
            return (p.g3 != 0) ? 2 : 4;
        }
        return (p.g3 != 0) ? 4 : 2;
    }

    uint32_t selectOperandSize64(const std::string& ss, const Prefix& p) {
        if (ss == "f64") {
            return 8;
        }

        if (p.hasRex() && p.rexW()) {
            return 8;
        }

        if (ss == "d64") {
            return (p.g3 != 0) ? 2 : 8;
        } else {
            return (p.g3 != 0) ? 2 : 4;
        }
    }

    uint32_t selectAddressSize(bool d, const Prefix& p) {
        if (d) {
            return (p.g4 != 0) ? 2 : 4;
        }
        return (p.g4 != 0) ? 4 : 2;
    }

    uint32_t selectAddressSize64(const Prefix& p) {
        return (p.g4 != 0) ? 4 : 8;
    }

}
}