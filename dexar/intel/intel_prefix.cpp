// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/intel_prefix.h"


namespace dexar {
namespace intel {

    Prefix::Prefix()
        : g1(0), g2(0), g3(0), g4(0), mand(0), rex(0),
        vex(), vex_length(0) {
    }

    uint8_t Prefix::rexW() const {
        return (rex & 0x8);
    }

    uint8_t Prefix::rexR() const {
        return (rex & 0x4);
    }

    uint8_t Prefix::rexX() const {
        return (rex & 0x2);
    }

    uint8_t Prefix::rexB() const {
        return (rex & 0x1);
    }

    // Only used in 3-bit
    uint8_t Prefix::vexW() const {
        return (vex[2] & 0x80);
    }

    uint8_t Prefix::vexR() const {
        return (vex[1] & 0x80);
    }

    // Only used in 3-bit
    uint8_t Prefix::vexX() const {
        return (vex[1] & 0x40);
    }

    // Only used in 3-bit
    uint8_t Prefix::vexB() const {
        return (vex[1] & 0x20);
    }

    uint8_t Prefix::vexL() const {
        if (vex_length == 2) {
            return (vex[1] & 0x4);
        }
        if (vex_length == 3) {
            return (vex[2] & 0x4);
        }
        return 0;
    }

    // Only used in 3-bit
    uint8_t Prefix::vexM() const {
        return (vex[1] & 0x1F);
    }

    uint8_t Prefix::vexV() const {
        if (vex_length == 2) {
            return (vex[1] & 0x78);
        }
        if (vex_length == 3) {
            return (vex[2] & 0x78);
        }
        return 0;
    }

    uint8_t Prefix::vexP() const {
        if (vex_length == 2) {
            return (vex[1] & 0x3);
        }
        if (vex_length == 3) {
            return (vex[2] & 0x73);
        }
        return 0;
    }

    bool Prefix::hasRex() const {
        return rex != 0;
    }

    bool Prefix::hasVex() const {
        return vex_length > 0;
    }

    uint32_t Prefix::length() const {
        uint32_t l = 0;
        if (g1 != 0) { ++l; }
        if (g2 != 0) { ++l; }
        if (g3 != 0) { ++l; }
        if (g4 != 0) { ++l; }
        if (mand != 0) { ++l; }
        if (rex != 0) { ++l; }
        l += vex_length;
        return l;
    }

    void Prefix::reset() {
        g1 = 0;
        g2 = 0;
        g3 = 0;
        g4 = 0;
        mand = 0;
        rex = 0;
        vex_length = 0;
    }

}
}
