// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_INTEL_INTEL_PREFIX_H_
#define DEXAR_INTEL_INTEL_PREFIX_H_

#include <cstdint>


namespace dexar {
namespace intel {

    class Prefix {
    public:
        uint8_t g1;
        uint8_t g2;
        uint8_t g3;
        uint8_t g4;
        uint8_t mand;
        uint8_t rex;
        uint8_t vex[3];
        uint32_t vex_length;

        Prefix();

        uint8_t rexW() const;
        uint8_t rexR() const;
        uint8_t rexX() const;
        uint8_t rexB() const;

        // Only used in 3-bit
        uint8_t vexW() const;
        uint8_t vexR() const;
        // Only used in 3-bit
        uint8_t vexX() const;
        // Only used in 3-bit
        uint8_t vexB() const;
        uint8_t vexL() const;
        // Only used in 3-bit
        uint8_t vexM() const;
        uint8_t vexV() const;
        uint8_t vexP() const;

        bool hasRex() const;
        bool hasVex() const;

        uint32_t length() const;
        void reset();
    };

}
}

#endif  // DEXAR_INTEL_INTEL_PREFIX_H_