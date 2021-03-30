// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_INTEL_CODE_SEGMENT_H_
#define DEXAR_INTEL_CODE_SEGMENT_H_

#include <cstdint>

#include "dexar/intel/intel_instruction_params.h"


namespace dexar {
    class CodeDataProvider;

namespace intel {

    class CodeSegment {
    public:
        Env env;
        uint32_t cur;
        uint32_t size;
        CodeDataProvider* provider;

        CodeSegment operator+(uint32_t off) const;
        CodeSegment& operator+=(uint32_t off);

        uint8_t get8(uint32_t off) const;
        uint16_t get16(uint32_t off) const;
        uint32_t get32(uint32_t off) const;
        uint64_t get64(uint32_t off) const;
        uint8_t getCur8() const;
    };

}
}

#endif  // DEXAR_INTEL_CODE_SEGMENT_H_