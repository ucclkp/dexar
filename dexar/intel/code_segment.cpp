// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/code_segment.h"

#include "dexar/code_data_provider.h"


namespace dexar {
namespace intel {

    CodeSegment CodeSegment::operator+(uint32_t off) const {
        CodeSegment tmp = *this;
        tmp.cur += off;
        return tmp;
    }

    CodeSegment& CodeSegment::operator+=(uint32_t off) {
        cur += off;
        return *this;
    }

    uint8_t CodeSegment::get8(uint32_t off) const {
        return provider->get8(off);
    }

    uint16_t CodeSegment::get16(uint32_t off) const {
        return provider->get16(off);
    }

    uint32_t CodeSegment::get32(uint32_t off) const {
        return provider->get32(off);
    }

    uint64_t CodeSegment::get64(uint32_t off) const {
        return provider->get64(off);
    }

    uint8_t CodeSegment::getCur8() const {
        return provider->get8(cur);
    }

}
}
