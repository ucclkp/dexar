// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_PE_SECTIONS_RELOC_SECTION_H_
#define DEXAR_PE_SECTIONS_RELOC_SECTION_H_

#include <istream>
#include <vector>


namespace dexar {
namespace pe {

    struct BaseRelocItem {
        unsigned char type;
        unsigned int offset;
    };

    struct BaseRelocBlock {
        unsigned long page_rva;
        unsigned long block_size;
        std::vector<BaseRelocItem> entries;
    };

    bool parseRelocSection(
        std::istream& s,
        size_t len,
        std::vector<BaseRelocBlock>* out);

}
}

#endif  // DEXAR_PE_SECTIONS_RELOC_SECTION_H_