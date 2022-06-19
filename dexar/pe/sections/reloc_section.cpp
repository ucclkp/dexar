// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "reloc_section.h"

#include "utils/memory/aligments.hpp"
#include "utils/stream_utils.h"


namespace dexar {
namespace pe {

    bool parseRelocSection(
        std::istream& s,
        size_t len,
        std::vector<BaseRelocBlock>* out)
    {
        auto spos = s.tellg();

        for (;;) {
            BaseRelocBlock block;
            READ_STREAM_LE(block.page_rva, 4);
            READ_STREAM_LE(block.block_size, 4);

            size_t cnt;
            if (block.block_size >= 8) {
                cnt = (block.block_size - 8) / 2;
            } else {
                cnt = 0;
            }

            for (size_t i = 0; i < cnt; ++i) {
                uint16_t ent;
                READ_STREAM_LE(ent, 2);

                BaseRelocItem item;
                item.type = ent >> 12u;
                item.offset = ent & 0xFFF;
                block.entries.push_back(item);
            }

            out->push_back(block);

            auto off = utl::align4off(block.block_size);
            if (off > 0) {
                s.seekg(off, std::ios::cur);
            }

            if (s.tellg() - spos >= len) {
                break;
            }
        }

        return true;
    }

}
}