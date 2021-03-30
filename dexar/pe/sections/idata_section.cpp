// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "idata_section.h"

#include "utils/stream_utils.h"

#include "../pe_data_types.h"


namespace dexar {
namespace pe {

    bool ImportSectionParser::parse(
        std::istream& s, const SectionHeader& header, bool is_plus)
    {
        auto sec_start_pos = header.raw_data_ptr;

        for (;;) {
            ImportDirectoryTableEntry entry;
            READ_STREAM_LE(entry.ilt_rva, 4);
            READ_STREAM_LE(entry.time_stamp, 4);
            READ_STREAM_LE(entry.forwarder_chain, 4);
            READ_STREAM_LE(entry.name_rva, 4);
            READ_STREAM_LE(entry.iat_rva, 4);

            if (entry.ilt_rva == 0 &&
                entry.time_stamp == 0 &&
                entry.forwarder_chain == 0 &&
                entry.name_rva == 0 &&
                entry.iat_rva == 0)
            {
                break;
            }
            idt_entries_.push_back(std::move(entry));
        }

        // 解 RVA
        for (auto& entry : idt_entries_) {
            // name_rva
            SEEKG_STREAM(sec_start_pos + (entry.name_rva - header.virtual_addr));
            for (;;) {
                uint8_t buf;
                READ_STREAM(buf, 1);
                if (!buf) { break; }
                entry.name.push_back(buf);
            }

            // ilt_rva
            SEEKG_STREAM(sec_start_pos + (entry.ilt_rva - header.virtual_addr));
            for (;;) {
                ImportLookupTableEntry ilt_entry;
                if (is_plus) {
                    uint64_t data;
                    READ_STREAM_LE(data, 8);
                    if (data == 0) {
                        break;
                    }
                    ilt_entry.ordinal = (data >> 63) == 1;
                    if (ilt_entry.ordinal) {
                        ilt_entry.ordinal_num = uint16_t(data & 0xFF);
                    } else {
                        ilt_entry.hint_name_table_rva = uint32_t(data & 0x7FFFFFFF);
                    }
                } else {
                    uint32_t data;
                    READ_STREAM_LE(data, 4);
                    if (data == 0) {
                        break;
                    }
                    ilt_entry.ordinal = (data >> 31) == 1;
                    if (ilt_entry.ordinal) {
                        ilt_entry.ordinal_num = uint16_t(data & 0xFF);
                    } else {
                        ilt_entry.hint_name_table_rva = uint32_t(data & 0x7FFFFFFF);
                    }
                }

                if (!ilt_entry.ordinal) {
                    // Hint/Name Table
                    auto prev_pos = s.tellg();
                    SEEKG_STREAM(sec_start_pos + (ilt_entry.hint_name_table_rva - header.virtual_addr));

                    READ_STREAM_LE(ilt_entry.hn_entry.hint, 2);
                    for (;;) {
                        uint8_t buf;
                        READ_STREAM(buf, 1);
                        if (!buf) { break; }
                        ilt_entry.hn_entry.name.push_back(buf);
                    }
                    s.seekg(prev_pos);
                }

                entry.ilt_entries.push_back(std::move(ilt_entry));
            }
        }

        return true;
    }

}
}
