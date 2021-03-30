// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "edata_section.h"

#include "utils/stream_utils.h"

#include "../pe_data_types.h"


namespace dexar {
namespace pe {

    bool ExportSectionParser::parse(std::istream& s, const SectionHeader& header) {
        auto sec_start_pos = header.raw_data_ptr;

        // Export Directory Table
        READ_STREAM_LE(edt_entry_.export_flags, 4);
        READ_STREAM_LE(edt_entry_.time_stamp, 4);
        READ_STREAM_LE(edt_entry_.major_ver, 2);
        READ_STREAM_LE(edt_entry_.minor_ver, 2);
        READ_STREAM_LE(edt_entry_.name_rva, 4);
        READ_STREAM_LE(edt_entry_.ordinal_base, 4);
        READ_STREAM_LE(edt_entry_.addr_table_entries, 4);
        READ_STREAM_LE(edt_entry_.name_ptr_num, 4);
        READ_STREAM_LE(edt_entry_.export_addr_table_rva, 4);
        READ_STREAM_LE(edt_entry_.name_ptr_rva, 4);
        READ_STREAM_LE(edt_entry_.ordinal_table_rva, 4);

        SEEKG_STREAM(sec_start_pos + (edt_entry_.export_addr_table_rva - header.virtual_addr));

        // Export Address Table
        for (uint32_t i = 0; i < edt_entry_.addr_table_entries; ++i) {
            ExportAddressTableEntry eat_entry;
            READ_STREAM_LE(eat_entry.export_rva, 4);
            READ_STREAM_LE(eat_entry.forwarder_rva, 4);
            eat_entries_.push_back(std::move(eat_entry));
        }

        SEEKG_STREAM(sec_start_pos + (edt_entry_.name_ptr_rva - header.virtual_addr));

        // Export Name Pointer Table
        for (uint32_t i = 0; i < edt_entry_.name_ptr_num; ++i) {
            ExportNamePtrTableEntry entry;
            READ_STREAM_LE(entry.rva, 4);
            enpt_entries_.push_back(entry);
        }

        SEEKG_STREAM(sec_start_pos + (edt_entry_.ordinal_table_rva - header.virtual_addr));

        // Export Ordinal Table
        for (uint32_t i = 0; i < edt_entry_.name_ptr_num; ++i) {
            uint16_t ord;
            READ_STREAM_LE(ord, 2);
            eot_entries_.push_back(ord);
        }

        // 解出字符串
        for (auto& entry : enpt_entries_) {
            SEEKG_STREAM(sec_start_pos + (entry.rva - header.virtual_addr));
            for (;;) {
                uint8_t buf;
                READ_STREAM(buf, 1);
                if (!buf) { break; }
                entry.name.push_back(buf);
            }
        }

        return true;
    }

}
}
