// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_PE_SECTIONS_EDATA_SECTION_H_
#define DEXAR_PE_SECTIONS_EDATA_SECTION_H_

#include <istream>
#include <vector>


namespace dexar {
namespace pe {

    struct SectionHeader;

    struct ExportDirectoryTableEntry {
        uint32_t export_flags;
        uint32_t time_stamp;
        uint16_t major_ver;
        uint16_t minor_ver;
        uint32_t name_rva;
        uint32_t ordinal_base;
        uint32_t addr_table_entries;
        uint32_t name_ptr_num;
        uint32_t export_addr_table_rva;
        uint32_t name_ptr_rva;
        uint32_t ordinal_table_rva;
    };

    struct ExportAddressTableEntry {
        uint32_t export_rva;
        uint32_t forwarder_rva;
    };

    struct ExportNamePtrTableEntry {
        uint32_t rva;

        // RVA 对应的内容
        std::string name;
    };


    class ExportSectionParser {
    public:
        ExportSectionParser() = default;

        bool parse(std::istream& s, const SectionHeader& header);

    private:
        ExportDirectoryTableEntry edt_entry_;
        std::vector<ExportAddressTableEntry> eat_entries_;
        std::vector<ExportNamePtrTableEntry> enpt_entries_;
        std::vector<uint16_t> eot_entries_;
    };

}
}

#endif  // DEXAR_PE_SECTIONS_EDATA_SECTION_H_