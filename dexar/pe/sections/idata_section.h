// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_PE_SECTIONS_IDATA_SECTION_H_
#define DEXAR_PE_SECTIONS_IDATA_SECTION_H_

#include <istream>
#include <vector>


namespace dexar {
namespace pe {

    struct SectionHeader;

    struct ImportHNTableEntry {
        uint16_t hint;
        std::string name;
    };

    struct ImportLookupTableEntry {
        bool ordinal;
        uint16_t ordinal_num;
        uint32_t hint_name_table_rva;

        // RVA 对应的内容
        ImportHNTableEntry hn_entry;
    };

    struct ImportDirectoryTableEntry {
        uint32_t ilt_rva;
        uint32_t time_stamp;
        uint32_t forwarder_chain;
        uint32_t name_rva;
        uint32_t iat_rva;

        // RVA 对应的内容
        std::string name;
        std::vector<ImportLookupTableEntry> ilt_entries;
        std::vector<ImportLookupTableEntry> iat_entries;
    };


    class ImportSectionParser {
    public:
        ImportSectionParser() = default;

        bool parse(std::istream& s, const SectionHeader& header, bool is_plus);

    private:
        std::vector<ImportDirectoryTableEntry> idt_entries_;
    };

}
}

#endif  // DEXAR_PE_SECTIONS_IDATA_SECTION_H_