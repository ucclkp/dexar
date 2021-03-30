// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_PE_SECTIONS_RSRC_SECTION_H_
#define DEXAR_PE_SECTIONS_RSRC_SECTION_H_

#include <istream>
#include <vector>


namespace dexar {
namespace pe {

    struct SectionHeader;
    struct ResDirectoryTable;

    struct ResDirectoryString {
        uint16_t length;
        std::u16string str;
    };

    struct ResDataEntry {
        uint32_t data_rva;
        uint32_t size;
        uint32_t codepage;
        uint32_t reserved;
    };

    struct ResDirectoryEntry {
        // 高位 0 表示 integer id, 1 表示 offset
        uint32_t name;
        // 高位 0 表示 data entry offset, 1 表示 subdir offset
        uint32_t data_offset;

        ResDirectoryString name_str;
        ResDataEntry data_entry;
        std::unique_ptr<ResDirectoryTable> leaf;
    };

    struct ResDirectoryTable {
        uint32_t characteristics;
        uint32_t time_date_stamp;
        uint16_t major_ver;
        uint16_t minor_ver;
        uint16_t name_entry_num;
        uint16_t id_entry_num;

        std::vector<ResDirectoryEntry> name_entries;
        std::vector<ResDirectoryEntry> id_entries;
    };


    class ResourceSectionParser {
    public:
        ResourceSectionParser() = default;

        bool parse(std::istream& s, std::unique_ptr<ResDirectoryTable>* out);

    private:
        bool parseDirectory(std::istream& s, std::unique_ptr<ResDirectoryTable>* out);
        bool parseDirectoryEntry(std::istream& s, ResDirectoryEntry* out);
        bool parseNameString(std::istream& s, uint32_t name, ResDirectoryString* out);
        bool parseDataEntry(std::istream& s, uint32_t data, ResDataEntry* out);

        std::streampos start_pos_;
    };

}
}

#endif  // DEXAR_PE_SECTIONS_RSRC_SECTION_H_