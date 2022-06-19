// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/pe/sections/rsrc_section.h"

#include "utils/stream_utils.h"

#include "../pe_data_types.h"


namespace dexar {
namespace pe {

    bool ResourceSectionParser::parse(
        std::istream& s, std::unique_ptr<ResDirectoryTable>* out)
    {
        start_pos_ = s.tellg();
        return parseDirectory(s, out);
    }

    bool ResourceSectionParser::parseDirectory(std::istream& s, std::unique_ptr<ResDirectoryTable>* out) {
        *out = std::make_unique<ResDirectoryTable>();
        auto ptr = out->get();

        READ_STREAM_LE(ptr->characteristics, 4);
        READ_STREAM_LE(ptr->time_date_stamp, 4);
        READ_STREAM_LE(ptr->major_ver, 2);
        READ_STREAM_LE(ptr->minor_ver, 2);
        READ_STREAM_LE(ptr->name_entry_num, 2);
        READ_STREAM_LE(ptr->id_entry_num, 2);

        for (uint16_t i = 0; i < ptr->name_entry_num; ++i) {
            ResDirectoryEntry entry{};
            if (!parseDirectoryEntry(s, &entry)) {
                return false;
            }
            ptr->name_entries.push_back(std::move(entry));
        }

        for (uint16_t i = 0; i < ptr->id_entry_num; ++i) {
            ResDirectoryEntry entry{};
            if (!parseDirectoryEntry(s, &entry)) {
                return false;
            }
            ptr->id_entries.push_back(std::move(entry));
        }

        return true;
    }

    bool ResourceSectionParser::parseDirectoryEntry(std::istream& s, ResDirectoryEntry* out) {
        READ_STREAM_LE(out->name, 4);
        READ_STREAM_LE(out->data_offset, 4);

        // offset
        if (out->name & 0x80000000) {
            if (!parseNameString(s, out->name, &out->name_str)) {
                return false;
            }
        }

        if (out->data_offset & 0x80000000) {
            // subdir offset
            auto prev_pos = s.tellg();
            if (!s.seekg(start_pos_ + std::streamoff(out->data_offset & ~0x80000000))) {
                return false;
            }

            if (!parseDirectory(s, &out->leaf)) {
                return false;
            }

            if (!s.seekg(prev_pos)) {
                return false;
            }
        } else {
            // data entry offset
            if (!parseDataEntry(s, out->data_offset, &out->data_entry)) {
                return false;
            }
        }

        return true;
    }

    bool ResourceSectionParser::parseNameString(
        std::istream& s, uint32_t name, ResDirectoryString* out)
    {
        // TODO: 需要测试
        auto prev_pos = s.tellg();
        if (!s.seekg(start_pos_ + std::streamoff(name & ~0x80000000))) {
            return false;
        }

        READ_STREAM_LE(out->length, 2);
        out->str.resize(out->length);
        READ_STREAM(*out->str.begin(), out->length * 2);

        if (!s.seekg(prev_pos)) {
            return false;
        }
        return true;
    }

    bool ResourceSectionParser::parseDataEntry(
        std::istream& s, uint32_t data, ResDataEntry* out)
    {
        auto prev_pos = s.tellg();
        if (!s.seekg(start_pos_ + std::streamoff(data))) {
            return false;
        }

        READ_STREAM_LE(out->data_rva, 4);
        READ_STREAM_LE(out->size, 4);
        READ_STREAM_LE(out->codepage, 4);

        if (!s.seekg(prev_pos)) {
            return false;
        }
        return true;
    }

}
}