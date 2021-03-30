// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "pe_parser.h"

#include "utils/stream_utils.h"

#include "sections/edata_section.h"
#include "sections/idata_section.h"
#include "sections/rsrc_section.h"


namespace dexar {
namespace pe {

    bool PEParser::parse(std::istream& s) {
        // MS-DOS Stub (Image Only)
        char stub_buf[kPEStubLength];
        READ_STREAM(stub_buf[0], kPEStubLength);
        stub_.append(stub_buf, kPEStubLength);

        // Signature offset
        uint32_t offset;
        READ_STREAM_LE(offset, 4);
        s.seekg(offset, std::ios::beg);
        if (!s) {
            return false;
        }

        // Signature (Image Only)
        uint32_t signature;
        READ_STREAM_LE(signature, 4);
        if (signature != kPESignature) {
            return false;
        }

        // COFF File Header (Object and Image)
        READ_STREAM_LE(coff_header_.machine, 2);
        READ_STREAM_LE(coff_header_.section_num, 2);
        READ_STREAM_LE(coff_header_.time_stamp, 4);
        READ_STREAM_LE(coff_header_.symbol_table_ptr, 4);
        READ_STREAM_LE(coff_header_.symbol_num, 4);
        READ_STREAM_LE(coff_header_.optional_header_size, 2);
        READ_STREAM_LE(coff_header_.chrs, 2);

        // Optional Header (Image Only)
        if (coff_header_.optional_header_size != 0) {
            // Standard fields
            READ_STREAM_LE(opt_header_std_.magic, 2);
            READ_STREAM(opt_header_std_.major_linker_ver, 1);
            READ_STREAM(opt_header_std_.minor_linker_ver, 1);
            READ_STREAM_LE(opt_header_std_.code_size, 4);
            READ_STREAM_LE(opt_header_std_.inited_data_size, 4);
            READ_STREAM_LE(opt_header_std_.uninited_data_size, 4);
            READ_STREAM_LE(opt_header_std_.ep_addr, 4);
            READ_STREAM_LE(opt_header_std_.code_base, 4);

            bool is_plus = opt_header_std_.magic == OptionalHeaderMagic::PE32Plus;
            if (!is_plus) {
                READ_STREAM_LE(opt_header_std_.data_base, 4);
            }

            // Windows-Specific fields
            if (is_plus) {
                READ_STREAM_LE(opt_header_win_.img_base, 8);
            } else {
                opt_header_win_.img_base = 0;
                READ_STREAM_MLLE(opt_header_win_.img_base, 4);
            }

            READ_STREAM_LE(opt_header_win_.section_align, 4);
            READ_STREAM_LE(opt_header_win_.file_align, 4);
            READ_STREAM_LE(opt_header_win_.major_os_ver, 2);
            READ_STREAM_LE(opt_header_win_.minor_os_ver, 2);
            READ_STREAM_LE(opt_header_win_.major_img_ver, 2);
            READ_STREAM_LE(opt_header_win_.minor_img_ver, 2);
            READ_STREAM_LE(opt_header_win_.major_sub_ver, 2);
            READ_STREAM_LE(opt_header_win_.minor_sub_ver, 2);
            READ_STREAM_LE(opt_header_win_.win32_ver_val, 4);
            READ_STREAM_LE(opt_header_win_.img_size, 4);
            READ_STREAM_LE(opt_header_win_.headers_size, 4);
            READ_STREAM_LE(opt_header_win_.check_sum, 4);
            READ_STREAM_LE(opt_header_win_.sub_system, 2);
            READ_STREAM_LE(opt_header_win_.dll_chrs, 2);

            if (is_plus) {
                READ_STREAM_LE(opt_header_win_.stack_reserve_size, 8);
                READ_STREAM_LE(opt_header_win_.stack_commit_size, 8);
                READ_STREAM_LE(opt_header_win_.heap_reserve_size, 8);
                READ_STREAM_LE(opt_header_win_.heap_commit_size, 8);
            } else {
                opt_header_win_.stack_reserve_size = 0;
                READ_STREAM_MLLE(opt_header_win_.stack_reserve_size, 4);

                opt_header_win_.stack_commit_size = 0;
                READ_STREAM_MLLE(opt_header_win_.stack_commit_size, 4);

                opt_header_win_.heap_reserve_size = 0;
                READ_STREAM_MLLE(opt_header_win_.heap_reserve_size, 4);

                opt_header_win_.heap_commit_size = 0;
                READ_STREAM_MLLE(opt_header_win_.heap_commit_size, 4);
            }

            READ_STREAM_LE(opt_header_win_.loader_flags, 4);
            READ_STREAM_LE(opt_header_win_.rva_and_sizes_num, 4);

            // 防止溢出
            if (opt_header_win_.rva_and_sizes_num > kPEDataDirectoryLimitSize) {
                opt_header_win_.rva_and_sizes_num = kPEDataDirectoryLimitSize;
            }

            // Data Directories
            for (uint32_t i = 0; i < opt_header_win_.rva_and_sizes_num; ++i) {
                ImageDataDirectory dir;
                READ_STREAM_LE(dir.rva, 4);
                READ_STREAM_LE(dir.size, 4);
                data_dirs_.push_back(std::move(dir));
            }
        }

        // Section Table (Section Headers)
        for (uint16_t i = 0; i < coff_header_.section_num; ++i) {
            SectionHeader header;
            READ_STREAM(header.name[0], 8);
            READ_STREAM_LE(header.virtual_size, 4);
            READ_STREAM_LE(header.virtual_addr, 4);
            READ_STREAM_LE(header.raw_data_size, 4);
            READ_STREAM_LE(header.raw_data_ptr, 4);
            READ_STREAM_LE(header.relocs_ptr, 4);
            READ_STREAM_LE(header.linenums_ptr, 4);
            READ_STREAM_LE(header.reloc_num, 2);
            READ_STREAM_LE(header.linenum_num, 2);
            READ_STREAM_LE(header.chrs, 4);
            sections_.push_back(std::move(header));
        }

        //parseImportSection(s);
        parseResourceSection(s);
        return true;
    }

    bool PEParser::parseExportSection(std::istream& s) {
        for (const auto& sec : sections_) {
            if (std::memcmp(sec.name, kExportSectionName, 8) == 0) {
                auto prev_pos = s.tellg();

                auto table_off = data_dirs_[0].rva - sec.virtual_addr;
                s.seekg(sec.raw_data_ptr + table_off);
                if (!s) {
                    s.seekg(prev_pos);
                    return false;
                }

                ExportSectionParser edata_parser;
                bool ret = edata_parser.parse(s, sec);
                s.seekg(prev_pos);
                return ret;
            }
        }
        return true;
    }

    bool PEParser::parseImportSection(std::istream& s) {
        for (const auto& sec : sections_) {
            if (std::memcmp(sec.name, kImportSectionName, 8) == 0) {
                auto prev_pos = s.tellg();

                auto table_off = data_dirs_[1].rva - sec.virtual_addr;
                s.seekg(sec.raw_data_ptr + table_off);
                if (!s) {
                    s.seekg(prev_pos);
                    return false;
                }

                ImportSectionParser idata_parser;
                bool ret = idata_parser.parse(
                    s, sec, opt_header_std_.magic == OptionalHeaderMagic::PE32Plus);
                s.seekg(prev_pos);
                return ret;
            }
        }
        return true;
    }

    bool PEParser::parseResourceSection(std::istream& s) {
        for (const auto& sec : sections_) {
            if (std::memcmp(sec.name, kResourceSectionName, 8) == 0) {
                auto prev_pos = s.tellg();

                auto table_off = data_dirs_[2].rva - sec.virtual_addr;
                s.seekg(sec.raw_data_ptr + table_off);
                if (!s) {
                    s.seekg(prev_pos);
                    return false;
                }

                ResourceSectionParser res_parser;
                std::unique_ptr<ResDirectoryTable> root;
                bool ret = res_parser.parse(s, &root);
                s.seekg(prev_pos);
                return ret;
            }
        }
        return true;
    }

    const CoffFileHeader& PEParser::getCOFFHeader() const {
        return coff_header_;
    }

    const OptionalHeaderStd& PEParser::getOptHeaderStd() const {
        return opt_header_std_;
    }

    const OptionalHeaderWin& PEParser::getOptHeaderWin() const {
        return opt_header_win_;
    }

    const std::vector<SectionHeader>& PEParser::getSectionHeaders() const {
        return sections_;
    }

}
}
