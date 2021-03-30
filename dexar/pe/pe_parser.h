// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_PE_PE_PARSER_H_
#define DEXAR_PE_PE_PARSER_H_

#include <istream>
#include <vector>

#include "dexar/pe/pe_data_types.h"


namespace dexar {
namespace pe {

    class PEParser {
    public:
        PEParser() = default;

        bool parse(std::istream& s);

        const CoffFileHeader& getCOFFHeader() const;
        const OptionalHeaderStd& getOptHeaderStd() const;
        const OptionalHeaderWin& getOptHeaderWin() const;
        const std::vector<SectionHeader>& getSectionHeaders() const;

    private:
        bool parseExportSection(std::istream& s);
        bool parseImportSection(std::istream& s);
        bool parseResourceSection(std::istream& s);

        std::string stub_;
        CoffFileHeader coff_header_;
        OptionalHeaderStd opt_header_std_;
        OptionalHeaderWin opt_header_win_;
        std::vector<ImageDataDirectory> data_dirs_;
        std::vector<SectionHeader> sections_;
    };

}
}

#endif  // DEXAR_PE_PE_PARSER_H_