// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_INTEL_INTEL_INSTRUCTION_PARSER_H_
#define DEXAR_INTEL_INTEL_INSTRUCTION_PARSER_H_

#include <cstdint>

#include "dexar/intel/code_segment.h"
#include "dexar/intel/intel_instruction_params.h"


namespace dexar {
namespace intel {

    class Instruction;

    class InstructionParser {
    public:
        InstructionParser() {}

        bool parse(CodeSegment csi, Instruction* info);

    private:
        bool walkOnOneByteOpcodeMap(CodeSegment csi, Instruction* info);
        bool walkOnTwoByteOpcodeMap(CodeSegment csi, Instruction* info);
        bool walkOnThreeByteOpcodeMap(CodeSegment csi, Instruction* info);
        bool walkOnCoprocessOpcodeMap(CodeSegment csi, Instruction* info);

        bool parseOneByte(CodeSegment csi, Prefix prefix, uint8_t byte1, Instruction* info);
        bool parseTwoByte(CodeSegment csi, Prefix prefix, uint8_t byte2, Instruction* info);
        bool parseThreeByte(CodeSegment csi, Prefix prefix, uint8_t byte2, uint8_t byte3, Instruction* info);

        bool parseAbbrs(
            CodeSegment csi, Prefix prefix, const std::string& abbrs, const std::string& ss, Instruction* info);
        bool parseAbbr(
            CodeSegment csi, Prefix prefix, const std::string& abbr, const std::string& ss, Instruction* info);
        bool parseModRMField(
            CodeSegment csi, Prefix prefix, uint8_t modrm, bool use_reg, ModRMField* field);
        bool parseSIBField(
            CodeSegment csi, Prefix prefix, uint8_t modrm, uint8_t sib, SIBField* field);

        uint32_t findImmeOffset(Instruction* info);

        struct ParsedItem {
            std::string name;
            std::string ss;
            std::string decorate;
            std::string operands;
        };

        bool parseTableItem(const std::string& item, ParsedItem* out);
    };

}
}

#endif  // DEXAR_INTEL_INTEL_INSTRUCTION_PARSER_H_