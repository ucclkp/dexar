// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_INTEL_INTEL_INSTRUCTION_H_
#define DEXAR_INTEL_INTEL_INSTRUCTION_H_

#include <cstdint>
#include <vector>

#include "dexar/intel/intel_prefix.h"
#include "dexar/intel/intel_operand.h"


namespace dexar {
namespace intel {

    class Instruction {
    public:
        Instruction();

        void reset();
        uint32_t length() const;
        std::string toString() const;

        Prefix prefix;
        std::string opcode;
        uint8_t opcode_bytes[3];
        uint32_t opcode_length;
        std::vector<Operand> operands;
        bool has_modrm;
        uint8_t modrm;
        bool has_sib;
        uint8_t sib;

    private:
        std::string getSignedDisp(uint64_t disp, uint32_t length, bool has_prefix) const;
        std::string getMemPtrInfo(uint32_t operand_size) const;
        std::string getSegmentReg(const std::string& def_reg) const;
    };

}
}

#endif  // DEXAR_INTEL_INTEL_INSTRUCTION_H_