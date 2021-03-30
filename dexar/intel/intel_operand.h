// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_INTEL_INTEL_OPERAND_H_
#define DEXAR_INTEL_INTEL_OPERAND_H_

#include <cstdint>

#include "dexar/intel/intel_instruction_params.h"


namespace dexar {
namespace intel {

    class Operand {
    public:
        std::string reg;

        bool use_modrm;
        ModRMField modrm_field;
        SIBField sib_field;

        uint64_t disp;
        uint64_t imme;
        uint32_t disp_length;
        uint32_t imme_length;
        // 内存寻址时，访问的内存地址大小
        uint32_t operand_size;

        bool is_digit;
        uint32_t digit;

        // 立即数指针，16:16 16:32 16:64 这样子的
        bool is_pointer;
        bool is_mem_pointer;
        uint32_t pointer_length;
        uint16_t pointer_seg;
        uint64_t pointer_addr;

        Operand();

        static Operand ofReg(const std::string& reg);
        static Operand ofModRM(const ModRMField& mf, const SIBField& sf);
        static Operand ofDisp(uint64_t disp, uint32_t len);
        static Operand ofImme(uint64_t imme, uint32_t len);
        static Operand ofDigit(uint32_t digit);
        static Operand ofPointer(uint16_t seg, uint64_t addr, uint32_t len, bool mem);
    };

}
}

#endif  // DEXAR_INTEL_INTEL_OPERAND_H_