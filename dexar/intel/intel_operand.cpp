// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/intel_operand.h"


namespace dexar {
namespace intel {

    Operand::Operand()
        : use_modrm(false),
        disp(0),
        imme(0),
        disp_length(0),
        imme_length(0),
        operand_size(0),
        is_digit(false),
        digit(0),
        is_pointer(false),
        is_mem_pointer(false),
        pointer_length(0),
        pointer_seg(0),
        pointer_addr(0) {
    }

    // static
    Operand Operand::ofReg(const std::string& reg) {
        Operand op;
        op.reg = reg;
        return op;
    }

    // static
    Operand Operand::ofModRM(const ModRMField& mf, const SIBField& sf) {
        Operand op;
        op.use_modrm = true;
        op.modrm_field = mf;
        op.sib_field = sf;
        return op;
    }

    // static
    Operand Operand::ofDisp(uint64_t disp, uint32_t len) {
        Operand op;
        op.disp = disp;
        op.disp_length = len;
        return op;
    }

    // static
    Operand Operand::ofImme(uint64_t imme, uint32_t len) {
        Operand op;
        op.imme = imme;
        op.imme_length = len;
        return op;
    }

    // static
    Operand Operand::ofDigit(uint32_t digit) {
        Operand op;
        op.is_digit = true;
        op.digit = digit;
        return op;
    }

    // static
    Operand Operand::ofPointer(uint16_t seg, uint64_t addr, uint32_t len, bool mem) {
        Operand op;
        op.is_pointer = true;
        op.is_mem_pointer = mem;
        op.pointer_length = len;
        op.pointer_seg = seg;
        op.pointer_addr = addr;
        return op;
    }

}
}
