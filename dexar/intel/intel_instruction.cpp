// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/intel_instruction.h"

#include "utils/strings/int_conv.hpp"


namespace dexar {
namespace intel {

    Instruction::Instruction()
        : opcode_bytes{},
          opcode_length(0),
          has_modrm(false),
          modrm(0),
          has_sib(false),
          sib(0) {}

    void Instruction::reset() {
        prefix.reset();
        opcode.clear();
        opcode_length = 0;
        operands.clear();
        has_modrm = false;
        modrm = 0;
        has_sib = false;
        sib = 0;
    }

    uint32_t Instruction::length() const {
        uint32_t off = prefix.length();
        off += opcode_length;
        if (has_modrm) { ++off; }
        if (has_sib) { ++off; }

        for (const auto& op : operands) {
            off += op.disp_length + op.imme_length + op.pointer_length
                + ((op.use_modrm && !op.modrm_field.is_reg) ? op.modrm_field.mrm_mem.disp_length : 0)
                + ((op.use_modrm && op.modrm_field.mrm_mem.has_sib) ? op.sib_field.sib_base.disp_length : 0);
        }

        return off;
    }

    std::string Instruction::toString() const {
        std::string result(opcode);
        if (prefix.g1) {
            if (prefix.g1 == 0xF0) result.append("LOCK ");
            if (prefix.g1 == 0xF2) result.append("REPNE ");
            if (prefix.g1 == 0xF3) result.append("REP ");
        }

        if (operands.empty()) {
            return result;
        }

        bool is_first = true;
        std::string cur_operand;
        for (const auto& op : operands) {
            if (op.is_digit) {
                cur_operand = utl::itos8(op.digit, 16);
            } else if (op.use_modrm) {
                if (op.modrm_field.is_reg) {
                    cur_operand = op.modrm_field.selected_reg;
                } else {
                    if (op.modrm_field.mrm_mem.has_sib) {
                        bool has_prefix = false;
                        auto& sib_base = op.sib_field.sib_base;
                        auto& sib_scale = op.sib_field.sib_scale;

                        if (op.operand_size != 0) {
                            cur_operand.append(getMemPtrInfo(op.operand_size));
                            cur_operand.append(" ");
                        }

                        if (!sib_base.seg_reg.empty()) {
                            cur_operand.append(getSegmentReg(sib_base.seg_reg));
                            cur_operand.append(":");
                        }

                        cur_operand.append("[");
                        if (!sib_base.reg.empty()) {
                            cur_operand.append(sib_base.reg);
                            has_prefix = true;
                        }
                        if (!sib_scale.reg.empty()) {
                            if (has_prefix) {
                                cur_operand.append("+");
                            }
                            cur_operand.append(sib_scale.reg)
                                .append("*").append(utl::itos8(sib_scale.scale, 16));
                            has_prefix = true;
                        }
                        if (sib_base.disp_length > 0) {
                            auto signed_disp = getSignedDisp(sib_base.disp, sib_base.disp_length, has_prefix);
                            cur_operand.append(signed_disp);
                        }
                        auto& mrm_mem = op.modrm_field.mrm_mem;
                        if (mrm_mem.disp_length > 0) {
                            auto signed_disp = getSignedDisp(mrm_mem.disp, mrm_mem.disp_length, has_prefix);
                            cur_operand.append(signed_disp);
                        }
                        cur_operand.append("]");
                    } else {
                        bool has_prefix = false;
                        auto& mrm_mem = op.modrm_field.mrm_mem;

                        if (op.operand_size != 0) {
                            cur_operand.append(getMemPtrInfo(op.operand_size));
                            cur_operand.append(" ");
                        }

                        if (!mrm_mem.seg_reg.empty()) {
                            cur_operand.append(getSegmentReg(mrm_mem.seg_reg));
                            cur_operand.append(":");
                        }

                        cur_operand.append("[");
                        if (!mrm_mem.idx1_reg.empty()) {
                            cur_operand.append(mrm_mem.idx1_reg);
                            has_prefix = true;
                        }
                        if (!mrm_mem.idx2_reg.empty()) {
                            if (has_prefix) {
                                cur_operand.append("+");
                            }
                            cur_operand.append(mrm_mem.idx2_reg);
                            has_prefix = true;
                        }
                        if (mrm_mem.disp_length > 0) {
                            auto signed_disp = getSignedDisp(mrm_mem.disp, mrm_mem.disp_length, has_prefix);
                            cur_operand.append(signed_disp);
                        }
                        cur_operand.append("]");
                    }
                }
            } else if (!op.reg.empty()) {
                cur_operand = op.reg;
            } else if (op.imme_length > 0) {
                cur_operand = getSignedDisp(op.imme, op.imme_length, false);
            } else if (op.disp_length > 0) {
                if (op.operand_size != 0) {
                    cur_operand.append(getMemPtrInfo(op.operand_size));
                    cur_operand.append(" ");
                }
                cur_operand.append(getSegmentReg("DS"));
                cur_operand.append(":");
                cur_operand.append("[");
                cur_operand.append(utl::itos8(op.disp, 16));
                cur_operand.append("]");
            } else if (op.is_pointer) {
                if (op.is_mem_pointer) {
                    cur_operand.append(utl::itos8(op.pointer_seg, 16));
                    cur_operand.append(":");
                    cur_operand.append("[");
                    cur_operand.append(utl::itos8(op.pointer_addr, 16));
                    cur_operand.append("]");
                } else {
                    cur_operand.append(utl::itos8(op.pointer_seg, 16));
                    cur_operand.append(":");
                    cur_operand.append(utl::itos8(op.pointer_addr, 16));
                }
            }

            if (cur_operand.empty()) {
                cur_operand = "ERR";
            }
            if (is_first) {
                is_first = false;
                result += " ";
            } else {
                result += ", ";
            }
            result += cur_operand;
            cur_operand.clear();
        }

        return result;
    }

    std::string Instruction::getSignedDisp(uint64_t disp, uint32_t length, bool has_prefix) const {
        std::string result;
        if (length == 1) {
            if (!(disp & 0x80)) {
                if (has_prefix) result.append("+");
                result.append(utl::itos8(disp, 16));
            } else {
                result.append("-");
                result.append(utl::itos8(0xFFU - disp + 1U, 16));
            }
            return result;
        }
        if (length == 2) {
            if (!(disp & 0x8000)) {
                if (has_prefix) result.append("+");
                result.append(utl::itos8(disp, 16));
            } else {
                result.append("-");
                result.append(utl::itos8(0xFFFFU - disp + 1U, 16));
            }
            return result;
        }
        if (length == 4) {
            if (!(disp & 0x80000000)) {
                if (has_prefix) result.append("+");
                result.append(utl::itos8(disp, 16));
            } else {
                result.append("-");
                result.append(utl::itos8(0xFFFFFFFFU - disp + 1U, 16));
            }
            return result;
        }
        if (length == 8) {
            if (!(disp & 0x8000000000000000)) {
                if (has_prefix) result.append("+");
                result.append(utl::itos8(disp, 16));
            } else {
                result.append("-");
                result.append(utl::itos8(0xFFFFFFFFFFFFFFFFU - disp + 1U, 16));
            }
            return result;
        }
        return "ERR";
    }

    std::string Instruction::getMemPtrInfo(uint32_t operand_size) const {
        if (operand_size == 0) {
            return "";
        }
        if (operand_size == 1) {
            return "byte ptr";
        }
        if (operand_size == 2) {
            return "word ptr";
        }
        if (operand_size == 4) {
            return "dword ptr";
        }
        if (operand_size == 8) {
            return "qword ptr";
        }
        return "ERR";
    }

    std::string Instruction::getSegmentReg(const std::string& def_reg) const {
        // TODO: Jcc
        if (prefix.g2) {
            if (prefix.g2 == 0x2E) return "CS";
            if (prefix.g2 == 0x36) return "SS";
            if (prefix.g2 == 0x3E) return "DS";
            if (prefix.g2 == 0x26) return "ES";
            if (prefix.g2 == 0x64) return "FS";
            if (prefix.g2 == 0x65) return "GS";
        }
        return def_reg;
    }

}
}
