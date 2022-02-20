// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/intel_instruction_parser.h"

#include "utils/log.h"
#include "utils/strings/string_utils.hpp"

#include "dexar/intel/intel_opcode_map.h"
#include "dexar/intel/intel_instruction.h"


#define RETURN_FAILED_IF(x) \
    if (x) {                \
        ubassert(false);      \
        return false;       \
    }


namespace dexar {
namespace intel {

    bool InstructionParser::parse(CodeSegment csi, Instruction* info) {
        RETURN_FAILED_IF(!info);
        return walkOnOneByteOpcodeMap(csi, info);
    }

    bool InstructionParser::walkOnOneByteOpcodeMap(CodeSegment csi, Instruction* info) {
        auto cur_bytecode = csi.getCur8();

        if (cur_bytecode == 0x26 ||
            cur_bytecode == 0x36 ||
            cur_bytecode == 0x2E ||
            cur_bytecode == 0x3E ||
            cur_bytecode == 0x64 ||
            cur_bytecode == 0x65)
        {
            // Prefix
            RETURN_FAILED_IF(info->prefix.g2 != 0);
            info->prefix.g2 = cur_bytecode;
            return walkOnOneByteOpcodeMap(csi + 1, info);
        }

        if (cur_bytecode == 0xF0) {
            // Prefix
            RETURN_FAILED_IF(info->prefix.g1 != 0);
            info->prefix.g1 = cur_bytecode;
            return walkOnOneByteOpcodeMap(csi + 1, info);
        }

        if (cur_bytecode == 0x67) {
            // Prefix
            RETURN_FAILED_IF(info->prefix.g4 != 0);
            info->prefix.g4 = cur_bytecode;
            return walkOnOneByteOpcodeMap(csi + 1, info);
        }

        if (csi.env.cpu_mode == CPUMode::_64Bit) {
            // REX prefix
            if (cur_bytecode >= 0x40 && cur_bytecode <= 0x4F) {
                RETURN_FAILED_IF(info->prefix.rex != 0);
                RETURN_FAILED_IF(info->prefix.vex_length != 0);
                info->prefix.rex = cur_bytecode;
                return walkOnOneByteOpcodeMap(csi + 1, info);
            }

            // VEX prefix
            if (cur_bytecode >= 0xC4 && cur_bytecode <= 0xC5 && (csi.get8(csi.cur + 1) & 0x80)) {
                if (cur_bytecode == 0xC4) {
                    info->prefix.vex_length = 3;
                    info->prefix.vex[0] = csi.get8(csi.cur + 1);
                    info->prefix.vex[1] = csi.get8(csi.cur + 2);
                    info->prefix.vex[2] = csi.get8(csi.cur + 3);
                } else {
                    info->prefix.vex_length = 2;
                    info->prefix.vex[0] = csi.get8(csi.cur + 1);
                    info->prefix.vex[1] = csi.get8(csi.cur + 2);
                }

                return walkOnOneByteOpcodeMap(csi + info->prefix.vex_length + 1, info);
            }
        }

        if (cur_bytecode == 0x66 ||
            cur_bytecode == 0xF2 ||
            cur_bytecode == 0xF3)
        {
            // Prefix
            if (csi.get8(csi.cur + 1) == 0x0F) {
                RETURN_FAILED_IF(info->prefix.mand != 0);
                info->prefix.mand = cur_bytecode;
                return walkOnTwoByteOpcodeMap(csi + 2, info);
            }

            if (csi.env.cpu_mode == CPUMode::_64Bit) {
                uint8_t next_opcode = csi.get8(csi.cur + 1);
                // REX prefix
                if (next_opcode >= 0x40 && next_opcode <= 0x4F) {
                    if (csi.get8(csi.cur + 2) == 0x0F) {
                        RETURN_FAILED_IF(info->prefix.mand != 0);
                        info->prefix.mand = cur_bytecode;
                        RETURN_FAILED_IF(info->prefix.rex != 0);
                        RETURN_FAILED_IF(info->prefix.vex_length != 0);
                        info->prefix.rex = next_opcode;
                        return walkOnTwoByteOpcodeMap(csi + 3, info);
                    }
                }

                // VEX prefix
                if (next_opcode >= 0xC4 && next_opcode <= 0xC5 && (csi.get8(csi.cur + 2) & 0x80)) {
                    if (cur_bytecode == 0xC4) {
                        info->prefix.vex_length = 3;
                        info->prefix.vex[0] = csi.get8(csi.cur + 2);
                        info->prefix.vex[1] = csi.get8(csi.cur + 3);
                        info->prefix.vex[2] = csi.get8(csi.cur + 4);
                    } else {
                        info->prefix.vex_length = 2;
                        info->prefix.vex[0] = csi.get8(csi.cur + 2);
                        info->prefix.vex[1] = csi.get8(csi.cur + 3);
                    }

                    return walkOnTwoByteOpcodeMap(csi + info->prefix.vex_length + 2, info);
                }
            }

            if (cur_bytecode == 0xF2 ||
                cur_bytecode == 0xF3)
            {
                RETURN_FAILED_IF(info->prefix.g1 != 0);
                info->prefix.g1 = cur_bytecode;
                return walkOnOneByteOpcodeMap(csi + 1, info);
            }

            if (cur_bytecode == 0x66) {
                RETURN_FAILED_IF(info->prefix.g3 != 0);
                info->prefix.g3 = cur_bytecode;
                return walkOnOneByteOpcodeMap(csi + 1, info);
            }
        }

        if (cur_bytecode == 0x0F) {
            return walkOnTwoByteOpcodeMap(csi + 1, info);
        }

        if (cur_bytecode >= 0xD8 && cur_bytecode <= 0xDF) {
            return walkOnCoprocessOpcodeMap(csi, info);
        }

        return parseOneByte(csi, info->prefix, cur_bytecode, info);
    }

    bool InstructionParser::walkOnTwoByteOpcodeMap(CodeSegment csi, Instruction* info) {
        auto cur_bytecode = csi.getCur8();

        if (cur_bytecode == 0x38 || cur_bytecode == 0x3A) {
            return walkOnThreeByteOpcodeMap(csi + 1, info);
        }

        return parseTwoByte(csi, info->prefix, cur_bytecode, info);
    }

    bool InstructionParser::walkOnThreeByteOpcodeMap(CodeSegment csi, Instruction* info) {
        auto cur_bytecode = csi.getCur8();
        return parseThreeByte(csi, info->prefix, csi.get8(csi.cur - 1), cur_bytecode, info);
    }

    bool InstructionParser::walkOnCoprocessOpcodeMap(CodeSegment csi, Instruction* info) {
        ubassert(false);
        return false;
    }

    bool InstructionParser::parseOneByte(CodeSegment csi, Prefix prefix, uint8_t byte1, Instruction* info) {
        RETURN_FAILED_IF(prefix.mand != 0);

        info->opcode_length = 1;
        info->opcode_bytes[0] = byte1;

        uint8_t row = byte1 >> 4;
        uint8_t col = byte1 & 0x0F;

        auto mne_func = op_1_map[row][col];
        if (!mne_func) {
            ubassert(false);
            return false;
        }

        auto mne = mne_func(csi.env, prefix, SelConfig());
        if (mne.is_escape || mne.is_prefix || mne.is_undefined) {
            ubassert(false);
            return false;
        }

        if (mne.is_extended) {
            auto ext_func = ext_op_map[mne.ext_group];
            if (!ext_func) {
                ubassert(false);
                return false;
            }

            info->has_modrm = true;
            auto modrm = csi.get8(csi.cur + 1);

            auto tail = mne.ext_tail;
            mne = ext_func(csi.env, prefix, modrm, byte1, SelConfig());
            if (mne.is_escape || mne.is_prefix || mne.is_extended || mne.is_undefined) {
                ubassert(false);
                return false;
            }

            if (!tail.empty() && tail.at(0)=='[') {
                mne.mnemonics += tail;
            } else {
                if (mne.mnemonics.find(" ") != std::string::npos && !tail.empty()) {
                    mne.mnemonics += "," + tail;
                } else {
                    mne.mnemonics += " " + tail;
                }
            }
        }

        ParsedItem item;
        if (!parseTableItem(mne.mnemonics, &item)) {
            ubassert(false);
            return false;
        }

        if (item.name.empty()) {
            ubassert(false);
            return false;
        }

        info->opcode = item.name;

        if (!parseAbbrs(csi, prefix, item.operands, item.ss, info)) {
            ubassert(false);
            return false;
        }

        return true;
    }

    bool InstructionParser::parseTwoByte(CodeSegment csi, Prefix prefix, uint8_t byte2, Instruction* info) {
        info->opcode_length = 2;
        info->opcode_bytes[0] = 0x0F;
        info->opcode_bytes[1] = byte2;

        uint8_t row = byte2 >> 4;
        uint8_t col = byte2 & 0x0F;

        auto mne_func = op_2_map[row][col];
        if (!mne_func) {
            ubassert(false);
            return false;
        }

        auto mne = mne_func(csi.env, prefix, SelConfig());
        if (mne.is_escape || mne.is_prefix || mne.is_undefined) {
            ubassert(false);
            return false;
        }

        if (mne.is_extended) {
            auto ext_func = ext_op_map[mne.ext_group];
            if (!ext_func) {
                ubassert(false);
                return false;
            }

            info->has_modrm = true;
            auto modrm = csi.get8(csi.cur + 1);

            auto tail = mne.ext_tail;
            mne = ext_func(csi.env, prefix, modrm, byte2, SelConfig());
            if (mne.is_escape || mne.is_prefix || mne.is_extended || mne.is_undefined) {
                ubassert(false);
                return false;
            }

            if (!tail.empty() && tail.at(0) == '[') {
                mne.mnemonics += tail;
            } else {
                mne.mnemonics += " " + tail;
            }
        }

        ParsedItem item;
        if (!parseTableItem(mne.mnemonics, &item)) {
            ubassert(false);
            return false;
        }

        if (item.name.empty()) {
            ubassert(false);
            return false;
        }

        info->opcode = item.name;
        if (!parseAbbrs(csi, prefix, item.operands, item.ss, info)) {
            ubassert(false);
            return false;
        }

        return true;
    }

    bool InstructionParser::parseThreeByte(
        CodeSegment csi, Prefix prefix, uint8_t byte2, uint8_t byte3, Instruction* info)
    {
        info->opcode_length = 3;
        info->opcode_bytes[0] = 0x0F;
        info->opcode_bytes[1] = byte2;
        info->opcode_bytes[2] = byte3;

        uint8_t row = byte3 >> 4;
        uint8_t col = byte3 & 0x0F;

        OpcodeHandler mne_func;
        if (byte2 == 0x38) {
            mne_func = op_38H_map[row][col];
        } else if (byte2 == 0x3A) {
            mne_func = op_3AH_map[row][col];
        }

        if (!mne_func) {
            ubassert(false);
            return false;
        }

        auto mne = mne_func(csi.env, prefix, SelConfig());
        if (mne.is_escape || mne.is_prefix || mne.is_undefined) {
            ubassert(false);
            return false;
        }

        if (mne.is_extended) {
            auto ext_func = ext_op_map[mne.ext_group];
            if (!ext_func) {
                ubassert(false);
                return false;
            }

            info->has_modrm = true;
            auto modrm = csi.get8(csi.cur + 1);

            auto tail = mne.ext_tail;
            mne = ext_func(csi.env, prefix, modrm, byte3, SelConfig());
            if (mne.is_escape || mne.is_prefix || mne.is_extended || mne.is_undefined) {
                ubassert(false);
                return false;
            }

            if (!tail.empty() && tail.at(0) == '[') {
                mne.mnemonics += tail;
            } else {
                mne.mnemonics += " " + tail;
            }
        }

        ParsedItem item;
        if (!parseTableItem(mne.mnemonics, &item)) {
            ubassert(false);
            return false;
        }

        if (item.name.empty()) {
            ubassert(false);
            return false;
        }

        info->opcode = item.name;
        if (!parseAbbrs(csi, prefix, item.operands, item.ss, info)) {
            ubassert(false);
            return false;
        }

        return true;
    }

    bool InstructionParser::parseAbbrs(
        CodeSegment csi, Prefix prefix, const std::string& abbrs, const std::string& ss, Instruction* info)
    {
        if (abbrs.empty()) {
            return true;
        }

        auto abbr_vec = utl::split(abbrs, ",");
        for (auto& abbr : abbr_vec) {
            utl::trim(&abbr, utl::TRF_ALL);
            if (!parseAbbr(csi, prefix, abbr, ss, info)) {
                ubassert(false);
                return false;
            }
        }

        return true;
    }

    bool InstructionParser::parseAbbr(
        CodeSegment csi, Prefix prefix, const std::string& abbr, const std::string& ss, Instruction* info)
    {
        if (abbr.length() >= 2) {
            auto reg = abbr.substr(0, 2);
            if (reg == "AL" || reg == "CL" || reg == "DL" || reg == "BL" ||
                reg == "AH" || reg == "CH" || reg == "DH" || reg == "BH" ||
                reg == "AX" || reg == "CX" || reg == "DX" || reg == "BX" ||
                reg == "CS" || reg == "DS" || reg == "ES" || reg == "SS")
            {
                info->operands.push_back(Operand::ofReg(abbr));
                return true;
            }

            if (reg[0] == 'R' && reg[1] >= '0' && reg[1] <= '9') {
                info->operands.push_back(Operand::ofReg(abbr));
                return true;
            }
        }

        if (abbr.length() >= 3) {
            if (abbr.substr(0, 1) == "e") {
                uint32_t operand_size;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    operand_size = selectOperandSize64(ss, prefix);
                } else {
                    operand_size = selectOperandSize(csi.env.d, prefix);
                }

                if (operand_size == 2) {
                    info->operands.push_back(Operand::ofReg(abbr.substr(1)));
                    return true;
                }
                if (operand_size == 4) {
                    std::string reg("E");
                    reg += abbr.substr(1);
                    info->operands.push_back(Operand::ofReg(reg));
                    return true;
                }
                return false;
            }

            if (abbr.substr(0, 1) == "r") {
                uint32_t operand_size;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    operand_size = selectOperandSize64(ss, prefix);
                } else {
                    operand_size = selectOperandSize(csi.env.d, prefix);
                }

                if (operand_size == 2) {
                    info->operands.push_back(Operand::ofReg(abbr.substr(1)));
                    return true;
                }
                if (operand_size == 4) {
                    std::string reg("E");
                    reg += abbr.substr(1);
                    info->operands.push_back(Operand::ofReg(reg));
                    return true;
                }
                if (operand_size == 8) {
                    std::string reg("R");
                    reg += abbr.substr(1);
                    info->operands.push_back(Operand::ofReg(reg));
                    return true;
                }
                return false;
            }
        }

        if (abbr == "1") {
            info->operands.push_back(Operand::ofDigit(1));
            return true;
        }

        if (abbr == "3") {
            info->operands.push_back(Operand::ofDigit(3));
            return true;
        }

        std::string addr_mode;
        std::string oper_type;
        if (abbr.length() < 2) {
            RETURN_FAILED_IF(abbr.empty());
            addr_mode = abbr;
        } else {
            addr_mode = abbr.substr(0, 1);
            oper_type = abbr.substr(1, abbr.size() - 1);
        }

        if (addr_mode == "A") {
            // **direct address, no mrm, no sib
            if (oper_type == "p") {
                uint32_t op_size;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    op_size = selectOperandSize64(ss, prefix);
                } else {
                    op_size = selectOperandSize(csi.env.d, prefix);
                }
                if (op_size == 2) {
                    info->operands.push_back(
                        Operand::ofPointer(csi.get16(csi.cur + 3), csi.get16(csi.cur + 1), 4, false));
                    return true;
                }
                if (op_size == 4) {
                    info->operands.push_back(
                        Operand::ofPointer(csi.get16(csi.cur + 5), csi.get32(csi.cur + 1), 6, false));
                    return true;
                }
                if (op_size == 8) {
                    info->operands.push_back(
                        Operand::ofPointer(csi.get16(csi.cur + 9), csi.get64(csi.cur + 1), 10, false));
                    return true;
                }
            }
        } else if (addr_mode == "B") {
            // **VEX prefix
        } else if (addr_mode == "C") {
            // **reg
        } else if (addr_mode == "D") {

        } else if (addr_mode == "E") {
            info->has_modrm = true;
            ModRMField m_field;
            auto mrm = csi.get8(csi.cur + 1);
            info->modrm = mrm;
            if (!parseModRMField(csi, prefix, mrm, false, &m_field)) {
                ubassert(false);
                return false;
            }

            if (m_field.is_reg) {
                if (oper_type == "b") {
                    m_field.selected_reg = m_field.mrm_reg.b_reg;
                    info->operands.push_back(Operand::ofModRM(m_field, {}));
                    return true;
                }
                if (oper_type == "w") {
                    m_field.selected_reg = m_field.mrm_reg.w_reg;
                    info->operands.push_back(Operand::ofModRM(m_field, {}));
                    return true;
                }
                if (oper_type == "v") {
                    if (csi.env.cpu_mode == CPUMode::_64Bit) {
                        auto op_size = selectOperandSize64(ss, prefix);
                        if (op_size == 2) {
                            m_field.selected_reg = m_field.mrm_reg.w_reg;
                            info->operands.push_back(Operand::ofModRM(m_field, {}));
                            return true;
                        }
                        if (op_size == 4) {
                            m_field.selected_reg = m_field.mrm_reg.dw_reg;
                            info->operands.push_back(Operand::ofModRM(m_field, {}));
                            return true;
                        }
                        if (op_size == 8) {
                            ubassert(false);
                            return false;
                        }
                    } else {
                        auto op_size = selectOperandSize(csi.env.d, prefix);
                        if (op_size == 2) {
                            m_field.selected_reg = m_field.mrm_reg.w_reg;
                            info->operands.push_back(Operand::ofModRM(m_field, {}));
                            return true;
                        }
                        if (op_size == 4) {
                            m_field.selected_reg = m_field.mrm_reg.dw_reg;
                            info->operands.push_back(Operand::ofModRM(m_field, {}));
                            return true;
                        }
                    }
                }
            } else {
                Operand operand;
                if (m_field.mrm_mem.has_sib) {
                    info->has_sib = true;
                    SIBField s_field;
                    auto sib = csi.get8(csi.cur + 2);
                    info->sib = sib;
                    if (!parseSIBField(csi, prefix, mrm, sib, &s_field)) {
                        ubassert(false);
                        return false;
                    }
                    operand = Operand::ofModRM(m_field, s_field);
                } else {
                    operand = Operand::ofModRM(m_field, {});
                }

                if (oper_type == "b") {
                    operand.operand_size = 1;
                    info->operands.push_back(operand);
                    return true;
                }
                if (oper_type == "w") {
                    operand.operand_size = 2;
                    info->operands.push_back(operand);
                    return true;
                }
                if (oper_type == "v") {
                    operand.operand_size =
                        (csi.env.cpu_mode == CPUMode::_64Bit ?
                            selectOperandSize64(ss, prefix) : selectOperandSize(csi.env.d, prefix));
                    info->operands.push_back(operand);
                    return true;
                }
            }
        } else if (addr_mode == "F") {
            if (oper_type == "v") {
                uint32_t op_size;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    op_size = selectOperandSize64(ss, prefix);
                } else {
                    op_size = selectOperandSize(csi.env.d, prefix);
                }
                if (op_size == 2 || op_size == 4) {
                    info->operands.push_back(Operand::ofReg("EFLAGS"));
                    return true;
                }
                if (op_size == 8) {
                    info->operands.push_back(Operand::ofReg("RFLAGS"));
                    return true;
                }
            }
        } else if (addr_mode == "G") {
            info->has_modrm = true;
            ModRMField m_field;
            auto mrm = csi.get8(csi.cur + 1);
            info->modrm = mrm;
            if (!parseModRMField(csi, prefix, mrm, true, &m_field)) {
                ubassert(false);
                return false;
            }

            if (oper_type == "b") {
                m_field.selected_reg = m_field.mrm_reg.b_reg;
                info->operands.push_back(Operand::ofModRM(m_field, {}));
                return true;
            }

            if (oper_type == "v") {
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    auto op_size = selectOperandSize64(ss, prefix);
                    if (op_size == 2) {
                        m_field.selected_reg = m_field.mrm_reg.w_reg;
                        info->operands.push_back(Operand::ofModRM(m_field, {}));
                        return true;
                    }
                    if (op_size == 4) {
                        m_field.selected_reg = m_field.mrm_reg.dw_reg;
                        info->operands.push_back(Operand::ofModRM(m_field, {}));
                        return true;
                    }
                    if (op_size == 8) {
                        ubassert(false);
                        return false;
                    }
                } else {
                    auto op_size = selectOperandSize(csi.env.d, prefix);
                    if (op_size == 2) {
                        m_field.selected_reg = m_field.mrm_reg.w_reg;
                        info->operands.push_back(Operand::ofModRM(m_field, {}));
                        return true;
                    }
                    if (op_size == 4) {
                        m_field.selected_reg = m_field.mrm_reg.dw_reg;
                        info->operands.push_back(Operand::ofModRM(m_field, {}));
                        return true;
                    }
                }
            }
        } else if (addr_mode == "H") {

        } else if (addr_mode == "I") {
            auto imme_off = findImmeOffset(info);

            if (oper_type == "b") {
                info->operands.push_back(Operand::ofImme(csi.get8(csi.cur + imme_off), 1));
                return true;
            }

            if (oper_type == "z") {
                uint32_t op_size;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    op_size = selectOperandSize64(ss, prefix);
                } else {
                    op_size = selectOperandSize(csi.env.d, prefix);
                }

                if (op_size == 2) {
                    info->operands.push_back(Operand::ofImme(csi.get16(csi.cur + imme_off), 2));
                    return true;
                }
                if (op_size == 4 || op_size == 8) {
                    info->operands.push_back(Operand::ofImme(csi.get32(csi.cur + imme_off), 4));
                    return true;
                }
            }

            if (oper_type == "v") {
                uint32_t op_size;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    op_size = selectOperandSize64(ss, prefix);
                } else {
                    op_size = selectOperandSize(csi.env.d, prefix);
                }

                if (op_size == 2) {
                    info->operands.push_back(Operand::ofImme(csi.get16(csi.cur + imme_off), 2));
                    return true;
                }
                if (op_size == 4) {
                    info->operands.push_back(Operand::ofImme(csi.get32(csi.cur + imme_off), 4));
                    return true;
                }
                if (op_size == 8) {
                    info->operands.push_back(Operand::ofImme(csi.get64(csi.cur + imme_off), 8));
                    return true;
                }
            }

            if (oper_type == "w") {
                info->operands.push_back(Operand::ofImme(csi.get16(csi.cur + imme_off), 2));
                return true;
            }
        } else if (addr_mode == "J") {
            if (oper_type == "b") {
                auto imme_off = findImmeOffset(info);
                info->operands.push_back(Operand::ofImme(csi.get8(csi.cur + imme_off), 1));
                return true;
            }

            if (oper_type == "z") {
                uint32_t op_size;
                auto imme_off = findImmeOffset(info);
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    op_size = selectOperandSize64(ss, prefix);
                } else {
                    op_size = selectOperandSize(csi.env.d, prefix);
                }

                if (op_size == 2) {
                    info->operands.push_back(Operand::ofImme(csi.get16(csi.cur + imme_off), 2));
                    return true;
                }
                if (op_size == 4 || op_size == 8) {
                    info->operands.push_back(Operand::ofImme(csi.get32(csi.cur + imme_off), 4));
                    return true;
                }
            }
        } else if (addr_mode == "M") {
            int off = 1;
            info->has_modrm = true;
            ModRMField m_field;
            auto mrm = csi.get8(csi.cur + 1);
            info->modrm = mrm;
            if (!parseModRMField(csi, prefix, mrm, false, &m_field)) {
                ubassert(false);
                return false;
            }
            ubassert(!m_field.is_reg);
            Operand operand;
            if (m_field.mrm_mem.has_sib) {
                ++off;
                info->has_sib = true;
                SIBField s_field;
                auto sib = csi.get8(csi.cur + 2);
                info->sib = sib;
                if (!parseSIBField(csi, prefix, mrm, sib, &s_field)) {
                    ubassert(false);
                    return false;
                }
                operand = Operand::ofModRM(m_field, s_field);
            } else {
                operand = Operand::ofModRM(m_field, {});
            }

            if (oper_type == "") {
                operand.operand_size = 0;
                info->operands.push_back(operand);
                return true;
            }
            if (oper_type == "a") {
                // 只有 BOUND 指令使用
                operand.operand_size = selectOperandSize(csi.env.d, prefix);
                info->operands.push_back(operand);
                return true;
            }
            if (oper_type == "p") {
                uint32_t op_size;
                operand.operand_size = 0;
                if (csi.env.cpu_mode == CPUMode::_64Bit) {
                    op_size = selectOperandSize64(ss, prefix);
                } else {
                    op_size = selectOperandSize(csi.env.d, prefix);
                }
                if (op_size == 2) {
                    info->operands.push_back(
                        Operand::ofPointer(csi.get16(csi.cur + off + 2), csi.get16(csi.cur + off), 4, true));
                    return true;
                }
                if (op_size == 4) {
                    info->operands.push_back(
                        Operand::ofPointer(csi.get16(csi.cur + off + 4), csi.get32(csi.cur + off), 6, true));
                    return true;
                }
                if (op_size == 8) {
                    info->operands.push_back(
                        Operand::ofPointer(csi.get16(csi.cur + off + 8), csi.get64(csi.cur + off), 10, true));
                    return true;
                }
            }
        } else if (addr_mode == "N") {

        } else if (addr_mode == "O") {
            auto addr_size = selectAddressSize(csi.env.d, prefix);
            Operand operand;
            if (addr_size == 2) {
                operand = Operand::ofDisp(csi.get16(csi.cur + 1), 2);
            } else if (addr_size == 4) {
                operand = Operand::ofDisp(csi.get32(csi.cur + 1), 4);
            } else if (addr_size == 8) {
                operand = Operand::ofDisp(csi.get64(csi.cur + 1), 8);
            } else {
                return false;
            }

            if (oper_type == "b") {
                operand.operand_size = 1;
                info->operands.push_back(operand);
                return true;
            }
            if (oper_type == "v") {
                operand.operand_size =
                    (csi.env.cpu_mode == CPUMode::_64Bit ?
                        selectOperandSize64(ss, prefix) : selectOperandSize(csi.env.d, prefix));
                info->operands.push_back(operand);
                return true;
            }
        } else if (addr_mode == "P") {

        } else if (addr_mode == "Q") {

        } else if (addr_mode == "R") {

        } else if (addr_mode == "S") {
            info->has_modrm = true;
            ModRMField m_field;
            auto mrm = csi.get8(csi.cur + 1);
            info->modrm = mrm;
            uint8_t ro = (mrm >> 3) & 0x7;
            if (oper_type == "w") {
                switch (ro) {
                case 0: info->operands.push_back(Operand::ofReg("ES")); break;
                case 1: info->operands.push_back(Operand::ofReg("CS")); break;
                case 2: info->operands.push_back(Operand::ofReg("SS")); break;
                case 3: info->operands.push_back(Operand::ofReg("DS")); break;
                case 4: info->operands.push_back(Operand::ofReg("FS")); break;
                case 5: info->operands.push_back(Operand::ofReg("GS")); break;
                default: return false;
                }
                return true;
            }
        } else if (addr_mode == "U") {

        } else if (addr_mode == "V") {

        } else if (addr_mode == "W") {

        } else if (addr_mode == "X") {

        } else if (addr_mode == "Y") {

        } else {
            ubassert(false);
        }

        ubassert(false);
        return false;
    }

    bool InstructionParser::parseModRMField(
        CodeSegment csi, Prefix prefix, uint8_t modrm, bool use_reg, ModRMField* field)
    {
        uint8_t rm = modrm & 0x7;
        uint8_t ro = (modrm >> 3) & 0x7;
        uint8_t mod = modrm >> 6;

        if (use_reg || mod == 0x3) {
            if (prefix.rex != 0 && csi.env.cpu_mode == CPUMode::_64Bit) {
                ro |= ((prefix.rex & 0x4) << 3);
            }

            field->is_reg = true;
            field->mrm_reg = modrm_reg_map[use_reg ? ro : rm](csi.env);
        } else {
            field->is_reg = false;
            field->mrm_mem = modrm_mem_map[mod][rm](csi.env);

            if (prefix.rex != 0 &&
                csi.env.cpu_mode == CPUMode::_64Bit &&
                !field->mrm_mem.has_sib)
            {
                uint8_t rexb = (prefix.rex & 0x1);
                if (rexb != 0) {
                    rm |= (rexb << 3);
                    field->mrm_mem = modrm_mem_map[mod][rm](csi.env);
                }
            }

            uint32_t disp_offset = field->mrm_mem.has_sib ? 3 : 2;
            switch (field->mrm_mem.disp_length) {
            case 0:
                break;
            case 1:
                field->mrm_mem.disp = csi.get8(csi.cur + disp_offset);
                break;
            case 2:
                field->mrm_mem.disp = csi.get16(csi.cur + disp_offset);
                break;
            case 4:
                field->mrm_mem.disp = csi.get32(csi.cur + disp_offset);
                break;
            default:
                ubassert(false);
                return false;
            }
        }

        return true;
    }

    bool InstructionParser::parseSIBField(
        CodeSegment csi, Prefix prefix, uint8_t modrm, uint8_t sib, SIBField* field)
    {
        uint8_t base = sib & 0x7;
        uint8_t index = (sib >> 3) & 0x7;
        uint8_t scale = sib >> 6;

        if (prefix.rex != 0 && csi.env.cpu_mode == CPUMode::_64Bit) {
            base |= ((prefix.rex & 0x1) << 3);
            index |= ((prefix.rex & 0x2) << 3);
        }

        field->sib_scale = sib_scale_map[scale][index](csi.env);
        field->sib_base = sib_base_map[base](csi.env, modrm);

        switch (field->sib_base.disp_length) {
        case 0:
            break;
        case 1:
            field->sib_base.disp = csi.get8(csi.cur + 3);
            break;
        case 2:
            field->sib_base.disp = csi.get16(csi.cur + 3);
            break;
        case 4:
            field->sib_base.disp = csi.get32(csi.cur + 3);
            break;
        default:
            ubassert(false);
            return false;
        }

        return true;
    }

    uint32_t InstructionParser::findImmeOffset(Instruction* info) {
        uint32_t offset = 0;
        if (info->has_modrm) { ++offset; }
        if (info->has_sib) { ++offset; }

        for (const auto& op : info->operands) {
            offset += op.disp_length + op.imme_length
                + op.pointer_length
                + op.modrm_field.mrm_mem.disp_length
                + op.sib_field.sib_base.disp_length;
        }

        return offset + 1;
    }

    bool InstructionParser::parseTableItem(const std::string& item, ParsedItem* out) {
        std::string str(item);
        utl::trim(&str);
        auto split_idx = str.find(" ");

        std::string mnes, abbrs;
        if (split_idx == std::string::npos) {
            mnes = str;
        } else {
            mnes = str.substr(0, split_idx);
            abbrs = str.substr(split_idx + 1, str.length() - split_idx);
            utl::trim(&abbrs, true);
        }

        bool bracket = false;
        bool parenthesis = false;
        bool step_on_mne = true;
        std::string cur_mne;
        std::string cur_ss;
        std::string cur_decorate;
        for (std::string::size_type i = 0; i < mnes.length(); ++i) {
            auto ch = mnes[i];
            if (ch == '[') {
                RETURN_FAILED_IF(bracket);
                RETURN_FAILED_IF(parenthesis);
                RETURN_FAILED_IF(i == 0 || i + 1 == mnes.length());
                bracket = true;
                if (step_on_mne) {
                    out->name = cur_mne;
                }
                step_on_mne = false;
            } else if (ch == ']') {
                RETURN_FAILED_IF(!bracket);
                RETURN_FAILED_IF(parenthesis);
                bracket = false;
                out->ss = cur_ss;
                cur_ss.clear();
            } else if (ch == '(') {
                RETURN_FAILED_IF(parenthesis);
                RETURN_FAILED_IF(bracket);
                RETURN_FAILED_IF(i == 0 || i + 1 == mnes.length());
                parenthesis = true;
                if (step_on_mne) {
                    out->name = cur_mne;
                }
                step_on_mne = false;
            } else if (ch == ')') {
                RETURN_FAILED_IF(!parenthesis);
                RETURN_FAILED_IF(bracket);
                parenthesis = false;
                out->decorate = cur_decorate;
                cur_decorate.clear();
            } else {
                if (bracket) {
                    cur_ss.push_back(ch);
                } else if (parenthesis) {
                    cur_decorate.push_back(ch);
                } else {
                    RETURN_FAILED_IF(!step_on_mne);
                    cur_mne.push_back(ch);
                }

                if (i + 1 == mnes.length()) {
                    RETURN_FAILED_IF(bracket);
                    RETURN_FAILED_IF(parenthesis);
                    out->name = cur_mne;
                    out->ss = cur_ss;
                }
            }
        }

        out->operands = abbrs;
        return true;
    }

}
}