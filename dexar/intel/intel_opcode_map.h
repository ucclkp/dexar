// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_OPCODE_MAP_H_
#define DEXAR_OPCODE_MAP_H_

#include "dexar/intel/intel_instruction_params.h"


namespace dexar {
namespace intel {

    struct OpcodeDesc {
        bool is_escape;
        bool is_undefined;

        bool is_prefix;
        std::string prefix;

        bool is_extended;
        uint8_t ext_group;
        std::string ext_tail;

        std::string mnemonics;

        OpcodeDesc()
            : is_escape(false),
              is_undefined(true),
              is_prefix(false),
              is_extended(false),
              ext_group(0) {}

        static OpcodeDesc ofEsc() {
            OpcodeDesc od;
            od.is_escape = true;
            od.is_undefined = false;
            return od;
        }
        static OpcodeDesc ofUnd() {
            OpcodeDesc od;
            od.is_undefined = true;
            return od;
        }
        static OpcodeDesc ofPfx(const std::string& p) {
            OpcodeDesc od;
            od.is_prefix = true;
            od.prefix = p;
            od.is_undefined = false;
            return od;
        }
        static OpcodeDesc ofExt(uint8_t group, const std::string& tail) {
            OpcodeDesc od;
            od.is_extended = true;
            od.ext_group = group;
            od.ext_tail = tail;
            od.is_undefined = false;
            return od;
        }
        static OpcodeDesc ofNor(const std::string& mnes) {
            OpcodeDesc od;
            od.mnemonics = mnes;
            od.is_undefined = false;
            return od;
        }
    };

    /**
     * Opcode Maps
     */
    // (cpu_mode, pfx)
    typedef OpcodeDesc (*OpcodeHandler)(const Env&, const Prefix&, const SelConfig&);

    // (pfx, modrm, op)
    typedef OpcodeDesc (*ExtOpcodeHandler)(const Env&, const Prefix&, uint8_t, uint8_t, const SelConfig&);

    extern OpcodeHandler op_1_map[0x10][0x10];
    extern OpcodeHandler op_2_map[0x10][0x10];
    extern OpcodeHandler op_38H_map[0x10][0x10];
    extern OpcodeHandler op_3AH_map[0x10][0x10];
    extern ExtOpcodeHandler ext_op_map[0x20];

    /**
     * ModRM Maps
     */
    // (cpu_mode)
    typedef ModRMMemMode (*ModRMMemHandler)(const Env&);
    typedef ModRMRegMode (*ModRMRegHandler)(const Env&);

    extern ModRMMemHandler modrm_mem_map[0x3][0x10];
    extern ModRMRegHandler modrm_reg_map[0x10];

    /**
     * SIB Maps
     */
    // (cpu_mode)
    typedef SIBScaleMode (*SIBScaleHandler)(const Env&);
    // (cpu_mode, modrm)
    typedef SIBBaseMode (*SIBBaseHandler)(const Env&, uint8_t);

    extern SIBScaleHandler sib_scale_map[0x4][0x10];
    extern SIBBaseHandler sib_base_map[0x10];

    void initOneByteOpcodeMap();
    void initTwoByteOpcodeMap();
    void initThreeByteOpcodeMap();
    void initExtensionOpcodeMap();
    void initModRMMap();
    void initSIBMap();

}
}

#endif  // DISASSEMBLER_OPCODE_MAP_H_