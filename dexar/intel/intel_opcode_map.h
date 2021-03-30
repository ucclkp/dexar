// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_OPCODE_MAP_H_
#define DEXAR_OPCODE_MAP_H_

#include <functional>
#include <unordered_map>

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
    template <typename T>
    using OpMap = std::unordered_map<uint8_t, T>;

    // (cpu_mode, pfx)
    using OpcodeHandler = std::function<OpcodeDesc(const Env&, const Prefix&, const SelConfig&)>;

    // (pfx, modrm, op)
    using ExtOpcodeHandler = std::function<OpcodeDesc(const Env&, const Prefix&, uint8_t, uint8_t, const SelConfig&)>;

    extern OpMap<OpMap<OpcodeHandler>> op_1_map;
    extern OpMap<OpMap<OpcodeHandler>> op_2_map;
    extern OpMap<OpMap<OpcodeHandler>> op_38H_map;
    extern OpMap<OpMap<OpcodeHandler>> op_3AH_map;
    extern OpMap<ExtOpcodeHandler> ext_op_map;

    /**
     * ModRM Maps
     */
    template <typename T>
    using ModMap = std::unordered_map<uint8_t, T>;

    // (cpu_mode)
    using ModRMMemHandler = std::function<ModRMMemMode(const Env&)>;
    using ModRMRegHandler = std::function<ModRMRegMode(const Env&)>;

    extern ModMap<ModMap<ModRMMemHandler>> modrm_mem_map;
    extern ModMap<ModRMRegHandler> modrm_reg_map;

    /**
     * SIB Maps
     */
    template <typename T>
    using SIBMap = std::unordered_map<uint8_t, T>;

    // (cpu_mode)
    using SIBScaleHandler = std::function<SIBScaleMode(const Env&)>;
    // (cpu_mode, modrm)
    using SIBBaseHandler = std::function<SIBBaseMode(const Env&, uint8_t)>;

    extern SIBMap<SIBMap<SIBScaleHandler>> sib_scale_map;
    extern SIBMap<SIBBaseHandler> sib_base_map;

    void initOneByteOpcodeMap();
    void initTwoByteOpcodeMap();
    void initThreeByteOpcodeMap();
    void initExtensionOpcodeMap();
    void initModRMMap();
    void initSIBMap();

}
}

#endif  // DISASSEMBLER_OPCODE_MAP_H_