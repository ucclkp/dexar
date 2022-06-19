// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/intel/intel_opcode_map.h"

#define OPCODE_N64_64(i64, o64)  {                                   \
    if (env.cpu_mode == CPUMode::_64Bit) return OpcodeDesc::ofNor(o64);  \
    return OpcodeDesc::ofNor(i64); }

#define OPCODE_N64_64P(i64, o64p)  {                                  \
    if (env.cpu_mode == CPUMode::_64Bit) return OpcodeDesc::ofPfx(o64p);  \
    return OpcodeDesc::ofNor(i64); }

#define OPCODE_RXX_NOR(rxx, nor)  {                      \
    if (pfx.hasRex() && pfx.rexB()) return OpcodeDesc::ofNor(rxx);  \
    return OpcodeDesc::ofNor(nor); }

#define OPCODE_DQ_BY_REXW(d, q)  {  \
    if (pfx.hasRex() && pfx.rexW()) return OpcodeDesc::ofNor(q);  \
    return OpcodeDesc::ofNor(d); }

#define OPCODE_VDQ_BY_VEXW(d, q)  {  \
    if (pfx.hasVex() && pfx.vex_length == 3 && pfx.vexW()) return OpcodeDesc::ofNor(q);  \
    return OpcodeDesc::ofNor(d); }

#define OPCODE_MAND_RET_ESC(m)            if (pfx.mand == m) return OpcodeDesc::ofEsc();
#define OPCODE_MAND_RET_PFX(m, pfx)       if (pfx.mand == m) return OpcodeDesc::ofPfx(pfx);
#define OPCODE_MAND_RET_EXT(m, grp, til)  if (pfx.mand == m) return OpcodeDesc::ofExt(grp, til);
#define OPCODE_MAND_RET_NOR(m, mne)       if (pfx.mand == m) return OpcodeDesc::ofNor(mne);
#define RET_UND                           return OpcodeDesc::ofUnd();

#define OPCODE_MAND_HANDLER(m)        { if (pfx.mand == m)
#define OPCODE_MAND_HANDLER_END       RET_UND; }
#define OPCODE_MAND_ESC(m)            { OPCODE_MAND_RET_ESC(m);           RET_UND; }
#define OPCODE_MAND_PFX(m, pfx)       { OPCODE_MAND_RET_PFX(m, pfx);      RET_UND; }
#define OPCODE_MAND_EXT(m, grp, til)  { OPCODE_MAND_RET_EXT(m, grp, til); RET_UND; }
#define OPCODE_MAND_NOR(m, mne)       { OPCODE_MAND_RET_NOR(m, mne);      RET_UND; }
#define OPCODE_MAND_DQ_BY_REXW(m, d, q)  OPCODE_MAND_HANDLER(m) { OPCODE_DQ_BY_REXW(d, q) } OPCODE_MAND_HANDLER_END
#define OPCODE_MAND_VDQ_BY_VEXW(m, d, q)  OPCODE_MAND_HANDLER(m) { OPCODE_VDQ_BY_VEXW(d, q) } OPCODE_MAND_HANDLER_END

// 1 byte opcode
#define OPCODE_1_MAP_HANDLER(row, col)        op_1_map[row][col] = [](const Env& env, const Prefix& pfx, const SelConfig& sel_cfg)->OpcodeDesc
#define OPCODE_1_MAP_ESC(row, col)            OPCODE_1_MAP_HANDLER(row, col) { return OpcodeDesc::ofEsc(); }
#define OPCODE_1_MAP_PFX(row, col, pfx)       OPCODE_1_MAP_HANDLER(row, col) { return OpcodeDesc::ofPfx(pfx); }
#define OPCODE_1_MAP_EXT(row, col, grp, til)  OPCODE_1_MAP_HANDLER(row, col) { return OpcodeDesc::ofExt(grp, til); }
#define OPCODE_1_MAP_NOR(row, col, mne)       OPCODE_1_MAP_HANDLER(row, col) { return OpcodeDesc::ofNor(mne); }

// 2 byte opcode
#define OPCODE_2_MAP_HANDLER(row, col)        op_2_map[row][col] = [](const Env& env, const Prefix& pfx, const SelConfig& sel_cfg)->OpcodeDesc
#define OPCODE_2_MAP_ESC(row, col)            OPCODE_MAP_2_HANDLER(row, col) { return OpcodeDesc::ofEsc(); }
#define OPCODE_2_MAP_PFX(row, col, pfx)       OPCODE_MAP_2_HANDLER(row, col) { return OpcodeDesc::ofPfx(pfx); }
#define OPCODE_2_MAP_EXT(row, col, grp, til)  OPCODE_MAP_2_HANDLER(row, col) { return OpcodeDesc::ofExt(grp, til); }
#define OPCODE_2_MAP_NOR(row, col, mne)       OPCODE_MAP_2_HANDLER(row, col) { return OpcodeDesc::ofNor(mne); }

// 3 byte opcode (38H)
#define OPCODE_38H_MAP_HANDLER(row, col)        op_38H_map[row][col] = [](const Env& env, const Prefix& pfx, const SelConfig& sel_cfg)->OpcodeDesc
#define OPCODE_38H_MAP_EXT(row, col, grp, til)  OPCODE_38H_MAP_HANDLER(row, col) { return OpcodeDesc::ofExt(grp, til); }
#define OPCODE_38H_MAP_NOR(row, col, mne)       OPCODE_38H_MAP_HANDLER(row, col) { return OpcodeDesc::ofNor(mne); }

// 3 byte opcode (3AH)
#define OPCODE_3AH_MAP_HANDLER(row, col)        op_3AH_map[row][col] = [](const Env& env, const Prefix& pfx, const SelConfig& sel_cfg)->OpcodeDesc
#define OPCODE_3AH_MAP_EXT(row, col, grp, til)  OPCODE_3AH_MAP_HANDLER(row, col) { return OpcodeDesc::ofExt(grp, til); }
#define OPCODE_3AH_MAP_NOR(row, col, mne)       OPCODE_3AH_MAP_HANDLER(row, col) { return OpcodeDesc::ofNor(mne); }

// extension opcode
#define OPCODE_EXTENSIONS_HANDLER(grp)  \
    ext_op_map[grp] = [](const Env& env, const Prefix& pfx, uint8_t modrm, uint8_t opcode, const SelConfig& sel_cfg)->OpcodeDesc

// ModRM
#define MODRM_MEM_MAP_HANDLER(mod, rm)   modrm_mem_map[mod][rm] = [](const Env& env)->ModRMMemMode
#define MODRM_REG_MAP_HANDLER(reg)       modrm_reg_map[reg] = [](const Env& env)->ModRMRegMode

// SIB
#define SIB_SCALE_MAP_HANDLER(ss, idx)   sib_scale_map[ss][idx] = [](const Env& env)->SIBScaleMode
#define SIB_BASE_MAP_HANDLER(base)       sib_base_map[base] = [](const Env& env, uint8_t modrm)->SIBBaseMode


namespace dexar {
namespace intel {

    OpcodeHandler op_1_map[0x10][0x10];
    OpcodeHandler op_2_map[0x10][0x10];
    OpcodeHandler op_38H_map[0x10][0x10];
    OpcodeHandler op_3AH_map[0x10][0x10];
    ExtOpcodeHandler ext_op_map[0x20];
    ModRMMemHandler modrm_mem_map[0x3][0x10];
    ModRMRegHandler modrm_reg_map[0x10];
    SIBScaleHandler sib_scale_map[0x4][0x10];
    SIBBaseHandler sib_base_map[0x10];


    void initOneByteOpcodeMap() {
        OPCODE_1_MAP_NOR(0x0, 0x0, "ADD Eb, Gb");
        OPCODE_1_MAP_NOR(0x0, 0x1, "ADD Ev, Gv");
        OPCODE_1_MAP_NOR(0x0, 0x2, "ADD Gb, Eb");
        OPCODE_1_MAP_NOR(0x0, 0x3, "ADD Gv, Ev");
        OPCODE_1_MAP_NOR(0x0, 0x4, "ADD AL, Ib");
        OPCODE_1_MAP_NOR(0x0, 0x5, "ADD rAX, Iz");
        OPCODE_1_MAP_NOR(0x0, 0x6, "PUSH[i64] ES");
        OPCODE_1_MAP_NOR(0x0, 0x7, "POP[i64] ES");
        OPCODE_1_MAP_NOR(0x0, 0x8, "OR Eb, Gb");
        OPCODE_1_MAP_NOR(0x0, 0x9, "OR Ev, Gv");
        OPCODE_1_MAP_NOR(0x0, 0xA, "OR Gb, Eb");
        OPCODE_1_MAP_NOR(0x0, 0xB, "OR Gv, Ev");
        OPCODE_1_MAP_NOR(0x0, 0xC, "OR AL, Ib");
        OPCODE_1_MAP_NOR(0x0, 0xD, "OR rAX, Iz");
        OPCODE_1_MAP_NOR(0x0, 0xE, "PUSH[i64] CS");
        OPCODE_1_MAP_ESC(0x0, 0xF);

        OPCODE_1_MAP_NOR(0x1, 0x0, "ADC Eb, Gb");
        OPCODE_1_MAP_NOR(0x1, 0x1, "ADC Ev, Gv");
        OPCODE_1_MAP_NOR(0x1, 0x2, "ADC Gb, Eb");
        OPCODE_1_MAP_NOR(0x1, 0x3, "ADC Gv, Ev");
        OPCODE_1_MAP_NOR(0x1, 0x4, "ADC AL, Ib");
        OPCODE_1_MAP_NOR(0x1, 0x5, "ADC rAX, Iz");
        OPCODE_1_MAP_NOR(0x1, 0x6, "PUSH[i64] SS");
        OPCODE_1_MAP_NOR(0x1, 0x7, "POP[i64] SS");
        OPCODE_1_MAP_NOR(0x1, 0x8, "SBB Eb, Gb");
        OPCODE_1_MAP_NOR(0x1, 0x9, "SBB Ev, Gv");
        OPCODE_1_MAP_NOR(0x1, 0xA, "SBB Gb, Eb");
        OPCODE_1_MAP_NOR(0x1, 0xB, "SBB Gv, Ev");
        OPCODE_1_MAP_NOR(0x1, 0xC, "SBB AL, Ib");
        OPCODE_1_MAP_NOR(0x1, 0xD, "SBB rAX, Iz");
        OPCODE_1_MAP_NOR(0x1, 0xE, "PUSH[i64] DS");
        OPCODE_1_MAP_NOR(0x1, 0xF, "POP[i64]  DS");

        OPCODE_1_MAP_NOR(0x2, 0x0, "AND Eb, Gb");
        OPCODE_1_MAP_NOR(0x2, 0x1, "AND Ev, Gv");
        OPCODE_1_MAP_NOR(0x2, 0x2, "AND Gb, Eb");
        OPCODE_1_MAP_NOR(0x2, 0x3, "AND Gv, Ev");
        OPCODE_1_MAP_NOR(0x2, 0x4, "AND AL, Ib");
        OPCODE_1_MAP_NOR(0x2, 0x5, "AND rAX, Iz");
        OPCODE_1_MAP_PFX(0x2, 0x6, "SEG=ES");
        OPCODE_1_MAP_NOR(0x2, 0x7, "DAA[i64]");
        OPCODE_1_MAP_NOR(0x2, 0x8, "SUB Eb, Gb");
        OPCODE_1_MAP_NOR(0x2, 0x9, "SUB Ev, Gv");
        OPCODE_1_MAP_NOR(0x2, 0xA, "SUB Gb, Eb");
        OPCODE_1_MAP_NOR(0x2, 0xB, "SUB Gv, Ev");
        OPCODE_1_MAP_NOR(0x2, 0xC, "SUB AL, Ib");
        OPCODE_1_MAP_NOR(0x2, 0xD, "SUB rAX, Iz");
        OPCODE_1_MAP_PFX(0x2, 0xE, "SEG=CS");
        OPCODE_1_MAP_NOR(0x2, 0xF, "DAS[i64]");

        OPCODE_1_MAP_NOR(0x3, 0x0, "XOR Eb, Gb");
        OPCODE_1_MAP_NOR(0x3, 0x1, "XOR Ev, Gv");
        OPCODE_1_MAP_NOR(0x3, 0x2, "XOR Gb, Eb");
        OPCODE_1_MAP_NOR(0x3, 0x3, "XOR Gv, Ev");
        OPCODE_1_MAP_NOR(0x3, 0x4, "XOR AL, Ib");
        OPCODE_1_MAP_NOR(0x3, 0x5, "XOR rAX, Iz");
        OPCODE_1_MAP_PFX(0x3, 0x6, "SEG=SS");
        OPCODE_1_MAP_NOR(0x3, 0x7, "AAA[i64]");
        OPCODE_1_MAP_NOR(0x3, 0x8, "CMP Eb, Gb");
        OPCODE_1_MAP_NOR(0x3, 0x9, "CMP Ev, Gv");
        OPCODE_1_MAP_NOR(0x3, 0xA, "CMP Gb, Eb");
        OPCODE_1_MAP_NOR(0x3, 0xB, "CMP Gv, Ev");
        OPCODE_1_MAP_NOR(0x3, 0xC, "CMP AL, Ib");
        OPCODE_1_MAP_NOR(0x3, 0xD, "CMP rAX, Iz");
        OPCODE_1_MAP_PFX(0x3, 0xE, "SEG=DS");
        OPCODE_1_MAP_NOR(0x3, 0xF, "AAS[i64]");

        OPCODE_1_MAP_HANDLER(0x4, 0x0) OPCODE_N64_64P("INC[i64] eAX", "REX[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x1) OPCODE_N64_64P("INC[i64] eCX", "REX.B[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x2) OPCODE_N64_64P("INC[i64] eDX", "REX.X[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x3) OPCODE_N64_64P("INC[i64] eBX", "REX.XB[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x4) OPCODE_N64_64P("INC[i64] eSP", "REX.R[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x5) OPCODE_N64_64P("INC[i64] eBP", "REX.RB[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x6) OPCODE_N64_64P("INC[i64] eSI", "REX.RX[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x7) OPCODE_N64_64P("INC[i64] eDI", "REX.RXB[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x8) OPCODE_N64_64P("DEC[i64] eAX", "REX.W[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0x9) OPCODE_N64_64P("DEC[i64] eCX", "REX.WB[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0xA) OPCODE_N64_64P("DEC[i64] eDX", "REX.WX[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0xB) OPCODE_N64_64P("DEC[i64] eBX", "REX.WXB[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0xC) OPCODE_N64_64P("DEC[i64] eSP", "REX.WR[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0xD) OPCODE_N64_64P("DEC[i64] eBP", "REX.WRB[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0xE) OPCODE_N64_64P("DEC[i64] eSI", "REX.WRX[o64]");
        OPCODE_1_MAP_HANDLER(0x4, 0xF) OPCODE_N64_64P("DEC[i64] eDI", "REX.WRXB[o64]");

        OPCODE_1_MAP_HANDLER(0x5, 0x0) OPCODE_RXX_NOR("PUSH[d64] r8",  "PUSH[d64] rAX");
        OPCODE_1_MAP_HANDLER(0x5, 0x1) OPCODE_RXX_NOR("PUSH[d64] r9",  "PUSH[d64] rCX");
        OPCODE_1_MAP_HANDLER(0x5, 0x2) OPCODE_RXX_NOR("PUSH[d64] r10", "PUSH[d64] rDX");
        OPCODE_1_MAP_HANDLER(0x5, 0x3) OPCODE_RXX_NOR("PUSH[d64] r11", "PUSH[d64] rBX");
        OPCODE_1_MAP_HANDLER(0x5, 0x4) OPCODE_RXX_NOR("PUSH[d64] r12", "PUSH[d64] rSP");
        OPCODE_1_MAP_HANDLER(0x5, 0x5) OPCODE_RXX_NOR("PUSH[d64] r13", "PUSH[d64] rBP");
        OPCODE_1_MAP_HANDLER(0x5, 0x6) OPCODE_RXX_NOR("PUSH[d64] r14", "PUSH[d64] rSI");
        OPCODE_1_MAP_HANDLER(0x5, 0x7) OPCODE_RXX_NOR("PUSH[d64] r15", "PUSH[d64] rDI");
        OPCODE_1_MAP_HANDLER(0x5, 0x8) OPCODE_RXX_NOR("POP[d64]  r8",  "POP[d64]  rAX");
        OPCODE_1_MAP_HANDLER(0x5, 0x9) OPCODE_RXX_NOR("POP[d64]  r9",  "POP[d64]  rCX");
        OPCODE_1_MAP_HANDLER(0x5, 0xA) OPCODE_RXX_NOR("POP[d64]  r10", "POP[d64]  rDX");
        OPCODE_1_MAP_HANDLER(0x5, 0xB) OPCODE_RXX_NOR("POP[d64]  r11", "POP[d64]  rBX");
        OPCODE_1_MAP_HANDLER(0x5, 0xC) OPCODE_RXX_NOR("POP[d64]  r12", "POP[d64]  rSP");
        OPCODE_1_MAP_HANDLER(0x5, 0xD) OPCODE_RXX_NOR("POP[d64]  r13", "POP[d64]  rBP");
        OPCODE_1_MAP_HANDLER(0x5, 0xE) OPCODE_RXX_NOR("POP[d64]  r14", "POP[d64]  rSI");
        OPCODE_1_MAP_HANDLER(0x5, 0xF) OPCODE_RXX_NOR("POP[d64]  r15", "POP[d64]  rDI");

        OPCODE_1_MAP_HANDLER(0x6, 0x0) {
            auto op_size = selectOperandSize(env.d, pfx);
            if (op_size == 2) return OpcodeDesc::ofNor("PUSHA[i64]");
            if (op_size == 4) return OpcodeDesc::ofNor("PUSHAD[i64]");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x6, 0x1) {
            auto op_size = selectOperandSize(env.d, pfx);
            if (op_size == 2) return OpcodeDesc::ofNor("POPA[i64]");
            if (op_size == 4) return OpcodeDesc::ofNor("POPAD[i64]");
            RET_UND;
        };
        OPCODE_1_MAP_NOR(0x6, 0x2, "BOUND[i64] Gv, Ma");
        OPCODE_1_MAP_HANDLER(0x6, 0x3) OPCODE_N64_64("ARPL[i64] Ew, Gw", "MOVSXD[o64] Gv, Ev");
        OPCODE_1_MAP_PFX(0x6, 0x4, "SEG=FS");
        OPCODE_1_MAP_PFX(0x6, 0x5, "SEG=GS");
        OPCODE_1_MAP_PFX(0x6, 0x6, "Operand Size");
        OPCODE_1_MAP_PFX(0x6, 0x7, "Address Size");
        OPCODE_1_MAP_NOR(0x6, 0x8, "PUSH[d64] Iz");
        OPCODE_1_MAP_NOR(0x6, 0x9, "IMUL Gv, Ev, Iz");
        OPCODE_1_MAP_NOR(0x6, 0xA, "PUSH[d64] Ib");
        OPCODE_1_MAP_NOR(0x6, 0xB, "IMUL Gv, Ev, Ib");
        OPCODE_1_MAP_HANDLER(0x6, 0xC) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("INS Yb, DX");
            return OpcodeDesc::ofNor("INSB");
        };
        OPCODE_1_MAP_HANDLER(0x6, 0xD) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("INS Yz, DX");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("INSW");
            if (op_size == 4) return OpcodeDesc::ofNor("INSD");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x6, 0xE) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("OUTS DX, Xb");
            return OpcodeDesc::ofNor("OUTSB");
        };
        OPCODE_1_MAP_HANDLER(0x6, 0xF) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("OUTS DX, Xz");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("OUTSW");
            if (op_size == 4) return OpcodeDesc::ofNor("OUTSD");
            RET_UND;
        };

        OPCODE_1_MAP_NOR(0x7, 0x0, "JO[f64] Jb");
        OPCODE_1_MAP_NOR(0x7, 0x1, "JNO[f64] Jb");
        OPCODE_1_MAP_HANDLER(0x7, 0x2) {
            if (sel_cfg.b_nae_c == 0) return OpcodeDesc::ofNor("JB[f64] Jb");
            if (sel_cfg.b_nae_c == 1) return OpcodeDesc::ofNor("JNAE[f64] Jb");
            if (sel_cfg.b_nae_c == 2) return OpcodeDesc::ofNor("JC[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0x3) {
            if (sel_cfg.nb_ae_nc == 0) return OpcodeDesc::ofNor("JNB[f64] Jb");
            if (sel_cfg.nb_ae_nc == 1) return OpcodeDesc::ofNor("JAE[f64] Jb");
            if (sel_cfg.nb_ae_nc == 2) return OpcodeDesc::ofNor("JNC[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0x4) {
            if (sel_cfg.e_z == 0) return OpcodeDesc::ofNor("JE[f64] Jb");
            if (sel_cfg.e_z == 1) return OpcodeDesc::ofNor("JZ[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0x5) {
            if (sel_cfg.nz_ne == 0) return OpcodeDesc::ofNor("JNZ[f64] Jb");
            if (sel_cfg.nz_ne == 1) return OpcodeDesc::ofNor("JNE[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0x6) {
            if (sel_cfg.be_na == 0) return OpcodeDesc::ofNor("JBE[f64] Jb");
            if (sel_cfg.be_na == 1) return OpcodeDesc::ofNor("JNA[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0x7) {
            if (sel_cfg.nbe_a == 0) return OpcodeDesc::ofNor("JNBE[f64] Jb");
            if (sel_cfg.nbe_a == 1) return OpcodeDesc::ofNor("JA[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_NOR(0x7, 0x8, "JS[f64] Jb");
        OPCODE_1_MAP_NOR(0x7, 0x9, "JNS[f64] Jb");
        OPCODE_1_MAP_HANDLER(0x7, 0xA) {
            if (sel_cfg.p_pe == 0) return OpcodeDesc::ofNor("JP[f64] Jb");
            if (sel_cfg.p_pe == 1) return OpcodeDesc::ofNor("JPE[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0xB) {
            if (sel_cfg.np_po == 0) return OpcodeDesc::ofNor("JNP[f64] Jb");
            if (sel_cfg.np_po == 1) return OpcodeDesc::ofNor("JPO[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0xC) {
            if (sel_cfg.l_nge == 0) return OpcodeDesc::ofNor("JL[f64] Jb");
            if (sel_cfg.l_nge == 1) return OpcodeDesc::ofNor("JNGE[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0xD) {
            if (sel_cfg.nl_ge == 0) return OpcodeDesc::ofNor("JNL[f64] Jb");
            if (sel_cfg.nl_ge == 1) return OpcodeDesc::ofNor("JGE[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0xE) {
            if (sel_cfg.le_ng == 0) return OpcodeDesc::ofNor("JLE[f64] Jb");
            if (sel_cfg.le_ng == 1) return OpcodeDesc::ofNor("JNG[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x7, 0xF) {
            if (sel_cfg.nle_g == 0) return OpcodeDesc::ofNor("JNLE[f64] Jb");
            if (sel_cfg.nle_g == 1) return OpcodeDesc::ofNor("JG[f64] Jb");
            RET_UND;
        };

        OPCODE_1_MAP_EXT(0x8, 0x0, 0x1, "Eb, Ib");
        OPCODE_1_MAP_EXT(0x8, 0x1, 0x1, "Ev, Iz");
        OPCODE_1_MAP_EXT(0x8, 0x2, 0x1, "[i64] Eb, Ib");
        OPCODE_1_MAP_EXT(0x8, 0x3, 0x1, "Ev, Ib");
        OPCODE_1_MAP_NOR(0x8, 0x4, "TEST Eb, Gb");
        OPCODE_1_MAP_NOR(0x8, 0x5, "TEST Ev, Gv");
        OPCODE_1_MAP_NOR(0x8, 0x6, "XCHG Eb, Gb");
        OPCODE_1_MAP_NOR(0x8, 0x7, "XCHG Ev, Gv");
        OPCODE_1_MAP_NOR(0x8, 0x8, "MOV Eb, Gb");
        OPCODE_1_MAP_NOR(0x8, 0x9, "MOV Ev, Gv");
        OPCODE_1_MAP_NOR(0x8, 0xA, "MOV Gb, Eb");
        OPCODE_1_MAP_NOR(0x8, 0xB, "MOV Gv, Ev");
        OPCODE_1_MAP_NOR(0x8, 0xC, "MOV Ev, Sw");
        OPCODE_1_MAP_NOR(0x8, 0xD, "LEA Gv, M");
        OPCODE_1_MAP_NOR(0x8, 0xE, "MOV Sw, Ew");
        OPCODE_1_MAP_EXT(0x8, 0xF, 0x1A, "Ev");

        OPCODE_1_MAP_HANDLER(0x9, 0x0) {
            if (pfx.mand == 0x0) {
                if (sel_cfg.use_nop) return OpcodeDesc::ofNor("NOP");
                return OpcodeDesc::ofNor("XCHG r8, rAX");
            }
            OPCODE_MAND_RET_NOR(0xF3, "PAUSE");
            RET_UND; };
        OPCODE_1_MAP_HANDLER(0x9, 0x1) OPCODE_RXX_NOR("XCHG rAX, r9",  "XCHG rAX, rCX");
        OPCODE_1_MAP_HANDLER(0x9, 0x2) OPCODE_RXX_NOR("XCHG rAX, r10", "XCHG rAX, rDX");
        OPCODE_1_MAP_HANDLER(0x9, 0x3) OPCODE_RXX_NOR("XCHG rAX, r11", "XCHG rAX, rBX");
        OPCODE_1_MAP_HANDLER(0x9, 0x4) OPCODE_RXX_NOR("XCHG rAX, r12", "XCHG rAX, rSP");
        OPCODE_1_MAP_HANDLER(0x9, 0x5) OPCODE_RXX_NOR("XCHG rAX, r13", "XCHG rAX, rBP");
        OPCODE_1_MAP_HANDLER(0x9, 0x6) OPCODE_RXX_NOR("XCHG rAX, r14", "XCHG rAX, rSI");
        OPCODE_1_MAP_HANDLER(0x9, 0x7) OPCODE_RXX_NOR("XCHG rAX, r15", "XCHG rAX, rDI");
        OPCODE_1_MAP_HANDLER(0x9, 0x8) {
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("CBW");
            if (op_size == 4) return OpcodeDesc::ofNor("CWDE");
            if (op_size == 8) return OpcodeDesc::ofNor("CDQE");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x9, 0x9) {
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("CWD");
            if (op_size == 4) return OpcodeDesc::ofNor("CDQ");
            if (op_size == 8) return OpcodeDesc::ofNor("CQO");
            RET_UND;
        };
        OPCODE_1_MAP_NOR(0x9, 0xA, "CALL(F)[i64] Ap");
        OPCODE_1_MAP_HANDLER(0x9, 0xB) {
            if (sel_cfg.use_fwait) return OpcodeDesc::ofNor("FWAIT");
            return OpcodeDesc::ofNor("WAIT");
        };
        OPCODE_1_MAP_HANDLER(0x9, 0xC) {
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("d64", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("PUSHF[d64] Fv");
            if (op_size == 4) return OpcodeDesc::ofNor("PUSHFD[d64] Fv");
            if (op_size == 8) return OpcodeDesc::ofNor("PUSHFQ[d64] Fv");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0x9, 0xD) {
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("d64", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("POPF[d64] Fv");
            if (op_size == 4) return OpcodeDesc::ofNor("POPFD[d64] Fv");
            if (op_size == 8) return OpcodeDesc::ofNor("POPFQ[d64] Fv");
            RET_UND;
        };
        OPCODE_1_MAP_NOR(0x9, 0xE, "SAHF");
        OPCODE_1_MAP_NOR(0x9, 0xF, "LAHF");

        OPCODE_1_MAP_NOR(0xA, 0x0, "MOV AL,  Ob");
        OPCODE_1_MAP_NOR(0xA, 0x1, "MOV rAX, Ov");
        OPCODE_1_MAP_NOR(0xA, 0x2, "MOV Ob,  AL");
        OPCODE_1_MAP_NOR(0xA, 0x3, "MOV Ov,  rAX");
        OPCODE_1_MAP_HANDLER(0xA, 0x4) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("MOVS Yb, Xb");
            return OpcodeDesc::ofNor("MOVSB");
        };
        OPCODE_1_MAP_HANDLER(0xA, 0x5) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("MOVS Yv, Xv");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("MOVSW");
            if (op_size == 4) return OpcodeDesc::ofNor("MOVSD");
            if (op_size == 8) return OpcodeDesc::ofNor("MOVSQ");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0xA, 0x6) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("CMPS Xb, Yb");
            return OpcodeDesc::ofNor("CMPSB");
        };
        OPCODE_1_MAP_HANDLER(0xA, 0x7) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("CMPS Xv, Yv");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("CMPSW");
            if (op_size == 4) return OpcodeDesc::ofNor("CMPSD");
            RET_UND;
        };
        OPCODE_1_MAP_NOR(0xA, 0x8, "TEST AL,  Ib");
        OPCODE_1_MAP_NOR(0xA, 0x9, "TEST rAX, Iz");
        OPCODE_1_MAP_HANDLER(0xA, 0xA) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("STOS Yb, AL");
            return OpcodeDesc::ofNor("STOSB");
        };
        OPCODE_1_MAP_HANDLER(0xA, 0xB) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("STOS Yv, rAX");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("STOSW");
            if (op_size == 4) return OpcodeDesc::ofNor("STOSD");
            if (op_size == 8) return OpcodeDesc::ofNor("STOSQ");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0xA, 0xC) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("LODS AL, Xb");
            return OpcodeDesc::ofNor("LODSB");
        };
        OPCODE_1_MAP_HANDLER(0xA, 0xD) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("LODS rAX, Xv");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("LODSW");
            if (op_size == 4) return OpcodeDesc::ofNor("LODSD");
            if (op_size == 8) return OpcodeDesc::ofNor("LODSQ");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0xA, 0xE) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("SCAS AL, Yb");
            return OpcodeDesc::ofNor("SCASB");
        };
        OPCODE_1_MAP_HANDLER(0xA, 0xF) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("SCAS rAX, Yv");
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("SCASW");
            if (op_size == 4) return OpcodeDesc::ofNor("SCASD");
            if (op_size == 8) return OpcodeDesc::ofNor("SCASQ");
            RET_UND;
        };

        OPCODE_1_MAP_HANDLER(0xB, 0x0) OPCODE_RXX_NOR("MOV R8L,  Ib", "MOV AL, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x1) OPCODE_RXX_NOR("MOV R9L,  Ib", "MOV CL, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x2) OPCODE_RXX_NOR("MOV R10L, Ib", "MOV DL, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x3) OPCODE_RXX_NOR("MOV R11L, Ib", "MOV BL, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x4) OPCODE_RXX_NOR("MOV R12L, Ib", "MOV AH, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x5) OPCODE_RXX_NOR("MOV R13L, Ib", "MOV CH, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x6) OPCODE_RXX_NOR("MOV R14L, Ib", "MOV DH, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x7) OPCODE_RXX_NOR("MOV R15L, Ib", "MOV BH, Ib");
        OPCODE_1_MAP_HANDLER(0xB, 0x8) OPCODE_RXX_NOR("MOV r8,  Iv", "MOV rAX, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0x9) OPCODE_RXX_NOR("MOV r9,  Iv", "MOV rCX, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0xA) OPCODE_RXX_NOR("MOV r10, Iv", "MOV rDX, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0xB) OPCODE_RXX_NOR("MOV r11, Iv", "MOV rBX, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0xC) OPCODE_RXX_NOR("MOV r12, Iv", "MOV rSP, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0xD) OPCODE_RXX_NOR("MOV r13, Iv", "MOV rBP, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0xE) OPCODE_RXX_NOR("MOV r14, Iv", "MOV rSI, Iv");
        OPCODE_1_MAP_HANDLER(0xB, 0xF) OPCODE_RXX_NOR("MOV r15, Iv", "MOV rDI, Iv");

        OPCODE_1_MAP_EXT(0xC, 0x0, 0x2, "Eb, Ib");
        OPCODE_1_MAP_EXT(0xC, 0x1, 0x2, "Ev, Ib");
        OPCODE_1_MAP_NOR(0xC, 0x2, "RET(N)[f64] Iw");
        OPCODE_1_MAP_NOR(0xC, 0x3, "RET(N)[f64]");
        OPCODE_1_MAP_NOR(0xC, 0x4, "LES[i64] Gz, Mp");
        OPCODE_1_MAP_NOR(0xC, 0x5, "LDS[i64] Gz, Mp");
        OPCODE_1_MAP_EXT(0xC, 0x6, 0x11, "");
        OPCODE_1_MAP_EXT(0xC, 0x7, 0x11, "");
        OPCODE_1_MAP_NOR(0xC, 0x8, "ENTER Iw, Ib");
        OPCODE_1_MAP_NOR(0xC, 0x9, "LEAVE[d64]");
        OPCODE_1_MAP_NOR(0xC, 0xA, "RET(F) Iw");
        OPCODE_1_MAP_NOR(0xC, 0xB, "RET(F)");
        OPCODE_1_MAP_NOR(0xC, 0xC, "INT 3");
        OPCODE_1_MAP_NOR(0xC, 0xD, "INT Ib");
        OPCODE_1_MAP_NOR(0xC, 0xE, "INTO[i64]");
        OPCODE_1_MAP_HANDLER(0xC, 0xF) {
            uint32_t op_size;
            if (env.cpu_mode == CPUMode::_64Bit) {
                op_size = selectOperandSize64("", pfx);
            } else {
                op_size = selectOperandSize(env.d, pfx);
            }
            if (op_size == 2) return OpcodeDesc::ofNor("IRET");
            if (op_size == 4) return OpcodeDesc::ofNor("IRETD");
            if (op_size == 8) return OpcodeDesc::ofNor("IRETQ");
            RET_UND;
        };

        OPCODE_1_MAP_EXT(0xD, 0x0, 0x2, "Eb, 1");
        OPCODE_1_MAP_EXT(0xD, 0x1, 0x2, "Ev, 1");
        OPCODE_1_MAP_EXT(0xD, 0x2, 0x2, "Eb, CL");
        OPCODE_1_MAP_EXT(0xD, 0x3, 0x2, "Ev, CL");
        OPCODE_1_MAP_NOR(0xD, 0x4, "AAM[i64] Ib");
        OPCODE_1_MAP_NOR(0xD, 0x5, "AAD[i64] Ib");
        OPCODE_1_MAP_HANDLER(0xD, 0x7) {
            if (sel_cfg.use_explicit) return OpcodeDesc::ofNor("XLAT");
            return OpcodeDesc::ofNor("XLATB");
        };
        OPCODE_1_MAP_ESC(0xD, 0x8);
        OPCODE_1_MAP_ESC(0xD, 0x9);
        OPCODE_1_MAP_ESC(0xD, 0xA);
        OPCODE_1_MAP_ESC(0xD, 0xB);
        OPCODE_1_MAP_ESC(0xD, 0xC);
        OPCODE_1_MAP_ESC(0xD, 0xD);
        OPCODE_1_MAP_ESC(0xD, 0xE);
        OPCODE_1_MAP_ESC(0xD, 0xF);

        OPCODE_1_MAP_HANDLER(0xE, 0x0) {
            if (sel_cfg.e_z == 0) return OpcodeDesc::ofNor("LOOPNE[f64] Jb");
            if (sel_cfg.e_z == 1) return OpcodeDesc::ofNor("LOOPNZ[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_HANDLER(0xE, 0x1) {
            if (sel_cfg.e_z == 0) return OpcodeDesc::ofNor("LOOPE[f64] Jb");
            if (sel_cfg.e_z == 1) return OpcodeDesc::ofNor("LOOPZ[f64] Jb");
            RET_UND;
        };
        OPCODE_1_MAP_NOR(0xE, 0x2, "LOOP[f64] Jb");
        OPCODE_1_MAP_NOR(0xE, 0x3, "JrCXZ[f64] Jb");
        OPCODE_1_MAP_NOR(0xE, 0x4, "IN  AL, Ib");
        OPCODE_1_MAP_NOR(0xE, 0x5, "IN  eAX, Ib");
        OPCODE_1_MAP_NOR(0xE, 0x6, "OUT Ib, AL");
        OPCODE_1_MAP_NOR(0xE, 0x7, "OUT Ib, eAX");
        OPCODE_1_MAP_NOR(0xE, 0x8, "CALL(N)[f64] Jz");
        OPCODE_1_MAP_NOR(0xE, 0x9, "JMP(N)[f64] Jz");
        OPCODE_1_MAP_NOR(0xE, 0xA, "JMP(F)[i64] Ap");
        OPCODE_1_MAP_NOR(0xE, 0xB, "JMP(S)[f64] Jb");
        OPCODE_1_MAP_NOR(0xE, 0xC, "IN AL, DX");
        OPCODE_1_MAP_NOR(0xE, 0xD, "IN eAX, DX");
        OPCODE_1_MAP_NOR(0xE, 0xE, "OUT DX, AL");
        OPCODE_1_MAP_NOR(0xE, 0xF, "OUT DX, eAX");

        OPCODE_1_MAP_PFX(0xF, 0x0, "LOCK");
        OPCODE_1_MAP_PFX(0xF, 0x2, "REPNE XACQUIRE");
        OPCODE_1_MAP_PFX(0xF, 0x3, "REP/REPE XRELEASE");
        OPCODE_1_MAP_NOR(0xF, 0x4, "HLT");
        OPCODE_1_MAP_NOR(0xF, 0x5, "CMC");
        OPCODE_1_MAP_EXT(0xF, 0x6, 0x3, "Eb");
        OPCODE_1_MAP_EXT(0xF, 0x7, 0x3, "Ev");
        OPCODE_1_MAP_NOR(0xF, 0x8, "CLC");
        OPCODE_1_MAP_NOR(0xF, 0x9, "STC");
        OPCODE_1_MAP_NOR(0xF, 0xA, "CLI");
        OPCODE_1_MAP_NOR(0xF, 0xB, "STI");
        OPCODE_1_MAP_NOR(0xF, 0xC, "CLD");
        OPCODE_1_MAP_NOR(0xF, 0xD, "STD");
        OPCODE_1_MAP_EXT(0xF, 0xE, 0x4, "");
        OPCODE_1_MAP_EXT(0xF, 0xF, 0x5, "");
    }

    void initTwoByteOpcodeMap() {
        OPCODE_2_MAP_HANDLER(0x0, 0x0) OPCODE_MAND_EXT(0x0, 0x6, "");
        OPCODE_2_MAP_HANDLER(0x0, 0x1) OPCODE_MAND_EXT(0x0, 0x7, "");
        OPCODE_2_MAP_HANDLER(0x0, 0x2) OPCODE_MAND_NOR(0x0, "LAR Gv, Ew");
        OPCODE_2_MAP_HANDLER(0x0, 0x3) OPCODE_MAND_NOR(0x0, "LSL Gv, Ew");
        OPCODE_2_MAP_HANDLER(0x0, 0x5) OPCODE_MAND_NOR(0x0, "SYSCALL[o64]");
        OPCODE_2_MAP_HANDLER(0x0, 0x6) OPCODE_MAND_NOR(0x0, "CLTS");
        OPCODE_2_MAP_HANDLER(0x0, 0x7) OPCODE_MAND_NOR(0x0, "SYSRET[o64]");
        OPCODE_2_MAP_HANDLER(0x0, 0x8) OPCODE_MAND_NOR(0x0, "INVD");
        OPCODE_2_MAP_HANDLER(0x0, 0x9) OPCODE_MAND_NOR(0x0, "WBINVD");
        OPCODE_2_MAP_HANDLER(0x0, 0xB) OPCODE_MAND_NOR(0x0, "UD2[1B]");
        OPCODE_2_MAP_HANDLER(0x0, 0xD) OPCODE_MAND_NOR(0x0, "prefetchw(/1) Ev");

        OPCODE_2_MAP_HANDLER(0x1, 0x0) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovups Vps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vmovupd Vpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vmovss Vx, Hx, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vmovsd Vx, Hx, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovups Wps, Vps");
            OPCODE_MAND_RET_NOR(0x66, "vmovupd Wpd, Vpd");
            OPCODE_MAND_RET_NOR(0xF3, "vmovss Wss, Hx, Vss");
            OPCODE_MAND_RET_NOR(0xF2, "vmovsd Wsd, Hx, Vsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x2) {
            if (pfx.mand == 0) {
                if (pfx.hasVex()) {
                    if (pfx.vexV() == 0xE) return OpcodeDesc::ofNor("vmovlps Vq, Hq, Mq");
                    if (pfx.vexV() == 0xD) return OpcodeDesc::ofNor("vmovhlps Vq, Hq, Uq");
                }
                RET_UND;
            }
            OPCODE_MAND_RET_NOR(0x66, "vmovlpd Vq, Hq, Mq");
            OPCODE_MAND_RET_NOR(0xF3, "vmovsldup Vx, Wx");
            OPCODE_MAND_RET_NOR(0xF2, "vmovddup Vx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovlps Mq, Vq");
            OPCODE_MAND_RET_NOR(0x66, "vmovlpd Mq, Vq");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,  "vunpcklps Vx, Hx, Wx");
            OPCODE_MAND_RET_NOR(0x66, "vunpcklpd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,  "vunpckhps Vx, Hx, Wx");
            OPCODE_MAND_RET_NOR(0x66, "vunpckhpd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x6) {
            if (pfx.mand == 0) {
                if (pfx.hasVex()) {
                    if (pfx.vexV() == 0xE) return OpcodeDesc::ofNor("vmovhps[v1] Vdq, Hq, Mq");
                    if (pfx.vexV() == 0xD) return OpcodeDesc::ofNor("vmovlhps Vdq, Hq, Uq");
                }
                RET_UND;
            }
            OPCODE_MAND_RET_NOR(0x66, "vmovhpd[v1] Vdq, Hq, Mq");
            OPCODE_MAND_RET_NOR(0xF3, "vmovshdup Vx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovhps[v1] Mq, Vq");
            OPCODE_MAND_RET_NOR(0x66, "vmovhpd[v1] Mq, Vq");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x1, 0x8) OPCODE_MAND_EXT(0x0, 0x16, "");
        OPCODE_2_MAP_HANDLER(0x1, 0xF) OPCODE_MAND_NOR(0x0, "NOP Ev");

        OPCODE_2_MAP_HANDLER(0x2, 0x0) OPCODE_MAND_NOR(0x0, "MOV Rd, Cd");
        OPCODE_2_MAP_HANDLER(0x2, 0x1) OPCODE_MAND_NOR(0x0, "MOV Rd, Dd");
        OPCODE_2_MAP_HANDLER(0x2, 0x2) OPCODE_MAND_NOR(0x0, "MOV Cd, Rd");
        OPCODE_2_MAP_HANDLER(0x2, 0x3) OPCODE_MAND_NOR(0x0, "MOV Dd, Rd");
        OPCODE_2_MAP_HANDLER(0x2, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovaps Vps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vmovapd Vpd, Wpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovaps Wps, Vps");
            OPCODE_MAND_RET_NOR(0x66, "vmovapd Wpd, Vpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,  "cvtpi2ps Vps, Qpi");
            OPCODE_MAND_RET_NOR(0x66, "cvtpi2pd Vpd, Qpi");
            OPCODE_MAND_RET_NOR(0xF3, "vcvtsi2ss Vss, Hss, Ey");
            OPCODE_MAND_RET_NOR(0xF2, "vcvtsi2sd Vsd, Hsd, Ey");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovntps Mps, Vps");
            OPCODE_MAND_RET_NOR(0x66, "vmovntpd Mpd, Vpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0xC) {
            OPCODE_MAND_RET_NOR(0x0,  "cvttps2pi Ppi, Wps");
            OPCODE_MAND_RET_NOR(0x66, "cvttpd2pi Ppi, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vcvttss2si Gy, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vcvttsd2si Gy, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0xD) {
            OPCODE_MAND_RET_NOR(0x0,  "cvtps2pi Ppi, Wps");
            OPCODE_MAND_RET_NOR(0x66, "cvtpd2pi Qpi, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vcvtss2si Gy, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vcvtsd2si Gy, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0xE) {
            OPCODE_MAND_RET_NOR(0x0,  "vucomiss Vss, Wss");
            OPCODE_MAND_RET_NOR(0x66, "vucomisd Vsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x2, 0xF) {
            OPCODE_MAND_RET_NOR(0x0,  "vcomiss Vss, Wss");
            OPCODE_MAND_RET_NOR(0x66, "vcomisd Vsd, Wsd");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0x3, 0x0) OPCODE_MAND_NOR(0x0, "WRMSR");
        OPCODE_2_MAP_HANDLER(0x3, 0x1) OPCODE_MAND_NOR(0x0, "RDTSC");
        OPCODE_2_MAP_HANDLER(0x3, 0x2) OPCODE_MAND_NOR(0x0, "RDMSR");
        OPCODE_2_MAP_HANDLER(0x3, 0x3) OPCODE_MAND_NOR(0x0, "RDPMC");
        OPCODE_2_MAP_HANDLER(0x3, 0x4) OPCODE_MAND_NOR(0x0, "SYSENTER");
        OPCODE_2_MAP_HANDLER(0x3, 0x5) OPCODE_MAND_NOR(0x0, "SYSEXIT");
        OPCODE_2_MAP_HANDLER(0x3, 0x7) OPCODE_MAND_NOR(0x0, "GETSEC");
        OPCODE_2_MAP_HANDLER(0x3, 0x8) OPCODE_MAND_ESC(0x0);
        OPCODE_2_MAP_HANDLER(0x3, 0xA) OPCODE_MAND_ESC(0x0);

        OPCODE_2_MAP_HANDLER(0x4, 0x0) OPCODE_MAND_NOR(0x0, "CMOVO Gv, Ev");
        OPCODE_2_MAP_HANDLER(0x4, 0x1) OPCODE_MAND_NOR(0x0, "CMOVNO Gv, Ev");
        OPCODE_2_MAP_HANDLER(0x4, 0x2) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.b_nae_c == 0) return OpcodeDesc::ofNor("CMOVB Gv, Ev");
            if (sel_cfg.b_nae_c == 1) return OpcodeDesc::ofNor("CMOVNAE Gv, Ev");
            if (sel_cfg.b_nae_c == 2) return OpcodeDesc::ofNor("CMOVC Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0x3) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nb_ae_nc == 0) return OpcodeDesc::ofNor("CMOVNB Gv, Ev");
            if (sel_cfg.nb_ae_nc == 1) return OpcodeDesc::ofNor("CMOVAE Gv, Ev");
            if (sel_cfg.nb_ae_nc == 2) return OpcodeDesc::ofNor("CMOVNC Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0x4) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.e_z == 0) return OpcodeDesc::ofNor("CMOVE Gv, Ev");
            if (sel_cfg.e_z == 1) return OpcodeDesc::ofNor("CMOVZ Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0x5) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nz_ne == 0) return OpcodeDesc::ofNor("CMOVNZ Gv, Ev");
            if (sel_cfg.nz_ne == 1) return OpcodeDesc::ofNor("CMOVNE Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0x6) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.be_na == 0) return OpcodeDesc::ofNor("CMOVBE Gv, Ev");
            if (sel_cfg.be_na == 1) return OpcodeDesc::ofNor("CMOVNA Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0x7) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nbe_a == 0) return OpcodeDesc::ofNor("CMOVNBE Gv, Ev");
            if (sel_cfg.nbe_a == 1) return OpcodeDesc::ofNor("CMOVA Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0x8) OPCODE_MAND_NOR(0x0, "CMOVS Gv, Ev");
        OPCODE_2_MAP_HANDLER(0x4, 0x9) OPCODE_MAND_NOR(0x0, "CMOVNS Gv, Ev");
        OPCODE_2_MAP_HANDLER(0x4, 0xA) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.p_pe == 0) return OpcodeDesc::ofNor("CMOVP Gv, Ev");
            if (sel_cfg.p_pe == 1) return OpcodeDesc::ofNor("CMOVPE Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0xB) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.np_po == 0) return OpcodeDesc::ofNor("CMOVNP Gv, Ev");
            if (sel_cfg.np_po == 1) return OpcodeDesc::ofNor("CMOVPO Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0xC) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.l_nge == 0) return OpcodeDesc::ofNor("CMOVL Gv, Ev");
            if (sel_cfg.l_nge == 1) return OpcodeDesc::ofNor("CMOVNGE Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0xD) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nl_ge == 0) return OpcodeDesc::ofNor("CMOVNL Gv, Ev");
            if (sel_cfg.nl_ge == 1) return OpcodeDesc::ofNor("CMOVGE Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0xE) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.le_ng == 0) return OpcodeDesc::ofNor("CMOVLE Gv, Ev");
            if (sel_cfg.le_ng == 1) return OpcodeDesc::ofNor("CMOVNG Gv, Ev");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x4, 0xF) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nle_g == 0) return OpcodeDesc::ofNor("CMOVNLE Gv, Ev");
            if (sel_cfg.nle_g == 1) return OpcodeDesc::ofNor("CMOVG Gv, Ev");
        } OPCODE_MAND_HANDLER_END;

        OPCODE_2_MAP_HANDLER(0x5, 0x0) {
            OPCODE_MAND_RET_NOR(0x0,  "vmovmskps Gy, Ups");
            OPCODE_MAND_RET_NOR(0x66, "vmovmskpd Gy, Upd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,  "vsqrtps Vps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vsqrtpd Vpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vsqrtss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vsqrtsd Vsd, Hsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,  "vrsqrtps Vps, Wps");
            OPCODE_MAND_RET_NOR(0xF3, "vrsqrtss Vss, Hss, Wss");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,  "vrcpps Vps, Wps");
            OPCODE_MAND_RET_NOR(0xF3, "vrcpss Vss, Hss, Wss");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,  "vandps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vandpd Vpd, Hpd, Wpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,  "vandnps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vandnpd Vpd, Hpd, Wpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x6) {
            OPCODE_MAND_RET_NOR(0x0,  "vorps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vorpd Vpd, Hpd, Wpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,  "vxorps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vxorpd Vpd, Hpd, Wpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,  "vaddps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vaddpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vaddss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vaddsd Vsd, Hsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,  "vmulps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vmulpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vmulss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vmulsd Vsd, Hsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,  "vcvtps2pd Vpd, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vcvtpd2ps Vps, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vcvtss2sd Vsd, Hx, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vcvtsd2ss Vss, Hx, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,  "vcvtdq2ps Vps, Wpq");
            OPCODE_MAND_RET_NOR(0x66, "vcvtps2dq Vdq, Wps");
            OPCODE_MAND_RET_NOR(0xF3, "vcvttps2dq Vdq, Wps");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0xC) {
            OPCODE_MAND_RET_NOR(0x0,  "vsubps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vsubpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vsubss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vsubsd Vsd, Hsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0xD) {
            OPCODE_MAND_RET_NOR(0x0,  "vminps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vminpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vminss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vminsd Vsd, Hsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0xE) {
            OPCODE_MAND_RET_NOR(0x0,  "vdivps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vdivpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vdivss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vdivsd Vsd, Hsd, Wsd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x5, 0xF) {
            OPCODE_MAND_RET_NOR(0x0,  "vmaxps Vps, Hps, Wps");
            OPCODE_MAND_RET_NOR(0x66, "vmaxpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vmaxss Vss, Hss, Wss");
            OPCODE_MAND_RET_NOR(0xF2, "vmaxsd Vsd, Hsd, Wsd");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0x6, 0x0) {
            OPCODE_MAND_RET_NOR(0x0,  "punpcklbw Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpunpcklbw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,  "punpcklwd Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpunpcklwd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,  "punpckldq Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpunpckldq Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,  "packsswb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpacksswb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,  "pcmpgtb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpcmpgtb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "pcmpgtw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpcmpgtw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x6) {
            OPCODE_MAND_RET_NOR(0x0,   "pcmpgtd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpcmpgtd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,   "packuswb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpackuswb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,   "punpckhbw Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpunpckhbw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,   "punpckhwd Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpunpckhwd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,   "punpckhdq Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpunpckhdq Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,   "packssdw Pq, Qd");
            OPCODE_MAND_RET_NOR(0x66, "vpackssdw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x6, 0xC) OPCODE_MAND_NOR(0x66, "vpunpcklqdq Vx, Hx, Wx");
        OPCODE_2_MAP_HANDLER(0x6, 0xD) OPCODE_MAND_NOR(0x66, "vpunpckhqdq Vx, Hx, Wx");
        OPCODE_2_MAP_HANDLER(0x6, 0xE) {
            if (pfx.mand == 0x0)  OPCODE_DQ_BY_REXW("movd Pd, Ey", "movq Pd, Ey");
            if (pfx.mand == 0x66) OPCODE_VDQ_BY_VEXW("vmovd Vy, Ey", "vmovq Vy, Ey");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0x6, 0xF) {
            OPCODE_MAND_RET_NOR(0x0, "movq Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vmovdqa Vx, Wx");
            OPCODE_MAND_RET_NOR(0xF3, "vmovdqu Vx, Wx");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0x7, 0x0) {
            OPCODE_MAND_RET_NOR(0x0, "pshufw Pq, Qq, Ib");
            OPCODE_MAND_RET_NOR(0x66, "vpshufd Vx, Wx, Ib");
            OPCODE_MAND_RET_NOR(0xF3, "vpshufhw Vx, Wx, Ib");
            OPCODE_MAND_RET_NOR(0xF2, "vpshuflw Vx, Wx, Ib");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0x1) {
            return OpcodeDesc::ofExt(0x12, ""); };
        OPCODE_2_MAP_HANDLER(0x7, 0x2) {
            return OpcodeDesc::ofExt(0x13, ""); };
        OPCODE_2_MAP_HANDLER(0x7, 0x3) {
            return OpcodeDesc::ofExt(0x14, ""); };
        OPCODE_2_MAP_HANDLER(0x7, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,   "pcmpeqb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpcmpeqb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "pcmpeqw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpcmpeqw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0x6) {
            OPCODE_MAND_RET_NOR(0x0,   "pcmpeqd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpcmpeqd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0x7) {
            if (pfx.mand == 0) {
                if (pfx.hasVex()) {
                    if (pfx.vexL() == 0) return OpcodeDesc::ofNor("vzeroupper[v]");
                    if (pfx.vexL() == 1) return OpcodeDesc::ofNor("vzeroall[v]");
                } else {
                    return OpcodeDesc::ofNor("emms");
                }
            }
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0x7, 0x8) OPCODE_MAND_NOR(0x0, "VMREAD Ey, Gy");
        OPCODE_2_MAP_HANDLER(0x7, 0x9) OPCODE_MAND_NOR(0x0, "VMWRITE Gy, Ey");
        OPCODE_2_MAP_HANDLER(0x7, 0xC) {
            OPCODE_MAND_RET_NOR(0x66, "vhaddpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF2, "vhaddps Vps, Hps, Wps");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0xD) {
            OPCODE_MAND_RET_NOR(0x66, "vhsubpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF2, "vhsubps Vps, Hps, Wps");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0xE) {
            if (pfx.mand == 0x0)  OPCODE_DQ_BY_REXW("movd Ey, Pd", "movq Ey, Pd");
            if (pfx.mand == 0x66) OPCODE_VDQ_BY_VEXW("vmovd Ey, Vy", "vmovq Ey, Vy")
            OPCODE_MAND_RET_NOR(0xF3, "vmovq Vq, Wq");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0x7, 0xF) {
            OPCODE_MAND_RET_NOR(0x0, "movq Qq, Pq");
            OPCODE_MAND_RET_NOR(0x66, "vmovdqa Wx, Vx");
            OPCODE_MAND_RET_NOR(0xF3, "vmovdqu Wx, Vx");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0x8, 0x0) OPCODE_MAND_NOR(0x0, "JO[f64] Jz");
        OPCODE_2_MAP_HANDLER(0x8, 0x1) OPCODE_MAND_NOR(0x0, "JNO[f64] Jz");
        OPCODE_2_MAP_HANDLER(0x8, 0x2) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.b_nae_c == 0) return OpcodeDesc::ofNor("JB[f64] Jz");
            if (sel_cfg.b_nae_c == 1) return OpcodeDesc::ofNor("JNAE[f64] Jz");
            if (sel_cfg.b_nae_c == 2) return OpcodeDesc::ofNor("JC[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0x3) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nb_ae_nc == 0) return OpcodeDesc::ofNor("JNB[f64] Jz");
            if (sel_cfg.nb_ae_nc == 1) return OpcodeDesc::ofNor("JAE[f64] Jz");
            if (sel_cfg.nb_ae_nc == 2) return OpcodeDesc::ofNor("JNC[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0x4) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.e_z == 0) return OpcodeDesc::ofNor("JE[f64] Jz");
            if (sel_cfg.e_z == 1) return OpcodeDesc::ofNor("JZ[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0x5) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nz_ne == 0) return OpcodeDesc::ofNor("JNZ[f64] Jz");
            if (sel_cfg.nz_ne == 1) return OpcodeDesc::ofNor("JNE[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0x6) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.be_na == 0) return OpcodeDesc::ofNor("JBE[f64] Jz");
            if (sel_cfg.be_na == 1) return OpcodeDesc::ofNor("JNA[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0x7) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nbe_a == 0) return OpcodeDesc::ofNor("JNBE[f64] Jz");
            if (sel_cfg.nbe_a == 1) return OpcodeDesc::ofNor("JA[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0x8) OPCODE_MAND_NOR(0x0, "JS[f64] Jz");
        OPCODE_2_MAP_HANDLER(0x8, 0x9) OPCODE_MAND_NOR(0x0, "JNS[f64] Jz");
        OPCODE_2_MAP_HANDLER(0x8, 0xA) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.p_pe == 0) return OpcodeDesc::ofNor("JP[f64] Jz");
            if (sel_cfg.p_pe == 1) return OpcodeDesc::ofNor("JPE[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0xB) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.np_po == 0) return OpcodeDesc::ofNor("JNP[f64] Jz");
            if (sel_cfg.np_po == 1) return OpcodeDesc::ofNor("JPO[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0xC) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.l_nge == 0) return OpcodeDesc::ofNor("JL[f64] Jz");
            if (sel_cfg.l_nge == 1) return OpcodeDesc::ofNor("JNGE[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0xD) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nl_ge == 0) return OpcodeDesc::ofNor("JNL[f64] Jz");
            if (sel_cfg.nl_ge == 1) return OpcodeDesc::ofNor("JGE[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0xE) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.le_ng == 0) return OpcodeDesc::ofNor("JLE[f64] Jz");
            if (sel_cfg.le_ng == 1) return OpcodeDesc::ofNor("JNG[f64] Jz");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x8, 0xF) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nle_g == 0) return OpcodeDesc::ofNor("JNLE[f64] Jz");
            if (sel_cfg.nle_g == 1) return OpcodeDesc::ofNor("JG[f64] Jz");
        } OPCODE_MAND_HANDLER_END;

        OPCODE_2_MAP_HANDLER(0x9, 0x0) OPCODE_MAND_NOR(0x0, "SETO Eb");
        OPCODE_2_MAP_HANDLER(0x9, 0x1) OPCODE_MAND_NOR(0x0, "SETNO Eb");
        OPCODE_2_MAP_HANDLER(0x9, 0x2) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.b_nae_c == 0) return OpcodeDesc::ofNor("SETB Eb");
            if (sel_cfg.b_nae_c == 1) return OpcodeDesc::ofNor("SETNAE Eb");
            if (sel_cfg.b_nae_c == 2) return OpcodeDesc::ofNor("SETC Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0x3) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nb_ae_nc == 0) return OpcodeDesc::ofNor("SETNB Eb");
            if (sel_cfg.nb_ae_nc == 1) return OpcodeDesc::ofNor("SETAE Eb");
            if (sel_cfg.nb_ae_nc == 2) return OpcodeDesc::ofNor("SETNC Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0x4) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.e_z == 0) return OpcodeDesc::ofNor("SETE Eb");
            if (sel_cfg.e_z == 1) return OpcodeDesc::ofNor("SETZ Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0x5) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nz_ne == 0) return OpcodeDesc::ofNor("SETNZ Eb");
            if (sel_cfg.nz_ne == 1) return OpcodeDesc::ofNor("SETNE Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0x6) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.be_na == 0) return OpcodeDesc::ofNor("SETBE Eb");
            if (sel_cfg.be_na == 1) return OpcodeDesc::ofNor("SETNA Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0x7) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nbe_a == 0) return OpcodeDesc::ofNor("SETNBE Eb");
            if (sel_cfg.nbe_a == 1) return OpcodeDesc::ofNor("SETA Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0x8) OPCODE_MAND_NOR(0x0, "SETS Eb");
        OPCODE_2_MAP_HANDLER(0x9, 0x9) OPCODE_MAND_NOR(0x0, "SETNS Eb");
        OPCODE_2_MAP_HANDLER(0x9, 0xA) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.p_pe == 0) return OpcodeDesc::ofNor("SETP Eb");
            if (sel_cfg.p_pe == 1) return OpcodeDesc::ofNor("SETPE Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0xB) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.np_po == 0) return OpcodeDesc::ofNor("SETNP Eb");
            if (sel_cfg.np_po == 1) return OpcodeDesc::ofNor("SETPO Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0xC) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.l_nge == 0) return OpcodeDesc::ofNor("SETL Eb");
            if (sel_cfg.l_nge == 1) return OpcodeDesc::ofNor("SETNGE Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0xD) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nl_ge == 0) return OpcodeDesc::ofNor("SETNL Eb");
            if (sel_cfg.nl_ge == 1) return OpcodeDesc::ofNor("SETGE Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0xE) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.le_ng == 0) return OpcodeDesc::ofNor("SETLE Eb");
            if (sel_cfg.le_ng == 1) return OpcodeDesc::ofNor("SETNG Eb");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0x9, 0xF) OPCODE_MAND_HANDLER(0x0) {
            if (sel_cfg.nle_g == 0) return OpcodeDesc::ofNor("SETNLE Eb");
            if (sel_cfg.nle_g == 1) return OpcodeDesc::ofNor("SETG Eb");
        } OPCODE_MAND_HANDLER_END;

        OPCODE_2_MAP_HANDLER(0xA, 0x0) OPCODE_MAND_NOR(0x0, "PUSH[d64] FS");
        OPCODE_2_MAP_HANDLER(0xA, 0x1) OPCODE_MAND_NOR(0x0, "POP[d64] FS");
        OPCODE_2_MAP_HANDLER(0xA, 0x2) OPCODE_MAND_NOR(0x0, "CPUID");
        OPCODE_2_MAP_HANDLER(0xA, 0x3) OPCODE_MAND_NOR(0x0, "BT Ev, Gv");
        OPCODE_2_MAP_HANDLER(0xA, 0x4) OPCODE_MAND_NOR(0x0, "SHLD Ev, Gv, Ib");
        OPCODE_2_MAP_HANDLER(0xA, 0x5) OPCODE_MAND_NOR(0x0, "SHLD Ev, Gv, CL");
        OPCODE_2_MAP_HANDLER(0xA, 0x8) OPCODE_MAND_NOR(0x0, "PUSH[d64] GS");
        OPCODE_2_MAP_HANDLER(0xA, 0x9) OPCODE_MAND_NOR(0x0, "POP[d64] GS");
        OPCODE_2_MAP_HANDLER(0xA, 0xA) OPCODE_MAND_NOR(0x0, "RSM");
        OPCODE_2_MAP_HANDLER(0xA, 0xB) OPCODE_MAND_NOR(0x0, "BTS Ev, Gv");
        OPCODE_2_MAP_HANDLER(0xA, 0xC) OPCODE_MAND_NOR(0x0, "SHRD Ev, Gv, Ib");
        OPCODE_2_MAP_HANDLER(0xA, 0xD) OPCODE_MAND_NOR(0x0, "SHRD Ev, Gv, CL");
        OPCODE_2_MAP_HANDLER(0xA, 0xE) OPCODE_MAND_EXT(0x0, 0x15, "");
        OPCODE_2_MAP_HANDLER(0xA, 0xF) OPCODE_MAND_NOR(0x0, "IMUL Gv, Ev");

        OPCODE_2_MAP_HANDLER(0xB, 0x0) OPCODE_MAND_NOR(0x0, "CMPXCHG Eb, Gb");
        OPCODE_2_MAP_HANDLER(0xB, 0x1) OPCODE_MAND_NOR(0x0, "CMPXCHG Ev, Gv");
        OPCODE_2_MAP_HANDLER(0xB, 0x2) OPCODE_MAND_NOR(0x0, "LSS Gv, Mp");
        OPCODE_2_MAP_HANDLER(0xB, 0x3) OPCODE_MAND_NOR(0x0, "BTR Ev, Gv");
        OPCODE_2_MAP_HANDLER(0xB, 0x4) OPCODE_MAND_NOR(0x0, "LFS Gv, Mp");
        OPCODE_2_MAP_HANDLER(0xB, 0x5) OPCODE_MAND_NOR(0x0, "LGS Gv, Mp");
        OPCODE_2_MAP_HANDLER(0xB, 0x6) OPCODE_MAND_NOR(0x0, "MOVZX Gv, Eb");
        OPCODE_2_MAP_HANDLER(0xB, 0x7) OPCODE_MAND_NOR(0x0, "MOVZX Gv, Ew");
        OPCODE_2_MAP_HANDLER(0xB, 0x8) {
            OPCODE_MAND_RET_NOR(0x0, "JMPE(reserved)");
            OPCODE_MAND_RET_NOR(0xF3, "POPCNT Gv, Ev");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xB, 0x9) {
            return OpcodeDesc::ofExt(0x10, "UD2(Alt)"); };
        OPCODE_2_MAP_HANDLER(0xB, 0xA) {
            return OpcodeDesc::ofExt(0x8, "Ev, Ib"); };
        OPCODE_2_MAP_HANDLER(0xB, 0xB) OPCODE_MAND_NOR(0x0, "BTC Ev, Gv");
        OPCODE_2_MAP_HANDLER(0xB, 0xC) {
            OPCODE_MAND_RET_NOR(0x0, "BSF Gv, Ev");
            OPCODE_MAND_RET_NOR(0xF3, "TZCNT Gv, Ev");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xB, 0xD) {
            OPCODE_MAND_RET_NOR(0x0, "BSR Gv, Ev");
            OPCODE_MAND_RET_NOR(0xF3, "LZCNT Gv, Ev");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xB, 0xE) {
            OPCODE_MAND_RET_NOR(0x0, "MOVSX Gv, Eb");
            OPCODE_MAND_RET_NOR(0xF3, "MOVSX Gv, Eb");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xB, 0xF) {
            OPCODE_MAND_RET_NOR(0x0, "MOVSX Gv, Ew");
            OPCODE_MAND_RET_NOR(0xF3, "MOVSX Gv, Ew");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0xC, 0x0) OPCODE_MAND_NOR(0x0, "XADD Eb, Gb");
        OPCODE_2_MAP_HANDLER(0xC, 0x1) OPCODE_MAND_NOR(0x0, "XADD Ev, Gv");
        OPCODE_2_MAP_HANDLER(0xC, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,  "vcmpps Vps, Hps, Wps, Ib");
            OPCODE_MAND_RET_NOR(0x66, "vcmppd Vpd, Hpd, Wpd, Ib");
            OPCODE_MAND_RET_NOR(0xF3, "vcmpss Vss, Hss, Wss, Ib");
            OPCODE_MAND_RET_NOR(0xF2, "vcmpsd Vsd, Hsd, Wsd, Ib");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xC, 0x3) OPCODE_MAND_NOR(0x0, "movnti My, Gy");
        OPCODE_2_MAP_HANDLER(0xC, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,   "pinsrw Pq, Ry/Mw, Ib");
            OPCODE_MAND_RET_NOR(0x66, "vpinsrw Vdq, Hdq, Ry/Mw, Ib");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xC, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "pextrw Gd, Nq, Ib");
            OPCODE_MAND_RET_NOR(0x66, "vpextrw Gd, Udq, Ib");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xC, 0x6) {
            OPCODE_MAND_RET_NOR(0x0,  "vshufps Vps, Hps, Wps, Ib");
            OPCODE_MAND_RET_NOR(0x66, "vshufpd Vpd, Hpd, Wpd, Ib");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xC, 0x7) {
            return OpcodeDesc::ofExt(0x9, ""); };
        OPCODE_2_MAP_HANDLER(0xC, 0x8) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R8" : "BSWAP RAX");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R8D" : "BSWAP EAX");
            }
            return OpcodeDesc::ofNor("BSWAP EAX");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0x9) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R9" : "BSWAP RCX");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R9D" : "BSWAP ECX");
            }
            return OpcodeDesc::ofNor("BSWAP ECX");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0xA) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R10" : "BSWAP RDX");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R10D" : "BSWAP EDX");
            }
            return OpcodeDesc::ofNor("BSWAP EDX");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0xB) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R11" : "BSWAP RBX");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R11D" : "BSWAP EBX");
            }
            return OpcodeDesc::ofNor("BSWAP EBX");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0xC) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R12" : "BSWAP RSP");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R12D" : "BSWAP ESP");
            }
            return OpcodeDesc::ofNor("BSWAP ESP");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0xD) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R13" : "BSWAP RBP");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R13D" : "BSWAP EBP");
            }
            return OpcodeDesc::ofNor("BSWAP EBP");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0xE) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R14" : "BSWAP RSI");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R14D" : "BSWAP ESI");
            }
            return OpcodeDesc::ofNor("BSWAP ESI");
        } OPCODE_MAND_HANDLER_END;
        OPCODE_2_MAP_HANDLER(0xC, 0xF) OPCODE_MAND_HANDLER(0x0) {
            if (pfx.hasRex()) {
                if (pfx.rexW()) return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R15" : "BSWAP RDI");
                return OpcodeDesc::ofNor(pfx.rexB() ? "BSWAP R15D" : "BSWAP EDI");
            }
            return OpcodeDesc::ofNor("BSWAP EDI");
        } OPCODE_MAND_HANDLER_END;

        OPCODE_2_MAP_HANDLER(0xD, 0x0) {
            OPCODE_MAND_RET_NOR(0x66, "vaddsubpd Vpd, Hpd, Wpd");
            OPCODE_MAND_RET_NOR(0xF2, "vaddsubps Vps, Hps, Wps");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,   "psrlw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsrlw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,   "psrld Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsrld Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,   "psrlq Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsrlq Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,   "paddq Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddq Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "pmullw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmullw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x6) {
            OPCODE_MAND_RET_NOR(0x66, "vmovvq Wq, Vq");
            OPCODE_MAND_RET_NOR(0xF3, "movq2dq Vdq, Nq");
            OPCODE_MAND_RET_NOR(0xF2, "movdq2q Pq, Uq");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,   "pmovmskb Gd, Nq");
            OPCODE_MAND_RET_NOR(0x66, "vpmovmskb Gd, Ux");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,   "psubusb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubusb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,   "psubusw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubusw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,   "pminub Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpminub Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,   "pand Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpand Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0xC) {
            OPCODE_MAND_RET_NOR(0x0,   "paddusb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddusb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0xD) {
            OPCODE_MAND_RET_NOR(0x0,   "paddusw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddusw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0xE) {
            OPCODE_MAND_RET_NOR(0x0,   "pmaxub Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmaxub Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xD, 0xF) {
            OPCODE_MAND_RET_NOR(0x0,   "pandn Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpandn Vx, Hx, Wx");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0xE, 0x0) {
            OPCODE_MAND_RET_NOR(0x0,   "pavgb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpavgb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,   "psraw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsraw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,   "psrad Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsrad Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,   "pavgw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpavgw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,   "pmulhuw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmulhuw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "pmulhw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmulhw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x6) {
            OPCODE_MAND_RET_NOR(0x66, "vcvttpd2dq Vx, Wpd");
            OPCODE_MAND_RET_NOR(0xF3, "vcvtdq2pd Vx, Wpd");
            OPCODE_MAND_RET_NOR(0xF2, "vcvtpd2dq Vx, Wpd");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,   "movntq Mq, Pq");
            OPCODE_MAND_RET_NOR(0x66, "vmovntdq Mx, Vx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,   "psubsb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubsb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,   "psubsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,   "pminsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpminsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,   "por Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpor Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0xC) {
            OPCODE_MAND_RET_NOR(0x0,   "paddsb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddsb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0xD) {
            OPCODE_MAND_RET_NOR(0x0,   "paddsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0xE) {
            OPCODE_MAND_RET_NOR(0x0,   "pmaxsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmaxsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_2_MAP_HANDLER(0xE, 0xF) {
            OPCODE_MAND_RET_NOR(0x0,   "pxor Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpxor Vx, Hx, Wx");
            RET_UND; };

        OPCODE_2_MAP_HANDLER(0xF, 0x0) OPCODE_MAND_NOR(0xF2, "vlddqu Vx, Mx");
        OPCODE_2_MAP_HANDLER(0xF, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,   "psllw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsllw Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,   "pslld Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpslld Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,   "psllq Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsllq Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,   "pmuludq Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmuludq Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "pmaddwd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmaddwd Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x6) {
            OPCODE_MAND_RET_NOR(0x0,   "psadbw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsadbw Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,   "maskmovq Pq, Nq");
            OPCODE_MAND_RET_NOR(0x66, "vmaskmovdqu Vdq, Udq");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,   "psubb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubb Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,   "psubw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubw Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,   "psubd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubd Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,   "psubq Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsubq Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0xC) {
            OPCODE_MAND_RET_NOR(0x0,   "paddb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddb Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0xD) {
            OPCODE_MAND_RET_NOR(0x0,   "paddw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddw Vx, Hx, Wx");
            RET_UND;
        };
        OPCODE_2_MAP_HANDLER(0xF, 0xE) {
            OPCODE_MAND_RET_NOR(0x0,   "paddd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpaddd Vx, Hx, Wx");
            RET_UND;
        };
    }

    void initThreeByteOpcodeMap() {
        // 38H
        OPCODE_38H_MAP_HANDLER(0x0, 0x0) {
            OPCODE_MAND_RET_NOR(0x0,   "pshufb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpshufb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x1) {
            OPCODE_MAND_RET_NOR(0x0,   "phaddw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vphaddw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x2) {
            OPCODE_MAND_RET_NOR(0x0,   "phaddd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vphaddd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x3) {
            OPCODE_MAND_RET_NOR(0x0,   "phaddsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vphaddsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x4) {
            OPCODE_MAND_RET_NOR(0x0,   "pmaddubsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmaddubsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x5) {
            OPCODE_MAND_RET_NOR(0x0,   "phsubw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vphsubw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x6) {
            OPCODE_MAND_RET_NOR(0x0,   "phsubd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vphsubd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x7) {
            OPCODE_MAND_RET_NOR(0x0,   "phsubsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vphsubsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x8) {
            OPCODE_MAND_RET_NOR(0x0,   "psignb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsignb Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0x9) {
            OPCODE_MAND_RET_NOR(0x0,   "psignw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsignw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0xA) {
            OPCODE_MAND_RET_NOR(0x0,   "psignd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpsignd Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0xB) {
            OPCODE_MAND_RET_NOR(0x0,   "pmulhrsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpmulhrsw Vx, Hx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x0, 0xC) OPCODE_MAND_NOR(0x66, "vpermilps[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x0, 0xD) OPCODE_MAND_NOR(0x66, "vpermilpd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x0, 0xE) OPCODE_MAND_NOR(0x66, "vtestps[v] Vx, Wx");
        OPCODE_38H_MAP_HANDLER(0x0, 0xF) OPCODE_MAND_NOR(0x66, "vtestpd[v] Vx, Wx");

        OPCODE_38H_MAP_HANDLER(0x1, 0x0) OPCODE_MAND_NOR(0x66, "pblendvb Vdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0x1, 0x3) OPCODE_MAND_NOR(0x66, "vcvtph2ps[v] Vx, Wx, Ib");
        OPCODE_38H_MAP_HANDLER(0x1, 0x4) OPCODE_MAND_NOR(0x66, "blendvps Vdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0x1, 0x5) OPCODE_MAND_NOR(0x66, "blendvpd Vdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0x1, 0x6) OPCODE_MAND_NOR(0x66, "vpermps[v] Vqq, Hqq, Wqq");
        OPCODE_38H_MAP_HANDLER(0x1, 0x7) OPCODE_MAND_NOR(0x66, "vptest Vx, Wx");
        OPCODE_38H_MAP_HANDLER(0x1, 0x8) OPCODE_MAND_NOR(0x66, "vbroadcastss[v] Vx, Wd");
        OPCODE_38H_MAP_HANDLER(0x1, 0x9) OPCODE_MAND_NOR(0x66, "vbroadcastsd[v] Vqq, Mdq");
        OPCODE_38H_MAP_HANDLER(0x1, 0xA) OPCODE_MAND_NOR(0x66, "vbroadcastf128[v] Vqq, Mdq");
        OPCODE_38H_MAP_HANDLER(0x1, 0xC) {
            OPCODE_MAND_RET_NOR(0x0,   "pabsb Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpabsb Vx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x1, 0xD) {
            OPCODE_MAND_RET_NOR(0x0,   "pabsw Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpabsw Vx, Wx");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0x1, 0xE) {
            OPCODE_MAND_RET_NOR(0x0,   "pabsd Pq, Qq");
            OPCODE_MAND_RET_NOR(0x66, "vpabsd Vx, Wx");
            RET_UND; };

        OPCODE_38H_MAP_HANDLER(0x2, 0x0) OPCODE_MAND_NOR(0x66, "vpmovsxbw Vx, Ux/Mq");
        OPCODE_38H_MAP_HANDLER(0x2, 0x1) OPCODE_MAND_NOR(0x66, "vpmovsxbd Vx, Ux/Md");
        OPCODE_38H_MAP_HANDLER(0x2, 0x2) OPCODE_MAND_NOR(0x66, "vpmovsxbq Vx, Ux/Mw");
        OPCODE_38H_MAP_HANDLER(0x2, 0x3) OPCODE_MAND_NOR(0x66, "vpmovsxwd Vx, Ux/Mq");
        OPCODE_38H_MAP_HANDLER(0x2, 0x4) OPCODE_MAND_NOR(0x66, "vpmovsxwq Vx, Ux/Md");
        OPCODE_38H_MAP_HANDLER(0x2, 0x5) OPCODE_MAND_NOR(0x66, "vpmovsxdq Vx, Ux/Mq");
        OPCODE_38H_MAP_HANDLER(0x2, 0x8) OPCODE_MAND_NOR(0x66, "vpmuldq Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x2, 0x9) OPCODE_MAND_NOR(0x66, "vpcmpeqq Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x2, 0xA) OPCODE_MAND_NOR(0x66, "vmovntdqa Vx, Mx");
        OPCODE_38H_MAP_HANDLER(0x2, 0xB) OPCODE_MAND_NOR(0x66, "vpackusdw Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x2, 0xC) OPCODE_MAND_NOR(0x66, "vmaskmovps[v] Vx,Hx,Mx");
        OPCODE_38H_MAP_HANDLER(0x2, 0xD) OPCODE_MAND_NOR(0x66, "vmaskmovpd[v] Vx, Hx, Mx");
        OPCODE_38H_MAP_HANDLER(0x2, 0xE) OPCODE_MAND_NOR(0x66, "vmaskmovps[v] Mx, Hx, Vx");
        OPCODE_38H_MAP_HANDLER(0x2, 0xF) OPCODE_MAND_NOR(0x66, "vmaskmovpd[v] Mx, Hx, Vx");

        OPCODE_38H_MAP_HANDLER(0x3, 0x0) OPCODE_MAND_NOR(0x66, "vpmovzxbw Vx, Ux/Mq");
        OPCODE_38H_MAP_HANDLER(0x3, 0x1) OPCODE_MAND_NOR(0x66, "vpmovzxbd Vx, Ux/Md");
        OPCODE_38H_MAP_HANDLER(0x3, 0x2) OPCODE_MAND_NOR(0x66, "vpmovzxbq Vx, Ux/Mw");
        OPCODE_38H_MAP_HANDLER(0x3, 0x3) OPCODE_MAND_NOR(0x66, "vpmovzxwd Vx, Ux/Mq");
        OPCODE_38H_MAP_HANDLER(0x3, 0x4) OPCODE_MAND_NOR(0x66, "vpmovzxwq Vx, Ux/Md");
        OPCODE_38H_MAP_HANDLER(0x3, 0x5) OPCODE_MAND_NOR(0x66, "vpmovzxdq Vx, Ux/Mq");
        OPCODE_38H_MAP_HANDLER(0x3, 0x6) OPCODE_MAND_NOR(0x66, "vpermd[v] Vqq, Hqq, Wqq");
        OPCODE_38H_MAP_HANDLER(0x3, 0x7) OPCODE_MAND_NOR(0x66, "vpcmpgtq Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0x8) OPCODE_MAND_NOR(0x66, "vpminsb Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0x9) OPCODE_MAND_NOR(0x66, "vpminsd Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0xA) OPCODE_MAND_NOR(0x66, "vpminuw Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0xB) OPCODE_MAND_NOR(0x66, "vpminud Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0xC) OPCODE_MAND_NOR(0x66, "vpmaxsb Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0xD) OPCODE_MAND_NOR(0x66, "vpmaxsd Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0xE) OPCODE_MAND_NOR(0x66, "vpmaxuw Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x3, 0xF) OPCODE_MAND_NOR(0x66, "vpmaxud Vx, Hx, Wx");

        OPCODE_38H_MAP_HANDLER(0x4, 0x0) OPCODE_MAND_NOR(0x66, "vpmulld Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x4, 0x1) OPCODE_MAND_NOR(0x66, "vphminposuw Vdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0x4, 0x5) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vpsrlvd Vx, Hx, Wx", "vpsrlvq[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x4, 0x6) OPCODE_MAND_NOR(0x66, "vpsravd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x4, 0x7) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vpsllvd Vx, Hx, Wx", "vpsllvq[v] Vx, Hx, Wx");

        OPCODE_38H_MAP_HANDLER(0x5, 0x8) OPCODE_MAND_NOR(0x66, "vpbroadcastd[v] Vx, Wx");
        OPCODE_38H_MAP_HANDLER(0x5, 0x9) OPCODE_MAND_NOR(0x66, "vpbroadcastq[v] Vx, Wx");
        OPCODE_38H_MAP_HANDLER(0x5, 0xA) OPCODE_MAND_NOR(0x66, "vbroadcasti128[v] Vqq, Mdq");

        OPCODE_38H_MAP_HANDLER(0x7, 0x8) OPCODE_MAND_NOR(0x66, "vpbroadcastb[v] Vx, Wx");
        OPCODE_38H_MAP_HANDLER(0x7, 0x9) OPCODE_MAND_NOR(0x66, "vpbroadcastw[v] Vx, Wx");

        OPCODE_38H_MAP_HANDLER(0x8, 0x0) OPCODE_MAND_NOR(0x66, "INVEPT Gy, Mdq");
        OPCODE_38H_MAP_HANDLER(0x8, 0x1) OPCODE_MAND_NOR(0x66, "INVVPID Gy, Mdq");
        OPCODE_38H_MAP_HANDLER(0x8, 0x2) OPCODE_MAND_NOR(0x66, "INVPCID Gy, Mdq");
        OPCODE_38H_MAP_HANDLER(0x8, 0xC) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vpmaskmovd Vx, Hx, Mx", "vpmaskmovq[v] Vx, Hx, Mx");
        OPCODE_38H_MAP_HANDLER(0x8, 0xE) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vpmaskmovd Mx, Vx, Hx", "vpmaskmovq[v] Mx, Vx, Hx");

        OPCODE_38H_MAP_HANDLER(0x9, 0x0) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vgatherdd Vx, Hx, Wx", "vgatherdq[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x1) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vgatherqd Vx, Hx, Wx", "vgatherqq[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x2) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vgatherdps Vx, Hx, Wx", "vgatherdpd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x3) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vgatherqps Vx, Hx, Wx", "vgatherqpd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x6) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmaddsub132ps Vx, Hx, Wx", "vfmaddsub132pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x7) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsubadd132ps Vx, Hx, Wx", "vfmsubadd132pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x8) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmadd132ps Vx, Hx, Wx", "vfmadd132pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0x9) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmadd132ss Vx, Hx, Wx", "vfmadd132sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0xA) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsub132ps Vx, Hx, Wx", "vfmsub132pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0xB) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsub132ss Vx, Hx, Wx", "vfmsub132sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0xC) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmadd132ps Vx, Hx, Wx", "vfnmadd132pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0xD) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmadd132ss Vx, Hx, Wx", "vfnmadd132sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0xE) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmsub132ps Vx, Hx, Wx", "vfnmsub132pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0x9, 0xF) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmsub132ss Vx, Hx, Wx", "vfnmsub132sd[v] Vx, Hx, Wx");

        OPCODE_38H_MAP_HANDLER(0xA, 0x6) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmaddsub213ps Vx, Hx, Wx", "vfmaddsub213pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0x7) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsubadd213ps Vx, Hx, Wx", "vfmsubadd213pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0x8) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmadd213ps Vx, Hx, Wx", "vfmadd213pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0x9) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmadd213ss Vx, Hx, Wx", "vfmadd213sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0xA) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsub213ps Vx, Hx, Wx", "vfmsub213pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0xB) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsub213ss Vx, Hx, Wx", "vfmsub213sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0xC) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmadd213ps Vx, Hx, Wx", "vfnmadd213pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0xD) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmadd213ss Vx, Hx, Wx", "vfnmadd213sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0xE) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmsub213ps Vx, Hx, Wx", "vfnmsub213pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xA, 0xF) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmsub213ss Vx, Hx, Wx", "vfnmsub213sd[v] Vx, Hx, Wx");

        OPCODE_38H_MAP_HANDLER(0xB, 0x6) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmaddsub231ps Vx, Hx, Wx", "vfmaddsub231pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0x7) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsubadd231ps Vx, Hx, Wx", "vfmsubadd231pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0x8) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmadd231ps Vx, Hx, Wx", "vfmadd231pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0x9) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmadd231ss Vx, Hx, Wx", "vfmadd231sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0xA) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsub231ps Vx, Hx, Wx", "vfmsub231pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0xB) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfmsub231ss Vx, Hx, Wx", "vfmsub231sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0xC) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmadd231ps Vx, Hx, Wx", "vfnmadd231pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0xD) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmadd231ss Vx, Hx, Wx", "vfnmadd231sd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0xE) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmsub231ps Vx, Hx, Wx", "vfnmsub231pd[v] Vx, Hx, Wx");
        OPCODE_38H_MAP_HANDLER(0xB, 0xF) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vfnmsub231ss Vx, Hx, Wx", "vfnmsub231sd[v] Vx, Hx, Wx");

        OPCODE_38H_MAP_HANDLER(0xD, 0xB) OPCODE_MAND_NOR(0x66, "VAESIMC Vdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0xD, 0xC) OPCODE_MAND_NOR(0x66, "VAESENC Vdq, Hdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0xD, 0xD) OPCODE_MAND_NOR(0x66, "VAESENCLAST Vdq, Hdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0xD, 0xE) OPCODE_MAND_NOR(0x66, "VAESDEC Vdq, Hdq, Wdq");
        OPCODE_38H_MAP_HANDLER(0xD, 0xF) OPCODE_MAND_NOR(0x66, "VAESDECLAST Vdq, Hdq, Wdq");

        OPCODE_38H_MAP_HANDLER(0xF, 0x0) {
            OPCODE_MAND_RET_NOR(0x0, "MOVBE Gy, My");
            OPCODE_MAND_RET_NOR(0x66, "MOVBE Gw, Mw");
            OPCODE_MAND_RET_NOR(0xF2, "CRC32 Gd, Eb");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0xF, 0x1) {
            OPCODE_MAND_RET_NOR(0x0, "MOVBE My, Gy");
            OPCODE_MAND_RET_NOR(0x66, "MOVBE Mw, Gw");
            if (pfx.mand == 0xF2) {
                if (pfx.g3 == 0x66) return OpcodeDesc::ofNor("CRC32 Gd, Ew");
                return OpcodeDesc::ofNor("CRC32 Gd, Ey");
            }
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0xF, 0x2) {
            OPCODE_MAND_RET_NOR(0x0, "MOVBE Gy, My");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0xF, 0x3) {
            return OpcodeDesc::ofExt(0x17, ""); };
        OPCODE_38H_MAP_HANDLER(0xF, 0x5) {
            OPCODE_MAND_RET_NOR(0x0, "BZHI[v] Gy, Ey, By");
            OPCODE_MAND_RET_NOR(0xF3, "PEXT[v] Gy, By, Ey");
            OPCODE_MAND_RET_NOR(0xF2, "PDEP[v] Gy, By, Ey");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0xF, 0x6) {
            OPCODE_MAND_RET_NOR(0x66, "ADCX Gy, Ey");
            OPCODE_MAND_RET_NOR(0xF3, "ADOX Gy, Ey");
            OPCODE_MAND_RET_NOR(0xF2, "MULX[v] By, Gy, rDX, Ey");
            RET_UND; };
        OPCODE_38H_MAP_HANDLER(0xF, 0x7) {
            OPCODE_MAND_RET_NOR(0x0, "BEXTR[v] Gy, Ey, By");
            OPCODE_MAND_RET_NOR(0x66, "SHLX[v] Gy, Ey, By");
            OPCODE_MAND_RET_NOR(0xF3, "SARX[v] Gy, Ey, By");
            OPCODE_MAND_RET_NOR(0xF2, "SHRX[v] Gy, Ey, By");
            RET_UND; };

        // 3AH
        OPCODE_3AH_MAP_HANDLER(0x0, 0x0) OPCODE_MAND_NOR(0x66, "vpermq[v] Vqq, Wqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x1) OPCODE_MAND_NOR(0x66, "vpermpd[v] Vqq, Wqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x2) OPCODE_MAND_NOR(0x66, "vpblendd[v] Vx, Hx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x4) OPCODE_MAND_NOR(0x66, "vpermilps[v] Vx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x5) OPCODE_MAND_NOR(0x66, "vpermilpd[v] Vx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x6) OPCODE_MAND_NOR(0x66, "vperm2f128[v] Vqq, Hqq, Wqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x8) OPCODE_MAND_NOR(0x66, "vroundps Vx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0x9) OPCODE_MAND_NOR(0x66, "vroundpd Vx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0xA) OPCODE_MAND_NOR(0x66, "vroundss Vss, Wss, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0xB) OPCODE_MAND_NOR(0x66, "vroundsd Vsd, Wsd, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0xC) OPCODE_MAND_NOR(0x66, "vblendps Vx, Hx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0xD) OPCODE_MAND_NOR(0x66, "vblendpd Vx, Hx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0xE) OPCODE_MAND_NOR(0x66, "vpblendw Vx, Hx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x0, 0xF) {
            OPCODE_MAND_RET_NOR(0x0,   "palignr Pq, Qq, Ib");
            OPCODE_MAND_RET_NOR(0x66, "vpalignr Vx, Hx, Wx, Ib");
            RET_UND; };

        OPCODE_3AH_MAP_HANDLER(0x1, 0x4) OPCODE_MAND_NOR(0x66, "vpextrb Rd/Mb, Vdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x1, 0x5) OPCODE_MAND_NOR(0x66, "vpextrw Rd/Mb, Vdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x1, 0x6) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vpextrd Ey, Vdq, Ib", "vpextrq Ey, Vdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x1, 0x7) OPCODE_MAND_NOR(0x66, "vextractps Ed, Vdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x1, 0x8) OPCODE_MAND_NOR(0x66, "vinsertf128[v] Vqq, Hqq, Wqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x1, 0x9) OPCODE_MAND_NOR(0x66, "vextractf128[v] Wdq, Vqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x1, 0xD) OPCODE_MAND_NOR(0x66, "vcvtps2ph[v] Wx, Vx, Ib");

        OPCODE_3AH_MAP_HANDLER(0x2, 0x0) OPCODE_MAND_NOR(0x66, "vpinsrb Vdq, Hdq, Ry/Mb, Ib");
        OPCODE_3AH_MAP_HANDLER(0x2, 0x1) OPCODE_MAND_NOR(0x66, "vinsertps Vdq, Hdq, Udq/Md, Ib");
        OPCODE_3AH_MAP_HANDLER(0x2, 0x2) OPCODE_MAND_VDQ_BY_VEXW(0x66, "vpinsrd Vdq, Hdq, Ey, Ib", "vpinsrq Vdq, Hdq, Ey, Ib");

        OPCODE_3AH_MAP_HANDLER(0x3, 0x8) OPCODE_MAND_NOR(0x66, "vinserti128[v] Vqq, Hqq, Wqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x3, 0x9) OPCODE_MAND_NOR(0x66, "vextracti128[v] Wdq, Vqq, Ib");

        OPCODE_3AH_MAP_HANDLER(0x4, 0x0) OPCODE_MAND_NOR(0x66, "vdpps Vx, Hx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x4, 0x1) OPCODE_MAND_NOR(0x66, "vdppd Vdq, Hdq, Wdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x4, 0x2) OPCODE_MAND_NOR(0x66, "vmpsadbw Vx, Hx, Wx, Ib");
        OPCODE_3AH_MAP_HANDLER(0x4, 0x4) OPCODE_MAND_NOR(0x66, "vpclmulqdq Vdq, Hdq, Wdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x4, 0x6) OPCODE_MAND_NOR(0x66, "vperm2i128[v] Vqq, Hqq, Wqq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x4, 0xA) OPCODE_MAND_NOR(0x66, "vblendvps[v] Vx, Hx, Wx, Lx");
        OPCODE_3AH_MAP_HANDLER(0x4, 0xB) OPCODE_MAND_NOR(0x66, "vblendvpd[v] Vx, Hx, Wx, Lx");
        OPCODE_3AH_MAP_HANDLER(0x4, 0xC) OPCODE_MAND_NOR(0x66, "vpblendvb[v] Vx, Hx, Wx, Lx");

        OPCODE_3AH_MAP_HANDLER(0x6, 0x0) OPCODE_MAND_NOR(0x66, "vpcmpestrm Vdq, Wdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x6, 0x1) OPCODE_MAND_NOR(0x66, "vpcmpestri Vdq, Wdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x6, 0x2) OPCODE_MAND_NOR(0x66, "vpcmpistrm Vdq, Wdq, Ib");
        OPCODE_3AH_MAP_HANDLER(0x6, 0x3) OPCODE_MAND_NOR(0x66, "vpcmpistri Vdq, Wdq, Ib");

        OPCODE_3AH_MAP_HANDLER(0xD, 0xF) OPCODE_MAND_NOR(0x66, "VAESKEYGEN Vdq, Wdq, Ib");

        OPCODE_3AH_MAP_HANDLER(0xF, 0x0) OPCODE_MAND_NOR(0xF2, "RORX[v] Gy, Ey, Ib");
    }

    void initExtensionOpcodeMap() {
        OPCODE_EXTENSIONS_HANDLER(0x1) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0: return OpcodeDesc::ofNor("ADD");
            case 0x1: return OpcodeDesc::ofNor("OR");
            case 0x2: return OpcodeDesc::ofNor("ADC");
            case 0x3: return OpcodeDesc::ofNor("SBB");
            case 0x4: return OpcodeDesc::ofNor("AND");
            case 0x5: return OpcodeDesc::ofNor("SUB");
            case 0x6: return OpcodeDesc::ofNor("XOR");
            case 0x7: return OpcodeDesc::ofNor("CMP");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x1A) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0: return OpcodeDesc::ofNor("POP[d64]");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x2) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0: return OpcodeDesc::ofNor("ROL");
            case 0x1: return OpcodeDesc::ofNor("ROR");
            case 0x2: return OpcodeDesc::ofNor("RCL");
            case 0x3: return OpcodeDesc::ofNor("RCR");
            case 0x4:
                if (sel_cfg.use_sal) return OpcodeDesc::ofNor("SAL");
                return OpcodeDesc::ofNor("SHL");
            case 0x5: return OpcodeDesc::ofNor("SHR");
            case 0x7: return OpcodeDesc::ofNor("SAR");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x3) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0:
                if (opcode == 0xF6) return OpcodeDesc::ofNor("TEST Eb, Ib");
                if (opcode == 0xF7) return OpcodeDesc::ofNor("TEST Ev, Iz");
            case 0x2: return OpcodeDesc::ofNor("NOT");
            case 0x3: return OpcodeDesc::ofNor("NEG");
            case 0x4:
                if (opcode == 0xF6) return OpcodeDesc::ofNor("MUL Eb");
                if (opcode == 0xF7) return OpcodeDesc::ofNor("MUL Ev");
            case 0x5:
                if (opcode == 0xF6) return OpcodeDesc::ofNor("IMUL Eb");
                if (opcode == 0xF7) return OpcodeDesc::ofNor("IMUL Ev");
            case 0x6:
                if (opcode == 0xF6) return OpcodeDesc::ofNor("DIV Eb");
                if (opcode == 0xF7) return OpcodeDesc::ofNor("DIV Ev");
            case 0x7:
                if (opcode == 0xF6) return OpcodeDesc::ofNor("IDIV Eb");
                if (opcode == 0xF7) return OpcodeDesc::ofNor("IDIV Ev");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x4) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0: return OpcodeDesc::ofNor("INC Eb");
            case 0x1: return OpcodeDesc::ofNor("DEC Eb");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x5) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0: return OpcodeDesc::ofNor("INC Ev");
            case 0x1: return OpcodeDesc::ofNor("DEC Ev");
            case 0x2: return OpcodeDesc::ofNor("CALL(N)[f64] Ev");
            case 0x3: return OpcodeDesc::ofNor("CALL(F) Ep");
            case 0x4: return OpcodeDesc::ofNor("JMP(N)[f64] Ev");
            case 0x5: return OpcodeDesc::ofNor("JMP(F) Mp");
            case 0x6: return OpcodeDesc::ofNor("PUSH[d64] Ev");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x6) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x0: return OpcodeDesc::ofNor("SLDT Rv/Mw");
            case 0x1: return OpcodeDesc::ofNor("STR Rv/Mw");
            case 0x2: return OpcodeDesc::ofNor("LLDT Ew");
            case 0x3: return OpcodeDesc::ofNor("LTR Ew");
            case 0x4: return OpcodeDesc::ofNor("VERR Ew");
            case 0x5: return OpcodeDesc::ofNor("VERW Ew");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x7) {
            uint8_t rm = modrm & 0x7;
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod != 0x3) {
                switch (ro) {
                case 0x0: return OpcodeDesc::ofNor("SGDT Ms");
                case 0x1: return OpcodeDesc::ofNor("SIDT Ms");
                case 0x2: return OpcodeDesc::ofNor("LGDT Ms");
                case 0x3: return OpcodeDesc::ofNor("LIDT Ms");
                case 0x4: return OpcodeDesc::ofNor("SMSW Mw/Rv");
                case 0x6: return OpcodeDesc::ofNor("LMSW Ew");
                case 0x7: return OpcodeDesc::ofNor("INVLPG Mb");
                default: break;
                }
            } else {
                switch (ro) {
                case 0x0:
                    switch (rm) {
                    case 0x1: return OpcodeDesc::ofNor("VMCALL");
                    case 0x2: return OpcodeDesc::ofNor("VMLAUNCH");
                    case 0x3: return OpcodeDesc::ofNor("VMRESUME");
                    case 0x4: return OpcodeDesc::ofNor("VMXOFF");
                    default: break;
                    }
                    break;
                case 0x1:
                    switch (rm) {
                    case 0x0: return OpcodeDesc::ofNor("MONITOR");
                    case 0x1: return OpcodeDesc::ofNor("MWAIT");
                    case 0x2: return OpcodeDesc::ofNor("CLAC");
                    case 0x3: return OpcodeDesc::ofNor("STAC");
                    default: break;
                    }
                    break;
                case 0x2:
                    switch (rm) {
                    case 0x0: return OpcodeDesc::ofNor("XGETBV");
                    case 0x1: return OpcodeDesc::ofNor("XSETBV");
                    case 0x4: return OpcodeDesc::ofNor("VMFUNC");
                    case 0x5: return OpcodeDesc::ofNor("XEND");
                    case 0x6: return OpcodeDesc::ofNor("XTEST");
                    default: break;
                    }
                    break;
                case 0x7:
                    switch (rm) {
                    case 0x0: return OpcodeDesc::ofNor("SWAPGS[o64]");
                    case 0x1: return OpcodeDesc::ofNor("RDTSCP");
                    default: break;
                    }
                    break;
                default: break;
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x8) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x4: return OpcodeDesc::ofNor("BT");
            case 0x5: return OpcodeDesc::ofNor("BTS");
            case 0x6: return OpcodeDesc::ofNor("BTR");
            case 0x7: return OpcodeDesc::ofNor("BTC");
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x9) {
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod != 0x3) {
                if (pfx.mand == 0x0) {
                    switch (ro) {
                    case 0x1: {
                        bool rexw = false;
                        if (pfx.rex) if (pfx.rex & 0x8) rexw = true;
                        if(rexw) return OpcodeDesc::ofNor("CMPXCHG16B Mdq");
                        return OpcodeDesc::ofNor("CMPXCHG8B Mq");
                    }
                    case 0x6: return OpcodeDesc::ofNor("VMPTRLD Mq");
                    case 0x7: return OpcodeDesc::ofNor("VMPTRST Mq");
                    default: break;
                    }
                } else if (pfx.mand == 0x66) {
                    switch (ro) {
                    case 0x6: return OpcodeDesc::ofNor("VMCLEAR Mq");
                    default: break;
                    }
                } else if (pfx.mand == 0xF3) {
                    switch (ro) {
                    case 0x6: return OpcodeDesc::ofNor("VMXON Mq");
                    case 0x7: return OpcodeDesc::ofNor("VMPTRST Mq");
                    default: break;
                    }
                }
            } else {
                switch (ro) {
                case 0x6: return OpcodeDesc::ofNor("RDRAND Rv");
                case 0x7: return OpcodeDesc::ofNor("RDSEED Rv");
                default: break;
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x10) {
            return OpcodeDesc::ofNor("UD2(Alt)");
        };

        OPCODE_EXTENSIONS_HANDLER(0x11) {
            uint8_t rm = modrm & 0x7;
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            switch (ro) {
            case 0x0:
                if (opcode == 0xC6) return OpcodeDesc::ofNor("MOV Eb, Ib");
                if (opcode == 0xC7) return OpcodeDesc::ofNor("MOV Ev, Iz");
                break;
            case 0x7:
                if (opcode == 0xC6 && mod == 0x3 && rm == 0x0) return OpcodeDesc::ofNor("XABORT Ib");
                if (opcode == 0xC7 && mod == 0x3 && rm == 0x0) return OpcodeDesc::ofNor("XBEGIN Jz");
                break;
            default: break;
            }
            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x12) {
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod == 0x3) {
                if (pfx.mand == 0x0) {
                    switch (ro) {
                    case 0x2: return OpcodeDesc::ofNor("psrlw Nq, Ib");
                    case 0x4: return OpcodeDesc::ofNor("psraw Nq, Ib");
                    case 0x6: return OpcodeDesc::ofNor("psllw Nq, Ib");
                    default: break;
                    }
                } else if (pfx.mand == 0x66) {
                    switch (ro) {
                    case 0x2: return OpcodeDesc::ofNor("vpsrlw Hx, Ux, Ib");
                    case 0x4: return OpcodeDesc::ofNor("vpsraw Hx, Ux, Ib");
                    case 0x6: return OpcodeDesc::ofNor("vpsllw Hx, Ux, Ib");
                    default: break;
                    }
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x13) {
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod == 0x3) {
                if (pfx.mand == 0x0) {
                    switch (ro) {
                    case 0x2: return OpcodeDesc::ofNor("psrld Nq, Ib");
                    case 0x4: return OpcodeDesc::ofNor("psrad Nq, Ib");
                    case 0x6: return OpcodeDesc::ofNor("pslld Nq, Ib");
                    default: break;
                    }
                } else if (pfx.mand == 0x66) {
                    switch (ro) {
                    case 0x2: return OpcodeDesc::ofNor("vpsrld Hx, Ux, Ib");
                    case 0x4: return OpcodeDesc::ofNor("vpsrad Hx, Ux, Ib");
                    case 0x6: return OpcodeDesc::ofNor("vpslld Hx, Ux, Ib");
                    default: break;
                    }
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x14) {
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod == 0x3) {
                if (pfx.mand == 0x0) {
                    switch (ro) {
                    case 0x2: return OpcodeDesc::ofNor("psrlq Nq, Ib");
                    case 0x6: return OpcodeDesc::ofNor("psllq Nq, Ib");
                    default: break;
                    }
                } else if (pfx.mand == 0x66) {
                    switch (ro) {
                    case 0x2: return OpcodeDesc::ofNor("vpsrlq Hx, Ux, Ib");
                    case 0x3: return OpcodeDesc::ofNor("vpsrldq Hx, Ux, Ib");
                    case 0x6: return OpcodeDesc::ofNor("vpsllq Hx, Ux, Ib");
                    case 0x7: return OpcodeDesc::ofNor("vpslldq Hx, Ux, Ib");
                    default: break;
                    }
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x15) {
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod != 0x3) {
                switch (ro) {
                case 0x0: return OpcodeDesc::ofNor("fxsave");
                case 0x1: return OpcodeDesc::ofNor("fxrstor");
                case 0x2: return OpcodeDesc::ofNor("ldmxcsr");
                case 0x3: return OpcodeDesc::ofNor("stmxcsr");
                case 0x4: return OpcodeDesc::ofNor("XSAVE");
                case 0x5: return OpcodeDesc::ofNor("XRSTOR");
                case 0x6: return OpcodeDesc::ofNor("XSAVEOPT");
                case 0x7: return OpcodeDesc::ofNor("clflush");
                default: break;
                }
            } else {
                if (pfx.mand == 0x0) {
                    switch (ro) {
                    case 0x5: return OpcodeDesc::ofNor("lfence");
                    case 0x6: return OpcodeDesc::ofNor("mfence");
                    case 0x7: return OpcodeDesc::ofNor("sfence");
                    default: break;
                    }
                } else if (pfx.mand == 0xF3) {
                    switch (ro) {
                    case 0x0: return OpcodeDesc::ofNor("RDFSBASE Ry");
                    case 0x1: return OpcodeDesc::ofNor("RDGSBASE Ry");
                    case 0x2: return OpcodeDesc::ofNor("WRFSBASE Ry");
                    case 0x3: return OpcodeDesc::ofNor("WRGSBASE Ry");
                    default: break;
                    }
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x16) {
            uint8_t ro = (modrm >> 3) & 0x7;
            uint8_t mod = modrm >> 6;
            if (mod != 0x3) {
                switch (ro) {
                case 0x0: return OpcodeDesc::ofNor("prefetch NTA");
                case 0x1: return OpcodeDesc::ofNor("prefetch T0");
                case 0x2: return OpcodeDesc::ofNor("prefetch T1");
                case 0x3: return OpcodeDesc::ofNor("prefetch T2");
                default: break;
                }
            }

            RET_UND;
        };

        OPCODE_EXTENSIONS_HANDLER(0x17) {
            uint8_t ro = (modrm >> 3) & 0x7;
            switch (ro) {
            case 0x1: return OpcodeDesc::ofNor("BLSR[v] By, Ey");
            case 0x2: return OpcodeDesc::ofNor("BLSMSK[v] By, Ey");
            case 0x3: return OpcodeDesc::ofNor("BLSI[v] By, Ey");
            default: break;
            }

            RET_UND;
        };
    }

    void initModRMMap() {
        /**
         * Mem
         */
        // MOD = 00
        MODRM_MEM_MAP_HANDLER(0x0, 0x0) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "SI", 0, 0, "DS", false };
            return { "EAX", "", 0, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x1) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "DI", 0, 0, "DS", false };
            return { "ECX", "", 0, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x2) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "SI", 0, 0, "SS", false };
            return { "EDX", "", 0, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x3) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "DI", 0, 0, "SS", false };
            return { "EBX", "", 0, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x4) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "SI", "",   0, 0, "DS", false };
            return { "",    "", 0, 0, "",   true };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x5) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "DI", "",   0, 0, "DS", false };
            return { "",    "", 4, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x6) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "",   "",   2, 0, "DS", false };
            return { "ESI", "", 0, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x7) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "",   0, 0, "DS", false };
            return { "EDI", "", 0, 0, "ES", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x8) {
            return { "R8", "", 0, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0x9) {
            return { "R9", "", 0, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0xA) {
            return { "R10", "", 0, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0xB) {
            return { "R11", "", 0, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0xC) {
            return { "",    "", 0, 0, "", true };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0xD) {
            return { "",    "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0xE) {
            return { "R14", "", 0, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x0, 0xF) {
            return { "R15", "", 0, 0, "", false };
        };

        // MOD=01
        MODRM_MEM_MAP_HANDLER(0x1, 0x0) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "SI", 1, 0, "DS", false };
            return { "EAX", "", 1, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x1) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "DI", 1, 0, "DS", false };
            return { "ECX", "", 1, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x2) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "SI", 1, 0, "SS", false };
            return { "EDX", "", 1, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x3) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "DI", 1, 0, "SS", false };
            return { "EBX", "", 1, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x4) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "SI", "",   1, 0, "DS", false };
            return { "",    "", 1, 0, "",   true };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x5) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "DI", "",   1, 0, "DS", false };
            return { "EBP", "", 1, 0, "SS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x6) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "",   1, 0, "SS", false };
            return { "ESI", "", 1, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x7) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "",   1, 0, "DS", false };
            return { "EDI", "", 1, 0, "ES", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x8) {
            return { "R8", "", 1, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0x9) {
            return { "R9", "", 1, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0xA) {
            return { "R10", "", 1, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0xB) {
            return { "R11", "", 1, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0xC) {
            return { "",    "", 1, 0, "", true };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0xD) {
            return { "R13", "", 1, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0xE) {
            return { "R14", "", 1, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x1, 0xF) {
            return { "R15", "", 1, 0, "", false };
        };

        // MOD=10
        MODRM_MEM_MAP_HANDLER(0x2, 0x0) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "SI", 2, 0, "DS", false };
            return { "EAX", "", 4, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x1) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "DI", 2, 0, "DS", false };
            return { "ECX", "", 4, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x2) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "SI", 2, 0, "SS", false };
            return { "EDX", "", 4, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x3) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "DI", 2, 0, "SS", false };
            return { "EBX", "", 4, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x4) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "SI", "",   2, 0, "DS", false };
            return { "",    "", 4, 0, "",   true };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x5) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "DI", "",   2, 0, "DS", false };
            return { "EBP", "", 4, 0, "SS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x6) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BP", "",   2, 0, "SS", false };
            return { "ESI", "", 4, 0, "DS", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x7) {
            if (env.cpu_mode == CPUMode::_16Bit) return { "BX", "",   2, 0, "DS", false };
            return { "EDI", "", 4, 0, "ES", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x8) {
            return { "R8", "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0x9) {
            return { "R9", "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0xA) {
            return { "R10", "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0xB) {
            return { "R11", "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0xC) {
            return { "",    "", 4, 0, "", true };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0xD) {
            return { "R13", "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0xE) {
            return { "R14", "", 4, 0, "", false };
        };
        MODRM_MEM_MAP_HANDLER(0x2, 0xF) {
            return { "R15", "", 4, 0, "", false };
        };

        /**
         * Reg
         */
        MODRM_REG_MAP_HANDLER(0x0) {
            return { "AL", "AX", "EAX", "MM0", "XMM0" };
        };
        MODRM_REG_MAP_HANDLER(0x1) {
            return { "CL", "CX", "ECX", "MM1", "XMM1" };
        };
        MODRM_REG_MAP_HANDLER(0x2) {
            return { "DL", "DX", "EDX", "MM2", "XMM2" };
        };
        MODRM_REG_MAP_HANDLER(0x3) {
            return { "BL", "BX", "EBX", "MM3", "XMM3" };
        };
        MODRM_REG_MAP_HANDLER(0x4) {
            return { "AH", "SP", "ESP", "MM4", "XMM4" };
        };
        MODRM_REG_MAP_HANDLER(0x5) {
            return { "CH", "BP", "EBP", "MM5", "XMM5" };
        };
        MODRM_REG_MAP_HANDLER(0x6) {
            return { "DH", "SI", "ESI", "MM6", "XMM6" };
        };
        MODRM_REG_MAP_HANDLER(0x7) {
            return { "BH", "DI", "EDI", "MM7", "XMM7" };
        };
        MODRM_REG_MAP_HANDLER(0x8) {
            return { "R8L", "R8D", "R8", "MM0", "XMM8" };
        };
        MODRM_REG_MAP_HANDLER(0x9) {
            return { "R9L", "R9D", "R9", "MM1", "XMM9" };
        };
        MODRM_REG_MAP_HANDLER(0xA) {
            return { "R10L", "R10D", "R10", "MM2", "XMM10" };
        };
        MODRM_REG_MAP_HANDLER(0xB) {
            return { "R11L", "R11D", "R11", "MM3", "XMM11" };
        };
        MODRM_REG_MAP_HANDLER(0xC) {
            return { "R12L", "R12D", "R12", "MM4", "XMM12" };
        };
        MODRM_REG_MAP_HANDLER(0xD) {
            return { "R13L", "R13D", "R13", "MM5", "XMM13" };
        };
        MODRM_REG_MAP_HANDLER(0xE) {
            return { "R14L", "R14D", "R14", "MM6", "XMM14" };
        };
        MODRM_REG_MAP_HANDLER(0xF) {
            return { "R15L", "R15D", "R15", "MM7", "XMM15" };
        };
    }

    void initSIBMap() {
        /**
         * Scale
         */
        // SS=00
        SIB_SCALE_MAP_HANDLER(0x0, 0x0) {
            return { "EAX", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x1) {
            return { "ECX", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x2) {
            return { "EDX", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x3) {
            return { "EBX", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x4) {
            return { "",    0 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x5) {
            return { "EBP", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x6) {
            return { "ESI", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x7) {
            return { "EDI", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x8) {
            return { "R8", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0x9) {
            return { "R9", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0xA) {
            return { "R10", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0xB) {
            return { "R11", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0xC) {
            return { "R12", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0xD) {
            return { "R13", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0xE) {
            return { "R14", 1 };
        };
        SIB_SCALE_MAP_HANDLER(0x0, 0xF) {
            return { "R15", 1 };
        };

        // SS=01
        SIB_SCALE_MAP_HANDLER(0x1, 0x0) {
            return { "EAX", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x1) {
            return { "ECX", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x2) {
            return { "EDX", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x3) {
            return { "EBX", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x4) {
            return { "",    0 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x5) {
            return { "EBP", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x6) {
            return { "ESI", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x7) {
            return { "EDI", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x8) {
            return { "R8", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0x9) {
            return { "R9", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0xA) {
            return { "R10", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0xB) {
            return { "R11", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0xC) {
            return { "R12", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0xD) {
            return { "R13", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0xE) {
            return { "R14", 2 };
        };
        SIB_SCALE_MAP_HANDLER(0x1, 0xF) {
            return { "R15", 2 };
        };

        // SS=10
        SIB_SCALE_MAP_HANDLER(0x2, 0x0) {
            return { "EAX", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x1) {
            return { "ECX", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x2) {
            return { "EDX", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x3) {
            return { "EBX", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x4) {
            return { "",    0 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x5) {
            return { "EBP", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x6) {
            return { "ESI", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x7) {
            return { "EDI", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x8) {
            return { "R8", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0x9) {
            return { "R9", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0xA) {
            return { "R10", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0xB) {
            return { "R11", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0xC) {
            return { "R12", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0xD) {
            return { "R13", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0xE) {
            return { "R14", 4 };
        };
        SIB_SCALE_MAP_HANDLER(0x2, 0xF) {
            return { "R15", 4 };
        };

        // SS=11
        SIB_SCALE_MAP_HANDLER(0x3, 0x0) {
            return { "EAX", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x1) {
            return { "ECX", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x2) {
            return { "EDX", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x3) {
            return { "EBX", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x4) {
            return { "",    0 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x5) {
            return { "EBP", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x6) {
            return { "ESI", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x7) {
            return { "EDI", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x8) {
            return { "R8", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0x9) {
            return { "R9", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0xA) {
            return { "R10", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0xB) {
            return { "R11", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0xC) {
            return { "R12", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0xD) {
            return { "R13", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0xE) {
            return { "R14", 8 };
        };
        SIB_SCALE_MAP_HANDLER(0x3, 0xF) {
            return { "R15", 8 };
        };

        /**
         * Base
         */
        SIB_BASE_MAP_HANDLER(0x0) {
            return { "EAX", 0, 0, "DS" };
        };
        SIB_BASE_MAP_HANDLER(0x1) {
            return { "ECX", 0, 0, "DS" };
        };
        SIB_BASE_MAP_HANDLER(0x2) {
            return { "EDX", 0, 0, "DS" };
        };
        SIB_BASE_MAP_HANDLER(0x3) {
            return { "EBX", 0, 0, "DS" };
        };
        SIB_BASE_MAP_HANDLER(0x4) {
            return { "ESP", 0, 0, "SS" };
        };
        SIB_BASE_MAP_HANDLER(0x5) {
            uint8_t mod = modrm >> 6;
            if (mod == 0x0) return { "",    4, 0, "DS" };
            if (mod == 0x1) return { "EBP", 0, 0, "SS" };
            if (mod == 0x2) return { "EBP", 0, 0, "SS" };
            return { "",    0, 0 };
        };
        SIB_BASE_MAP_HANDLER(0x6) {
            return { "ESI", 0, 0, "SS" };
        };
        SIB_BASE_MAP_HANDLER(0x7) {
            return { "EDI", 0, 0, "ES" };
        };
        SIB_BASE_MAP_HANDLER(0x8) {
            return { "R8", 0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0x9) {
            return { "R9", 0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0xA) {
            return { "R10", 0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0xB) {
            return { "R11", 0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0xC) {
            return { "R12", 0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0xD) {
            return { "",    0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0xE) {
            return { "R14", 0, 0, "" };
        };
        SIB_BASE_MAP_HANDLER(0xF) {
            return { "R15", 0, 0, "" };
        };
    }

}
}