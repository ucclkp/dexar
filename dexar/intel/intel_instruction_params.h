// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_INTEL_INTEL_INSTRUCTION_PARAMS_H_
#define DEXAR_INTEL_INTEL_INSTRUCTION_PARAMS_H_

#include <string>

#include "dexar/intel/intel_prefix.h"


namespace dexar {
namespace intel {

    enum class CPUMode {
        _16Bit,
        _32Bit,
        _64Bit,
    };

    enum Regs {
        /**
         * Segment
         */
        REG_CS = 0,
        REG_DS,
        REG_SS,
        REG_ES,
        REG_FS,
        REG_GS,

        /**
         * 8-bit
         */
        REG_AL,
        REG_CL,
        REG_DL,
        REG_BL,
        // in-64bm: only-no-REX
        REG_AH,
        REG_CH,
        REG_DH,
        REG_BH,
        // only-64bm REX
        REG_SPL,
        REG_BPL,
        REG_SIL,
        REG_DIL,
        REG_R8L,
        REG_R9L,
        REG_R10L,
        REG_R11L,
        REG_R12L,
        REG_R13L,
        REG_R14L,
        REG_R15L,

        /**
         * 16-bit
         */
        REG_AX,
        REG_CX,
        REG_DX,
        REG_BX,
        REG_SP,
        REG_BP,
        REG_SI,
        REG_DI,
        // only-64bm REX
        REG_R8W,
        REG_R9W,
        REG_R10W,
        REG_R11W,
        REG_R12W,
        REG_R13W,
        REG_R14W,
        REG_R15W,

        /**
         * 32-bit
         */
        REG_EAX,
        REG_ECX,
        REG_EDX,
        REG_EBX,
        REG_ESP,
        REG_EBP,
        REG_ESI,
        REG_EDI,
        // only-64bm REX
        REG_R8D,
        REG_R9D,
        REG_R10D,
        REG_R11D,
        REG_R12D,
        REG_R13D,
        REG_R14D,
        REG_R15D,

        /**
         * 64-bit
         * only-64bm REX
         */
        REG_RAX,
        REG_RCX,
        REG_RDX,
        REG_RBX,
        REG_RSP,
        REG_RBP,
        REG_RSI,
        REG_RDI,
        REG_R8,
        REG_R9,
        REG_R10,
        REG_R11,
        REG_R12,
        REG_R13,
        REG_R14,
        REG_R15,

        REG_LAST_ITEM,
    };

    enum Operands {
        OPR_S_b,
        OPR_S_v,
        OPR_S_w,
        OPR_S_z,

        OPR_P_e = 1,
        OPR_P_r,
        OPR_P_A,
        OPR_P_B,
        OPR_P_C,
        OPR_P_D,
        OPR_P_E,
        OPR_P_F,
        OPR_P_G,
        OPR_P_H,
        OPR_P_I,
        OPR_P_J,
        OPR_P_K,
        OPR_P_L,
        OPR_P_M,
        OPR_P_N,
        OPR_P_O,
        OPR_P_P,
        OPR_P_Q,
        OPR_P_R,
        OPR_P_S,
        OPR_P_T,
        OPR_P_U,
        OPR_P_V,
        OPR_P_W,
        OPR_P_X,
        OPR_P_Y,
        OPR_P_Z,

        OPR_eAX = (OPR_P_e << 8) | REG_AX,
        OPR_eCX = (OPR_P_e << 8) | REG_CX,
        OPR_eDX = (OPR_P_e << 8) | REG_DX,
        OPR_eBX = (OPR_P_e << 8) | REG_BX,
        OPR_eSP = (OPR_P_e << 8) | REG_SP,
        OPR_eBP = (OPR_P_e << 8) | REG_BP,
        OPR_eSI = (OPR_P_e << 8) | REG_SI,
        OPR_eDI = (OPR_P_e << 8) | REG_DI,

        OPR_rAX = (OPR_P_e << 8) | REG_AX,
        OPR_rCX = (OPR_P_e << 8) | REG_CX,
        OPR_rDX = (OPR_P_e << 8) | REG_DX,
        OPR_rBX = (OPR_P_e << 8) | REG_BX,
        OPR_rSP = (OPR_P_e << 8) | REG_SP,
        OPR_rBP = (OPR_P_e << 8) | REG_BP,
        OPR_rSI = (OPR_P_e << 8) | REG_SI,
        OPR_rDI = (OPR_P_e << 8) | REG_DI,
        OPR_r8  = (OPR_P_e << 8) | REG_R8,
        OPR_r9  = (OPR_P_e << 8) | REG_R9,
        OPR_r10 = (OPR_P_e << 8) | REG_R10,
        OPR_r11 = (OPR_P_e << 8) | REG_R11,
        OPR_r12 = (OPR_P_e << 8) | REG_R12,
        OPR_r13 = (OPR_P_e << 8) | REG_R13,
        OPR_r14 = (OPR_P_e << 8) | REG_R14,
        OPR_r15 = (OPR_P_e << 8) | REG_R15,

        OPR_Eb = (OPR_P_E << 8) | OPR_S_b,
        OPR_Ev,
        OPR_Gb,
        OPR_Gv,
        OPR_Ib,
        OPR_Iv,
        OPR_Iw,
        OPR_Iz,
        OPR_Ob,
        OPR_Ov,
        OPR_Xb,
        OPR_Xv,
        OPR_Yb,
        OPR_Yv,
    };

    enum SScripts {
        SS_i64 = 0,
        SS_o64,
        SS_d64,
        SS_f64,
        SS_v,
        SS_v1,
        SS_1B,
    };

    enum Decorators {
        DR_N = 0,
        DR_F,
        DR_S,
        DR_S1,
        DR_Alt,
        DR_reserved,
    };

    enum Mnemonics {
        MNE_AAA,
        MNE_AAD,
        MNE_AAM,
        MNE_AAS,
        MNE_ADC,
        MNE_ADCX,
        MNE_ADD,
        MNE_ADOX,
        MNE_AND,
        MNE_ARPL,
        MNE_BEXTR,
        MNE_BLENDVPD,
        MNE_BLENDVPS,
        MNE_BLSI,
        MNE_BLSMSK,
        MNE_BLSR,
        MNE_BOUND,
        MNE_BSF,
        MNE_BSR,
        MNE_BSWAP,
        MNE_BT,
        MNE_BTC,
        MNE_BTR,
        MNE_BTS,
        MNE_BZHI,
        MNE_CALL,
        MNE_CBW,
        MNE_CDQ,
        MNE_CDQE,
        MNE_CLAC,
        MNE_CLC,
        MNE_CLD,
        MNE_CLFLUSH,
        MNE_CLI,
        MNE_CLTS,
        MNE_CMC,
        MNE_CMOVA,
        MNE_CMOVAE,
        MNE_CMOVB,
        MNE_CMOVBE,
        MNE_CMOVC,
        MNE_CMOVE,
        MNE_CMOVG,
        MNE_CMOVGE,
        MNE_CMOVLE,
        MNE_CMOVNA,
        MNE_CMOVNAE,
        MNE_CMOVNB,
        MNE_CMOVNBE,
        MNE_CMOVNC,
        MNE_CMOVNE,
        MNE_CMOVNG,
        MNE_CMOVNGE,
        MNE_CMOVNL,
        MNE_CMOVNLE,
        MNE_CMOVNO,
        MNE_CMOVNP,
        MNE_CMOVNS,
        MNE_CMOVNZ,
        MNE_CMOVL,
        MNE_CMOVO,
        MNE_CMOVP,
        MNE_CMOVPE,
        MNE_CMOVPO,
        MNE_CMOVS,
        MNE_CMOVZ,
        MNE_CMP,
        MNE_CMPS,
        MNE_CMPSB,
        MNE_CMPSD,
        MNE_CMPSW,
        MNE_CMPXCHG,
        MNE_CMPXCHG16B,
        MNE_CMPXCHG8B,
        MNE_CPUID,
        MNE_CRC32,
        MNE_CWD,
        MNE_CWDE,
        MNE_CQO,
        MNE_CVTPI2PD,
        MNE_CVTPI2PS,
        MNE_CVTPD2PI,
        MNE_CVTPS2PI,
        MNE_CVTTPD2PI,
        MNE_CVTTPS2PI,
        MNE_DAA,
        MNE_DAS,
        MNE_DEC,
        MNE_DIV,
        MNE_EMMS,
        MNE_ENTER,
        MNE_FWAIT,
        MNE_FXRSTOR,
        MNE_FXSAVE,
        MNE_GETSEC,
        MNE_HLT,
        MNE_IDIV,
        MNE_IMUL,
        MNE_IN,
        MNE_INC,
        MNE_INS,
        MNE_INSB,
        MNE_INSD,
        MNE_INSW,
        MNE_INT,
        MNE_INTO,
        MNE_INVEPT,
        MNE_INVD,
        MNE_INVLPG,
        MNE_INVPCID,
        MNE_INVVPID,
        MNE_IRET,
        MNE_IRETD,
        MNE_IRETQ,
        MNE_JB,   // JNAE, JC
        MNE_JBE,  // JNA
        MNE_JE,   // JZ
        MNE_JL,   // JNGE
        MNE_JLE,  // JNG
        MNE_JMP,
        MNE_JMPE,
        MNE_JNB,  // JAE, JNC
        MNE_JNBE, // JA
        MNE_JNL,  // JGE
        MNE_JNLE, // JG
        MNE_JNO,
        MNE_JNP,  // JPO
        MNE_JNS,
        MNE_JNZ,  // JNE
        MNE_JO,
        MNE_JP,   // JPE
        MNE_JRCXZ,
        MNE_JS,
        MNE_LAHF,
        MNE_LAR,
        MNE_LDMXCSR,
        MNE_LDS,
        MNE_LEA,
        MNE_LEAVE,
        MNE_LES,
        MNE_LFENCE,
        MNE_LFS,
        MNE_LGDT,
        MNE_LGS,
        MNE_LIDT,
        MNE_LLDT,
        MNE_LMSW,
        MNE_LODS,
        MNE_LODSB,
        MNE_LODSD,
        MNE_LODSQ,
        MNE_LODSW,
        MNE_LOOP,
        MNE_LOOPE,  // LOOPZ
        MNE_LOOPNE, // LOOPNZ
        MNE_LSL,
        MNE_LSS,
        MNE_LTR,
        MNE_LZCNT,
        MNE_MASKMOVQ,
        MNE_MFENCE,
        MNE_MONITOR,
        MNE_MOV,
        MNE_MOVBE,
        MNE_MOVD,
        MNE_MOVNTI,
        MNE_MOVNTQ,
        MNE_MOVQ,
        MNE_MOVDQ2Q,
        MNE_MOVQ2DQ,
        MNE_MOVS,
        MNE_MOVSB,
        MNE_MOVSD,
        MNE_MOVSQ,
        MNE_MOVSW,
        MNE_MOVSX,
        MNE_MOVSXD,
        MNE_MOVZX,
        MNE_MUL,
        MNE_MULX,
        MNE_MWAIT,
        MNE_NEG,
        MNE_NOP,
        MNE_NOT,
        MNE_OR,
        MNE_OUT,
        MNE_OUTS,
        MNE_OUTSB,
        MNE_OUTSD,
        MNE_OUTSW,
        MNE_PABSB,
        MNE_PABSD,
        MNE_PABSW,
        MNE_PACKSSDW,
        MNE_PACKSSWB,
        MNE_PACKUSWB,
        MNE_PADDB,
        MNE_PADDD,
        MNE_PADDQ,
        MNE_PADDSB,
        MNE_PADDSW,
        MNE_PADDUSB,
        MNE_PADDUSW,
        MNE_PADDW,
        MNE_PALIGNR,
        MNE_PAND,
        MNE_PANDN,
        MNE_PAUSE,
        MNE_PAVGB,
        MNE_PAVGW,
        MNE_PBLENDVB,
        MNE_PCMPEQB,
        MNE_PCMPEQD,
        MNE_PCMPEQW,
        MNE_PCMPGTB,
        MNE_PCMPGTD,
        MNE_PCMPGTW,
        MNE_PDEP,
        MNE_PEXT,
        MNE_PEXTRW,
        MNE_PHADDD,
        MNE_PHADDSW,
        MNE_PHADDW,
        MNE_PHSUBD,
        MNE_PHSUBSW,
        MNE_PHSUBW,
        MNE_PINSRW,
        MNE_PMADDUBSW,
        MNE_PMADDWD,
        MNE_PMAXSW,
        MNE_PMAXUB,
        MNE_PMINSW,
        MNE_PMINUB,
        MNE_PMOVMSKB,
        MNE_PMULHRSW,
        MNE_PMULHUW,
        MNE_PMULHW,
        MNE_PMULLW,
        MNE_PMULUDQ,
        MNE_PSADBW,
        MNE_PSHUFB,
        MNE_PSIGNB,
        MNE_PSIGND,
        MNE_PSIGNW,
        MNE_PSUBB,
        MNE_PSUBQ,
        MNE_PSUBD,
        MNE_PSUBW,
        MNE_POP,
        MNE_POPA,
        MNE_POPAD,
        MNE_POPCNT,
        MNE_POR,
        MNE_PREFETCH,
        MNE_PREFETCHW,
        MNE_PSHUFW,
        MNE_PSLLD,
        MNE_PSLLQ,
        MNE_PSLLW,
        MNE_PSRAD,
        MNE_PSRAW,
        MNE_PSRLD,
        MNE_PSRLQ,
        MNE_PSRLW,
        MNE_PSUBSB,
        MNE_PSUBSW,
        MNE_PSUBUSB,
        MNE_PSUBUSW,
        MNE_PUNPCKHBW,
        MNE_PUNPCKHDQ,
        MNE_PUNPCKHWD,
        MNE_PUNPCKLBW,
        MNE_PUNPCKLDQ,
        MNE_PUNPCKLWD,
        MNE_PUSH,
        MNE_PUSHA,
        MNE_PUSHAD,
        MNE_PXOR,
        MNE_RCL,
        MNE_RCR,
        MNE_RDFSBASE,
        MNE_RDGSBASE,
        MNE_RDMSR,
        MNE_RDPMC,
        MNE_RDRAND,
        MNE_RDSEED,
        MNE_RDTSC,
        MNE_RDTSCP,
        MNE_RET,
        MNE_ROL,
        MNE_ROR,
        MNE_RORX,
        MNE_RSM,
        MNE_SAHF,
        MNE_SAL,
        MNE_SAR,
        MNE_SARX,
        MNE_SBB,
        MNE_SCAS,
        MNE_SCASB,
        MNE_SCASD,
        MNE_SCASQ,
        MNE_SCASW,
        MNE_SETB,   // SETNAE, SETC
        MNE_SETBE,  // SETNA
        MNE_SETE,   // SETZ
        MNE_SETL,   // SETNGE
        MNE_SETLE,  // SETNG
        MNE_SETNB,  // SETAE, SETNC
        MNE_SETNBE, // SETA
        MNE_SETNL,  // SETGE
        MNE_SETNLE, // SETG
        MNE_SETNO,
        MNE_SETNP,  // SETPO
        MNE_SETNS,
        MNE_SETNZ,  // SETNE
        MNE_SETO,
        MNE_SETP,   // SETPE
        MNE_SETS,
        MNE_SFENCE,
        MNE_SGDT,
        MNE_SIDT,
        MNE_SHL,
        MNE_SHLD,
        MNE_SHLX,
        MNE_SHR,
        MNE_SHRD,
        MNE_SHRX,
        MNE_SLDT,
        MNE_SMSW,
        MNE_STAC,
        MNE_STC,
        MNE_STD,
        MNE_STI,
        MNE_STMXCSR,
        MNE_STOS,
        MNE_STOSB,
        MNE_STOSD,
        MNE_STOSQ,
        MNE_STOSW,
        MNE_STR,
        MNE_SUB,
        MNE_SWAPGS,
        MNE_SYSCALL,
        MNE_SYSENTER,
        MNE_SYSEXIT,
        MNE_SYSRET,
        MNE_TEST,
        MNE_TZCNT,
        MNE_UD2,

        MNE_VADDPD,
        MNE_VADDPS,
        MNE_VADDSD,
        MNE_VADDSS,
        MNE_VADDSUBPD,
        MNE_VADDSUBPS,
        MNE_VAESDEC,
        MNE_VAESDECLAST,
        MNE_VAESENC,
        MNE_VAESENCLAST,
        MNE_VAESIMC,
        MNE_VAESKEYGEN,
        MNE_VANDNPD,
        MNE_VANDNPS,
        MNE_VANDPD,
        MNE_VANDPS,
        MNE_VBLENDPD,
        MNE_VBLENDPS,
        MNE_VBLENDVPD,
        MNE_VBLENDVPS,
        MNE_VBROADCASTF128,
        MNE_VBROADCASTI128,
        MNE_VBROADCASTSD,
        MNE_VBROADCASTSS,
        MNE_VCMPPD,
        MNE_VCMPPS,
        MNE_VCMPSD,
        MNE_VCMPSS,
        MNE_VCOMISD,
        MNE_VCOMISS,
        MNE_VCVTDQ2PD,
        MNE_VCVTDQ2PS,
        MNE_VCVTPD2DQ,
        MNE_VCVTPD2PS,
        MNE_VCVTPH2PS,
        MNE_VCVTPS2DQ,
        MNE_VCVTPS2PD,
        MNE_VCVTPS2PH,
        MNE_VCVTSD2SI,
        MNE_VCVTSD2SS,
        MNE_VCVTSI2SD,
        MNE_VCVTSI2SS,
        MNE_VCVTSS2SD,
        MNE_VCVTSS2SI,
        MNE_VCVTTPD2DQ,
        MNE_VCVTTPS2DQ,
        MNE_VCVTTSD2SI,
        MNE_VCVTTSS2SI,
        MNE_VDIVPD,
        MNE_VDIVPS,
        MNE_VDIVSD,
        MNE_VDIVSS,
        MNE_VDPPD,
        MNE_VDPPS,
        MNE_VERR,
        MNE_VERW,
        MNE_VEXTRACTPS,
        MNE_VEXTRACTF128,
        MNE_VEXTRACTI128,

        MNE_VFMADDSUB132PD,
        MNE_VFMADDSUB132PS,
        MNE_VFMADD132PD,
        MNE_VFMADD132PS,
        MNE_VFMADD132SD,
        MNE_VFMADD132SS,
        MNE_VFMSUBADD132PD,
        MNE_VFMSUBADD132PS,
        MNE_VFMSUB132PD,
        MNE_VFMSUB132PS,
        MNE_VFMSUB132SD,
        MNE_VFMSUB132SS,
        MNE_VFNMADD132PD,
        MNE_VFNMADD132PS,
        MNE_VFNMADD132SD,
        MNE_VFNMADD132SS,
        MNE_VFNMSUB132PD,
        MNE_VFNMSUB132PS,
        MNE_VFNMSUB132SD,
        MNE_VFNMSUB132SS,

        MNE_VFMADDSUB213PD,
        MNE_VFMADDSUB213PS,
        MNE_VFMADD213PD,
        MNE_VFMADD213PS,
        MNE_VFMADD213SD,
        MNE_VFMADD213SS,
        MNE_VFMSUBADD213PD,
        MNE_VFMSUBADD213PS,
        MNE_VFMSUB213PD,
        MNE_VFMSUB213PS,
        MNE_VFMSUB213SD,
        MNE_VFMSUB213SS,
        MNE_VFNMADD213PD,
        MNE_VFNMADD213PS,
        MNE_VFNMADD213SD,
        MNE_VFNMADD213SS,
        MNE_VFNMSUB213PD,
        MNE_VFNMSUB213PS,
        MNE_VFNMSUB213SD,
        MNE_VFNMSUB213SS,

        MNE_VFMADDSUB231PD,
        MNE_VFMADDSUB231PS,
        MNE_VFMADD231PD,
        MNE_VFMADD231PS,
        MNE_VFMADD231SD,
        MNE_VFMADD231SS,
        MNE_VFMSUBADD231PD,
        MNE_VFMSUBADD231PS,
        MNE_VFMSUB231PD,
        MNE_VFMSUB231PS,
        MNE_VFMSUB231SD,
        MNE_VFMSUB231SS,
        MNE_VFNMADD231PD,
        MNE_VFNMADD231PS,
        MNE_VFNMADD231SD,
        MNE_VFNMADD231SS,
        MNE_VFNMSUB231PD,
        MNE_VFNMSUB231PS,
        MNE_VFNMSUB231SD,
        MNE_VFNMSUB231SS,

        MNE_VGATHERDD,
        MNE_VGATHERDQ,
        MNE_VGATHERQD,
        MNE_VGATHERQQ,
        MNE_VGATHERDPD,
        MNE_VGATHERDPS,
        MNE_VGATHERQPD,
        MNE_VGATHERQPS,
        MNE_VHADDPD,
        MNE_VHADDPS,
        MNE_VHSUBPD,
        MNE_VHSUBPS,
        MNE_VINSERTF128,
        MNE_VINSERTI128,
        MNE_VINSERTPS,
        MNE_VLDDQU,
        MNE_VMASKMOVDQU,
        MNE_VMASKMOVPD,
        MNE_VMASKMOVPS,
        MNE_VMAXPD,
        MNE_VMAXPS,
        MNE_VMAXSD,
        MNE_VMAXSS,
        MNE_VMCALL,
        MNE_VMCLEAR,
        MNE_VMFUNC,
        MNE_VMINPD,
        MNE_VMINPS,
        MNE_VMINSD,
        MNE_VMINSS,
        MNE_VMLAUNCH,
        MNE_VMOVAPD,
        MNE_VMOVAPS,
        MNE_VMOVD,
        MNE_VMOVDDUP,
        MNE_VMOVDQA,
        MNE_VMOVDQU,
        MNE_VMOVHLPS,
        MNE_VMOVHPD,
        MNE_VMOVHPS,
        MNE_VMOVLHPS,
        MNE_VMOVLPD,
        MNE_VMOVLPS,
        MNE_VMOVMSKPD,
        MNE_VMOVMSKPS,
        MNE_VMOVNTDQ,
        MNE_VMOVNTDQA,
        MNE_VMOVNTPD,
        MNE_VMOVNTPS,
        MNE_VMOVQ,
        MNE_VMOVQDA,
        MNE_VMOVQDU,
        MNE_VMOVSD,
        MNE_VMOVSHDUP,
        MNE_VMOVSLDUP,
        MNE_VMOVSS,
        MNE_VMOVUPD,
        MNE_VMOVUPS,
        MNE_VMOVVQ,
        MNE_VMPSADBW,
        MNE_VMPTRLD,
        MNE_VMPTRST,
        MNE_VMREAD,
        MNE_VMRESUME,
        MNE_VMULPD,
        MNE_VMULPS,
        MNE_VMULSD,
        MNE_VMULSS,
        MNE_VMWRITE,
        MNE_VMXOFF,
        MNE_VMXON,
        MNE_VORPD,
        MNE_VORPS,
        MNE_VPABSB,
        MNE_VPABSD,
        MNE_VPABSW,
        MNE_VPACKSSDW,
        MNE_VPACKSSWB,
        MNE_VPACKUSDW,
        MNE_VPACKUSWB,
        MNE_VPADDB,
        MNE_VPADDD,
        MNE_VPADDQ,
        MNE_VPADDSB,
        MNE_VPADDSW,
        MNE_VPADDUSB,
        MNE_VPADDUSW,
        MNE_VPADDW,
        MNE_VPALIGNR,
        MNE_VPAND,
        MNE_VPANDN,
        MNE_VPAVGB,
        MNE_VPAVGW,
        MNE_VPBLENDD,
        MNE_VPBLENDVB,
        MNE_VPBLENDW,
        MNE_VPBROADCASTB,
        MNE_VPBROADCASTD,
        MNE_VPBROADCASTQ,
        MNE_VPBROADCASTW,
        MNE_VPCLMULQDQ,
        MNE_VPCMPEQB,
        MNE_VPCMPEQD,
        MNE_VPCMPEQQ,
        MNE_VPCMPEQW,
        MNE_VPCMPESTRI,
        MNE_VPCMPESTRM,
        MNE_VPCMPGTB,
        MNE_VPCMPGTD,
        MNE_VPCMPGTQ,
        MNE_VPCMPGTW,
        MNE_VPCMPISTRI,
        MNE_VPCMPISTRM,
        MNE_VPERMD,
        MNE_VPERMQ,
        MNE_VPERMILPD,
        MNE_VPERMILPS,
        MNE_VPERMPD,
        MNE_VPERMPS,
        MNE_VPERM2F128,
        MNE_VPERM2I128,
        MNE_VPEXTRB,
        MNE_VPEXTRD,
        MNE_VPEXTRQ,
        MNE_VPEXTRW,
        MNE_VPHADDD,
        MNE_VPHADDSW,
        MNE_VPHADDW,
        MNE_VPHMINPOSUW,
        MNE_VPHSUBD,
        MNE_VPHSUBSW,
        MNE_VPHSUBW,
        MNE_VPINSRB,
        MNE_VPINSRD,
        MNE_VPINSRQ,
        MNE_VPINSRW,
        MNE_VPMADDUBSW,
        MNE_VPMADDWD,
        MNE_VPMASKMOVD,
        MNE_VPMASKMOVQ,
        MNE_VPMAXSB,
        MNE_VPMAXSD,
        MNE_VPMAXSW,
        MNE_VPMAXUB,
        MNE_VPMAXUD,
        MNE_VPMAXUW,
        MNE_VPMINSB,
        MNE_VPMINSD,
        MNE_VPMINSW,
        MNE_VPMINUB,
        MNE_VPMINUD,
        MNE_VPMINUW,
        MNE_VPMOVSXBD,
        MNE_VPMOVSXBQ,
        MNE_VPMOVSXBW,
        MNE_VPMOVSXDQ,
        MNE_VPMOVSXWD,
        MNE_VPMOVSXWQ,
        MNE_VPMOVZXBD,
        MNE_VPMOVZXBQ,
        MNE_VPMOVZXBW,
        MNE_VPMOVZXDQ,
        MNE_VPMOVZXWD,
        MNE_VPMOVZXWQ,
        MNE_VPMULDQ,
        MNE_VPMULHUW,
        MNE_VPMULHRSW,
        MNE_VPMULHW,
        MNE_VPMULLD,
        MNE_VPMULLW,
        MNE_VPMULUDQ,
        MNE_VPMOVMSKB,
        MNE_VPSADBW,
        MNE_VPSIGNB,
        MNE_VPSIGND,
        MNE_VPSIGNW,
        MNE_VPOR,
        MNE_VPSHUFB,
        MNE_VPSHUFD,
        MNE_VPSHUFHW,
        MNE_VPSHUFLW,
        MNE_VPSLLD,
        MNE_VPSLLDQ,
        MNE_VPSLLQ,
        MNE_VPSLLVD,
        MNE_VPSLLVQ,
        MNE_VPSLLW,
        MNE_VPSRAD,
        MNE_VPSRAVD,
        MNE_VPSRAW,
        MNE_VPSRLD,
        MNE_VPSRLDQ,
        MNE_VPSRLQ,
        MNE_VPSRLVD,
        MNE_VPSRLVQ,
        MNE_VPSRLW,
        MNE_VPSUBB,
        MNE_VPSUBD,
        MNE_VPSUBQ,
        MNE_VPSUBSB,
        MNE_VPSUBSW,
        MNE_VPSUBUSB,
        MNE_VPSUBUSW,
        MNE_VPSUBW,
        MNE_VPTEST,
        MNE_VPUNPCKHBW,
        MNE_VPUNPCKHDQ,
        MNE_VPUNPCKHQDQ,
        MNE_VPUNPCKHWD,
        MNE_VPUNPCKLBW,
        MNE_VPUNPCKLDQ,
        MNE_VPUNPCKLQDQ,
        MNE_VPUNPCKLWD,
        MNE_VPXOR,
        MNE_VRCPPS,
        MNE_VRCPSS,
        MNE_VROUNDPD,
        MNE_VROUNDPS,
        MNE_VROUNDSD,
        MNE_VROUNDSS,
        MNE_VRSQRTPS,
        MNE_VRSQRTSS,
        MNE_VSHUFPD,
        MNE_VSHUFPS,
        MNE_VSQRTPD,
        MNE_VSQRTPS,
        MNE_VSQRTSD,
        MNE_VSQRTSS,
        MNE_VSUBPD,
        MNE_VSUBPS,
        MNE_VSUBSD,
        MNE_VSUBSS,
        MNE_VTESTPD,
        MNE_VTESTPS,
        MNE_VUCOMISD,
        MNE_VUCOMISS,
        MNE_VUNPCKHPD,
        MNE_VUNPCKHPS,
        MNE_VUNPCKLPD,
        MNE_VUNPCKLPS,
        MNE_VXORPD,
        MNE_VXORPS,
        MNE_VZEROALL,
        MNE_VZEROUPPER,

        MNE_WAIT,
        MNE_WBINVD,
        MNE_WRFSBASE,
        MNE_WRGSBASE,
        MNE_WRMSR,
        MNE_XABORT,
        MNE_XADD,
        MNE_XBEGIN,
        MNE_XCHG,
        MNE_XEND,
        MNE_XGETBV,
        MNE_XLAT,
        MNE_XLATB,
        MNE_XOR,
        MNE_XRSTOR,
        MNE_XSAVE,
        MNE_XSAVEOPT,
        MNE_XSETBV,
        MNE_XTEST,
    };

    struct Env {
        CPUMode cpu_mode;
        bool d;
    };

    struct ModRMMemMode {
        std::string idx1_reg;
        std::string idx2_reg;
        uint32_t disp_length = 0;
        uint32_t disp = 0;
        std::string seg_reg;
        bool has_sib = false;
    };

    struct ModRMRegMode {
        std::string b_reg;
        std::string w_reg;
        std::string dw_reg;
        std::string mm_reg;
        std::string xmm_reg;
    };

    struct SIBBaseMode {
        std::string reg;
        uint32_t disp_length = 0;
        uint32_t disp = 0;
        std::string seg_reg;
    };

    struct SIBScaleMode {
        std::string reg;
        uint32_t scale = 0;
    };

    struct ModRMField {
        bool is_reg = false;
        ModRMMemMode mrm_mem;
        ModRMRegMode mrm_reg;
        std::string selected_reg;
    };

    struct SIBField {
        SIBBaseMode sib_base;
        SIBScaleMode sib_scale;
    };

    struct SelConfig {
        bool use_explicit = false;
        bool use_fwait = false;
        bool use_nop = true;
        bool use_sal = false;
        uint8_t e_z = 0;
        uint8_t b_nae_c = 0;
        uint8_t nb_ae_nc = 0;
        uint8_t nz_ne = 0;
        uint8_t be_na = 0;
        uint8_t nbe_a = 0;
        uint8_t p_pe = 0;
        uint8_t np_po = 0;
        uint8_t l_nge = 0;
        uint8_t nl_ge = 0;
        uint8_t le_ng = 0;
        uint8_t nle_g = 0;
        uint8_t shl_sal = 0;
        uint8_t repne_nz = 0;
        uint8_t rep_e_z = 0;
    };

    uint32_t selectOperandSize(bool d, const Prefix& p);
    uint32_t selectOperandSize64(const std::string& ss, const Prefix& p);
    uint32_t selectAddressSize(bool d, const Prefix& p);
    uint32_t selectAddressSize64(const Prefix& p);

}
}

#endif  // DEXAR_INTEL_INTEL_INSTRUCTION_PARAMS_H_