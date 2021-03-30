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