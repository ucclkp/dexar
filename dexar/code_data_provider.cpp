// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/code_data_provider.h"

#include "utils/log.h"


namespace dexar {

    // StaticCodeDataProvider
    StaticCodeDataProvider::StaticCodeDataProvider(const uint8_t* buf)
        : buf_(buf) {}

    uint8_t StaticCodeDataProvider::get8(uint32_t off) const {
        return buf_[off];
    }

    uint16_t StaticCodeDataProvider::get16(uint32_t off) const {
        return *reinterpret_cast<const uint16_t*>(buf_ + off);
    }

    uint32_t StaticCodeDataProvider::get32(uint32_t off) const {
        return *reinterpret_cast<const uint32_t*>(buf_ + off);
    }

    uint64_t StaticCodeDataProvider::get64(uint64_t off) const {
        return *reinterpret_cast<const uint64_t*>(buf_ + off);
    }


    // DynamicCodeDataProvider
    DynamicCodeDataProvider::DynamicCodeDataProvider(intptr_t base, HANDLE process)
        : base_(base),
          process_(process) {
    }

    uint8_t DynamicCodeDataProvider::get8(uint32_t off) const {
        uint8_t dat = 0;
        SIZE_T read_byte_count = 0;
        BOOL ret = ::ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(base_ + off), &dat, 1, &read_byte_count);
        if (ret == 0 || read_byte_count != 1) {
            DCHECK(false);
            return 0;
        }
        return dat;
    }

    uint16_t DynamicCodeDataProvider::get16(uint32_t off) const {
        uint16_t dat = 0;
        SIZE_T read_byte_count = 0;
        BOOL ret = ::ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(base_ + off), &dat, 2, &read_byte_count);
        if (ret == 0 || read_byte_count != 2) {
            DCHECK(false);
            return 0;
        }
        return dat;
    }

    uint32_t DynamicCodeDataProvider::get32(uint32_t off) const {
        uint32_t dat = 0;
        SIZE_T read_byte_count = 0;
        BOOL ret = ::ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(base_ + off), &dat, 4, &read_byte_count);
        if (ret == 0 || read_byte_count != 4) {
            DCHECK(false);
            return 0;
        }
        return dat;
    }

    uint64_t DynamicCodeDataProvider::get64(uint64_t off) const {
        uint64_t dat = 0;
        SIZE_T read_byte_count = 0;
        BOOL ret = ::ReadProcessMemory(
            process_, reinterpret_cast<LPCVOID>(base_ + off), &dat, 8, &read_byte_count);
        if (ret == 0 || read_byte_count != 8) {
            DCHECK(false);
            return 0;
        }
        return dat;
    }

}
