// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_PE_PE_DATA_TYPES_H_
#define DEXAR_PE_PE_DATA_TYPES_H_

#include <cstdint>


namespace dexar {
namespace pe {

    const size_t kPEStubLength = 0x3C;
    const uint32_t kPESignature = 0x00004550;    // PE\0\0
    const uint32_t kPEDataDirectoryLimitSize = 0x10;

    const char kExportSectionName[] = ".edata\0\0";
    const char kImportSectionName[] = ".idata\0\0";
    const char kResourceSectionName[] = ".rsrc\0\0\0";


    enum class MachineType : uint16_t {
        UNKNOWN = 0x0,
        AM33 = 0x1d3,
        AMD64 = 0x8664,
        ARM = 0x1c0,
        ARM64 = 0xaa64,
        ARMNT = 0x1c4,
        EBC = 0xebc,
        I386 = 0x14c,
        IA64 = 0x200,
        M32R = 0x9041,
        MIPS16 = 0x266,
        MIPSFPU = 0x366,
        MIPSFPU16 = 0x466,
        POWERPC = 0x1f0,
        POWERPCFP = 0x1f1,
        R4000 = 0x166,
        RISCV32 = 0x5032,
        RISCV64 = 0x5064,
        RISCV128 = 0x5128,
        SH3 = 0x1a2,
        SH3DSP = 0x1a3,
        SH4 = 0x1a6,
        SH5 = 0x1a8,
        THUMB = 0x1c2,
        WCEMIPSV2 = 0x169,
    };

    enum class COFFCharacteristics : uint16_t {
        /**
           Image only, Windows CE, and Microsoft Windows NT and later.
           This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address.
           If the base address is not available, the loader reports an error.
           The default behavior of the linker is to strip base relocations from executable(EXE) files.
        */
        RELOCS_STRIPPED = 0x0001,
        /**
           Image only.
           This indicates that the image file is valid and can be run.
           If this flag is not set, it indicates a linker error.
        */
        EXECUTABLE_IMAGE = 0x0002,
        // COFF line numbers have been removed.
        // This flag is deprecated and should be zero.
        LINE_NUMS_STRIPPED = 0x0004,
        // COFF symbol table entries for local symbols have been removed.
        // This flag is deprecated and should be zero.
        LOCAL_SYMS_STRIPPED = 0x0008,
        // Obsolete.
        // Aggressively trim working set.
        // This flag is deprecated for Windows 2000 and later and must be zero.
        AGGRESSIVE_WS_TRIM = 0x0010,
        // Application can handle > 2 - GB addresses.
        LARGE_ADDRESS_AWARE = 0x0020,
        // This flag is reserved for future use.
        RESERVED = 0x0040,
        // Little endian : the least significant bit(LSB) precedes the most significant bit(MSB) in memory.
        // This flag is deprecated and should be zero.
        BYTES_REVERSED_LO = 0x0080,
        // Machine is based on a 32 - bit - word architecture.
        _32BIT_MACHINE = 0x0100,
        // Debugging information is removed from the image file.
        DEBUG_STRIPPED = 0x0200,
        // If the image is on removable media, fully load it and copy it to the swap file.
        REMOVABLE_RUN_FROM_SWAP = 0x0400,
        // If the image is on network media, fully load it and copy it to the swap file.
        NET_RUN_FROM_SWAP = 0x0800,
        // The image file is a system file, not a user program.
        SYSTEM = 0x1000,
        // The image file is a dynamic - link library(DLL).
        // Such files are considered executable files for almost all purposes, although they cannot be directly run.
        DLL = 0x2000,
        // The file should be run only on a uniprocessor machine.
        UP_SYSTEM_ONLY = 0x4000,
        // Big endian : the MSB precedes the LSB in memory.
        // This flag is deprecated and should be zero.
        BYTES_REVERSED_HI = 0x8000,
    };

    enum class OptionalHeaderMagic : uint16_t {
        PE32 = 0x10B,
        PE32Plus = 0x20B,
    };

    enum class WindowsSubsystem : uint16_t {
        // An unknown subsystem
        UNKNOWN = 0,
        // Device drivers and native Windows processes
        NATIVE = 1,
        // The Windows graphical user interface(GUI) subsystem
        WINDOWS_GUI = 2,
        // The Windows character subsystem
        WINDOWS_CUI = 3,
        // The OS / 2 character subsystem
        OS2_CUI = 5,
        // The Posix character subsystem
        POSIX_CUI = 7,
        // Native Win9x driver
        NATIVE_WINDOWS = 8,
        // Windows CE
        WINDOWS_CE_GUI = 9,
        // An Extensible Firmware Interface(EFI) application
        EFI_APPLICATION = 10,
        // An EFI driver with boot services
        EFI_BOOT_SERVICE_DRIVER = 11,
        // An EFI driver with run - time services
        EFI_RUNTIME_DRIVER = 12,
        // An EFI ROM image
        EFI_ROM = 13,
        // XBOX
        XBOX = 14,
        // Windows boot application.
        WINDOWS_BOOT_APPLICATION = 16,
    };

    enum class DLLCharacteristics : uint16_t {
        // Reserved, must be zero.
        RESERVED1 = 0x0001,
        // Reserved, must be zero.
        RESERVED2 = 0x0002,
        // Reserved, must be zero.
        RESERVED3 = 0x0004,
        // Reserved, must be zero.
        RESERVED4 = 0x0008,
        // Image can handle a high entropy 64 - bit virtual address space.
        HIGH_ENTROPY_VA = 0x0020,
        // DLL can be relocated at load time.
        DYNAMIC_BASE = 0x0040,
        // Code Integrity checks are enforced.
        FORCE_INTEGRITY = 0x0080,
        // Image is NX compatible.
        NX_COMPAT = 0x0100,
        // Isolation aware, but do not isolate the image.
        NO_ISOLATION = 0x0200,
        // Does not use structured exception(SE) handling.
        // No SE handler may be called in this image.
        NO_SEH = 0x0400,
        // Do not bind the image.
        NO_BIND = 0x0800,
        // Image must execute in an AppContainer.
        APPCONTAINER = 0x1000,
        // A WDM driver.
        WDM_DRIVER = 0x2000,
        // Image supports Control Flow Guard.
        GUARD_CF = 0x4000,
        // Terminal Server aware.
        TERMINAL_SERVER_AWARE = 0x8000,
    };

    enum class SectionFlags : uint32_t {
        // Reserved for future use.
        RESERVED1 = 0x00000000,
        // Reserved for future use.
        RESERVED2 = 0x00000001,
        // Reserved for future use.
        RESERVED3 = 0x00000002,
        // Reserved for future use.
        RESERVED4 = 0x00000004,
        // The section should not be padded to the next boundary.
        // This flag is obsolete and is replaced by ALIGN_1BYTES.
        // This is valid only for object files.
        TYPE_NO_PAD = 0x00000008,
        // Reserved for future use.
        RESERVED5 = 0x00000010,
        // The section contains executable code.
        CNT_CODE = 0x00000020,
        // The section contains initialized data.
        CNT_INITIALIZED_DATA = 0x00000040,
        // The section contains uninitialized data.
        CNT_UNINITIALIZED_DATA = 0x00000080,
        // Reserved for future use.
        LNK_OTHER = 0x00000100,
        // The section contains comments or other information.
        // The drectve section has this type.
        // This is valid for object files only.
        LNK_INFO = 0x00000200,
        // Reserved for future use.
        RESERVED6 = 0x00000400,
        // The section will not become part of the image.
        // This is valid only for object files.
        LNK_REMOVE = 0x00000800,
        // The section contains COMDAT data.
        // For more information, see COMDAT Sections(Object Only).
        // This is valid only for object files.
        LNK_COMDAT = 0x00001000,
        // The section contains data referenced through the global pointer(GP).
        GPREL = 0x00008000,
        // Reserved for future use.
        MEM_PURGEABLE = 0x00020000,
        // Reserved for future use.
        MEM_16BIT = 0x00020000,
        // Reserved for future use.
        MEM_LOCKED = 0x00040000,
        // Reserved for future use.
        MEM_PRELOAD = 0x00080000,
        // Align data on a 1 - byte boundary.
        // Valid only for object files.
        ALIGN_1BYTES = 0x00100000,
        // Align data on a 2 - byte boundary.
        // Valid only for object files.
        ALIGN_2BYTES = 0x00200000,
        // Align data on a 4 - byte boundary.
        // Valid only for object files.
        ALIGN_4BYTES = 0x00300000,
        // Align data on an 8 - byte boundary.
        // Valid only for object files.
        ALIGN_8BYTES = 0x00400000,
        // Align data on a 16 - byte boundary.
        // Valid only for object files.
        ALIGN_16BYTES = 0x00500000,
        // Align data on a 32 - byte boundary.
        // Valid only for object files.
        ALIGN_32BYTES = 0x00600000,
        // Align data on a 64 - byte boundary.
        // Valid only for object files.
        ALIGN_64BYTES = 0x00700000,
        // Align data on a 128 - byte boundary.
        // Valid only for object files.
        ALIGN_128BYTES = 0x00800000,
        // Align data on a 256 - byte boundary.
        // Valid only for object files.
        ALIGN_256BYTES = 0x00900000,
        // Align data on a 512 - byte boundary.
        // Valid only for object files.
        ALIGN_512BYTES = 0x00A00000,
        // Align data on a 1024 - byte boundary.
        // Valid only for object files.
        ALIGN_1024BYTES = 0x00B00000,
        // Align data on a 2048 - byte boundary.
        // Valid only for object files.
        ALIGN_2048BYTES = 0x00C00000,
        // Align data on a 4096 - byte boundary.
        // Valid only for object files.
        ALIGN_4096BYTES = 0x00D00000,
        // Align data on an 8192 - byte boundary.
        // Valid only for object files.
        ALIGN_8192BYTES = 0x00E00000,
        // The section contains extended relocations.
        LNK_NRELOC_OVFL = 0x01000000,
        // The section can be discarded as needed.
        MEM_DISCARDABLE = 0x02000000,
        // The section cannot be cached.
        MEM_NOT_CACHED = 0x04000000,
        // The section is not pageable.
        MEM_NOT_PAGED = 0x08000000,
        // The section can be shared in memory.
        MEM_SHARED = 0x10000000,
        // The section can be executed as code.
        MEM_EXECUTE = 0x20000000,
        // The section can be read.
        MEM_READ = 0x40000000,
        // The section can be written to.
        MEM_WRITE = 0x80000000,
    };


    // File headers
    struct CoffFileHeader {
        MachineType machine;
        uint16_t section_num;
        uint32_t time_stamp;
        uint32_t symbol_table_ptr;
        uint32_t symbol_num;
        uint16_t optional_header_size;
        COFFCharacteristics chrs;
    };

    struct OptionalHeaderStd {
        OptionalHeaderMagic magic;
        uint8_t major_linker_ver;
        uint8_t minor_linker_ver;
        uint32_t code_size;
        uint32_t inited_data_size;
        uint32_t uninited_data_size;
        uint32_t ep_addr;
        uint32_t code_base;
        uint32_t data_base;
    };

    struct OptionalHeaderWin {
        uint64_t img_base;
        uint32_t section_align;
        uint32_t file_align;
        uint16_t major_os_ver;
        uint16_t minor_os_ver;
        uint16_t major_img_ver;
        uint16_t minor_img_ver;
        uint16_t major_sub_ver;
        uint16_t minor_sub_ver;
        uint32_t win32_ver_val;
        uint32_t img_size;
        uint32_t headers_size;
        uint32_t check_sum;
        WindowsSubsystem sub_system;
        DLLCharacteristics dll_chrs;
        uint64_t stack_reserve_size;
        uint64_t stack_commit_size;
        uint64_t heap_reserve_size;
        uint64_t heap_commit_size;
        uint32_t loader_flags;
        uint32_t dd_num;
    };


    // Table
    struct ImageDataDirectory {
        uint32_t rva;
        uint32_t size;
    };


    // Section
    struct SectionHeader {
        char name[8];
        uint32_t virtual_size;
        uint32_t virtual_addr;
        uint32_t raw_data_size;
        uint32_t raw_data_ptr;
        uint32_t relocs_ptr;
        uint32_t linenums_ptr;
        uint16_t reloc_num;
        uint16_t linenum_num;
        SectionFlags chrs;
    };

}
}

#endif  // DEXAR_PE_PE_DATA_TYPES_H_