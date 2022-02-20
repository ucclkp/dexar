// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_DEBUGGER_H_
#define DEXAR_DEBUGGER_H_

#include <condition_variable>
#include <thread>
#include <map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "utils/message/cycler.h"

#include "dexar/pe/pe_parser.h"


namespace dexar {

    class DebuggerBridge {
    public:
        struct DebugInfo {
            // Virtual Address
            intptr_t img_base_addr;
            intptr_t bp_addr;

            intptr_t sec_base_addr;
            uint32_t sec_size;

            DWORD tid;
            CONTEXT context;
            HANDLE process;
            HANDLE thread;
        };

        virtual ~DebuggerBridge() = default;

        virtual void onBreakpoint(const DebugInfo& info) = 0;
        virtual void onSingleStep(const DebugInfo& info) = 0;
    };

    class Debugger : public utl::CyclerListener {
    public:
        Debugger();
        ~Debugger();

        void create(const std::u16string_view& name);
        void attach(const std::u16string_view& name);
        void resume();
        void setDebuggerBridge(DebuggerBridge* bridge);

        bool isRunning() const;

    protected:
        void onHandleMessage(const utl::Message& msg) override;

    private:
        struct Breakpoint {
            intptr_t addr;
            uint8_t opcode;
        };

        enum {
            CYCLER_BREAKPOINT,
            CYCLER_SINGLE_STEP,
        };

        void run(const std::u16string& name);
        bool setRegisterInfo(DWORD tid, const CONTEXT* c);
        bool getRegisterInfo(DWORD tid, CONTEXT* c);
        bool setProcessMemory(intptr_t addr, uint8_t dat);
        bool getProcessMemory(intptr_t addr, uint8_t* dat);
        bool setBreakpoint(intptr_t addr);
        bool clearBreakpoint(intptr_t addr);
        bool hasBreakpoint(intptr_t addr);

        bool setTFFlag(DWORD tid);
        bool backwardEIP(DWORD tid);

        void onProcessCreated(const CREATE_PROCESS_DEBUG_INFO& info);
        void onThreadCreated(const CREATE_THREAD_DEBUG_INFO& info, DWORD pid, DWORD tid);
        void onException(const EXCEPTION_DEBUG_INFO& info, DWORD pid, DWORD tid);
        void onThreadExited(const EXIT_THREAD_DEBUG_INFO& info, DWORD pid, DWORD tid);
        void onProcessExited(const EXIT_PROCESS_DEBUG_INFO& info);
        void onDLLLoaded(const LOAD_DLL_DEBUG_INFO& info);
        void onDLLUnloaded(const UNLOAD_DLL_DEBUG_INFO& info);
        void onOutputDebugString(const OUTPUT_DEBUG_STRING_INFO& info);
        void onRIPEvent(const RIP_INFO& info);

        void onBreakpoint(DWORD tid, intptr_t addr);
        void onSingleStep(DWORD tid, intptr_t addr);

        std::wstring ANSIToW(const std::string& str);

        bool is_running_ = false;
        uint32_t ep_sec_vir_addr_ = 0;
        uint32_t ep_sec_vir_size_ = 0;

        HANDLE debugged_proc_;
        DWORD continue_status_;
        bool is_first_breakpoint_;
        std::u16string image_file_name_;
        intptr_t image_base_addr_;

        pe::PEParser pe_parser_;
        utl::Cycler cycler_;
        std::thread debugger_thread_;
        std::vector<Breakpoint> breakpoints_;
        std::map<DWORD, HANDLE> thread_map_;
        std::mutex mutex_;
        std::condition_variable cv_;
        bool cv_pred_;
        DebuggerBridge* bridge_;
    };

}

#endif  // DEXAR_DEBUGGER_H_