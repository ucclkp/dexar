// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar/debugger.h"

#include <memory>
#include <fstream>
#include <filesystem>

#include "utils/log.h"
#include "utils/convert.h"
#include "utils/message/cycler.h"
#include "utils/message/message_pump.h"
#include "utils/message/message.h"
#include "utils/number.hpp"


namespace dexar {

    Debugger::Debugger()
        : debugged_proc_(nullptr),
          continue_status_(DBG_CONTINUE),
          is_first_breakpoint_(true),
          image_base_addr_(0),
          cycler_(utl::MessagePump::getMain()),
          cv_pred_(false),
          bridge_(nullptr)
    {
        cycler_.setListener(this);
    }

    Debugger::~Debugger() {
        if (debugger_thread_.joinable()) {
            ::TerminateProcess(debugged_proc_, 0);
            resume();
            debugger_thread_.join();
        }
    }

    void Debugger::create(const std::u16string& name) {
        is_running_ = true;
        debugger_thread_ = std::thread(&Debugger::run, this, name);
    }

    void Debugger::attach(const std::u16string& name) {
    }

    void Debugger::resume() {
        {
            std::lock_guard<std::mutex> lg(mutex_);
            cv_pred_ = true;
        }
        cv_.notify_one();
    }

    void Debugger::setDebuggerBridge(DebuggerBridge* bridge) {
        bridge_ = bridge;
    }

    bool Debugger::isRunning() const {
        return is_running_;
    }

    void Debugger::onHandleMessage(const utl::Message& msg) {
        switch (msg.id) {
        case CYCLER_BREAKPOINT:
        {
            auto info = static_cast<DebuggerBridge::DebugInfo*>(msg.data);
            if (bridge_) {
                bridge_->onBreakpoint(*info);
            } else {
                resume();
            }
            break;
        }

        case CYCLER_SINGLE_STEP:
        {
            auto info = static_cast<DebuggerBridge::DebugInfo*>(msg.data);
            if (bridge_) {
                bridge_->onSingleStep(*info);
            } else {
                resume();
            }
            break;
        }

        default:
            break;
        }
    }

    void Debugger::run(const std::u16string& name) {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ::memset(&si, 0, sizeof(STARTUPINFOW));
        ::memset(&pi, 0, sizeof(PROCESS_INFORMATION));

        BOOL ret = ::CreateProcessW(
            reinterpret_cast<const wchar_t*>(name.c_str()), nullptr, nullptr, nullptr,
            FALSE, DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi);
        if (ret == 0) {
            LOG(Log::ERR) << "Failed to create process: " << ::GetLastError();
            return;
        }

        image_file_name_ = name;
        debugged_proc_ = pi.hProcess;

        thread_map_[pi.dwThreadId] = pi.hThread;

        bool exit = false;
        DEBUG_EVENT debug_event;
        while (!exit && ::WaitForDebugEvent(&debug_event, INFINITE)) {
            continue_status_ = DBG_CONTINUE;
            switch (debug_event.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                onProcessCreated(debug_event.u.CreateProcessInfo);
                break;

            case CREATE_THREAD_DEBUG_EVENT:
                onThreadCreated(debug_event.u.CreateThread, debug_event.dwProcessId, debug_event.dwThreadId);
                break;

            case EXCEPTION_DEBUG_EVENT:
                onException(debug_event.u.Exception, debug_event.dwProcessId, debug_event.dwThreadId);
                break;

            case EXIT_THREAD_DEBUG_EVENT:
                onThreadExited(debug_event.u.ExitThread, debug_event.dwProcessId, debug_event.dwThreadId);
                break;

            case EXIT_PROCESS_DEBUG_EVENT:
                onProcessExited(debug_event.u.ExitProcess);
                exit = true;
                break;

            case LOAD_DLL_DEBUG_EVENT:
                onDLLLoaded(debug_event.u.LoadDll);
                break;

            case UNLOAD_DLL_DEBUG_EVENT:
                onDLLUnloaded(debug_event.u.UnloadDll);
                break;

            case OUTPUT_DEBUG_STRING_EVENT:
                onOutputDebugString(debug_event.u.DebugString);
                break;

            case RIP_EVENT:
                onRIPEvent(debug_event.u.RipInfo);
                break;

            default:
                DCHECK(false);
                break;
            }

            ::ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status_);
        }

        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);

        debugged_proc_ = nullptr;
    }

    bool Debugger::setRegisterInfo(DWORD tid, const CONTEXT* c) {
        auto it = thread_map_.find(tid);
        if (it == thread_map_.end()) {
            LOG(Log::ERR) << "Cannot find thread handle!";
            return false;
        }

        if (::SetThreadContext(it->second, c) == 0) {
            LOG(Log::WARNING) << "Cannot set register info!";
            return false;
        }
        return true;
    }

    bool Debugger::getRegisterInfo(DWORD tid, CONTEXT* c) {
        auto it = thread_map_.find(tid);
        if (it == thread_map_.end()) {
            LOG(Log::ERR) << "Cannot find thread handle!";
            return false;
        }

        ::memset(c, 0, sizeof(CONTEXT));
        c->ContextFlags = CONTEXT_ALL;
        if (::GetThreadContext(it->second, c) == 0) {
            LOG(Log::WARNING) << "Cannot get register info!";
            return false;
        }
        return true;
    }

    bool Debugger::setProcessMemory(intptr_t addr, uint8_t dat) {
        SIZE_T write_byte_count = 0;
        BOOL ret = ::WriteProcessMemory(
            debugged_proc_, reinterpret_cast<LPVOID>(addr), &dat, 1, &write_byte_count);
        if (ret == 0 || write_byte_count != 1) {
            return false;
        }
        return true;
    }

    bool Debugger::getProcessMemory(intptr_t addr, uint8_t* dat) {
        SIZE_T read_byte_count = 0;
        BOOL ret = ::ReadProcessMemory(
            debugged_proc_, reinterpret_cast<LPCVOID>(addr), dat, 1, &read_byte_count);
        if (ret == 0 || read_byte_count != 1) {
            return false;
        }
        return true;
    }

    bool Debugger::setBreakpoint(intptr_t addr) {
        for (const auto& bp : breakpoints_) {
            if (bp.addr == addr) {
                return false;
            }
        }

        uint8_t opcode;
        if (!getProcessMemory(addr, &opcode)) {
            return false;
        }

        if (!setProcessMemory(addr, 0xCC)) {
            return false;
        }

        Breakpoint bp;
        bp.addr = addr;
        bp.opcode = opcode;
        breakpoints_.push_back(bp);
        return true;
    }

    bool Debugger::clearBreakpoint(intptr_t addr) {
        auto it = breakpoints_.begin();
        for (; it != breakpoints_.end(); ++it) {
            if (it->addr == addr) {
                break;
            }
        }

        if (it == breakpoints_.end()) {
            return false;
        }

        if (!setProcessMemory(addr, it->opcode)) {
            return false;
        }

        breakpoints_.erase(it);
        return true;
    }

    bool Debugger::hasBreakpoint(intptr_t addr) {
        for (const auto& bp : breakpoints_) {
            if (bp.addr == addr) {
                return true;
            }
        }
        return false;
    }

    bool Debugger::setTFFlag(DWORD tid) {
        CONTEXT c;
        if (!getRegisterInfo(tid, &c)) {
            return false;
        }
        c.EFlags |= 0x100;
        if (!setRegisterInfo(tid, &c)) {
            return false;
        }
        return true;
    }

    bool Debugger::backwardEIP(DWORD tid) {
        CONTEXT c;
        if (!getRegisterInfo(tid, &c)) {
            return false;
        }
#ifdef _WIN64
        c.Rip -= 1;
#else
        c.Eip -= 1;
#endif
        if (!setRegisterInfo(tid, &c)) {
            return false;
        }
        return true;
    }

    void Debugger::onProcessCreated(const CREATE_PROCESS_DEBUG_INFO& info) {
        LOG(Log::INFO) << "Debugger::onProcessCreated";
        ::CloseHandle(info.hFile);

        std::ifstream file(std::filesystem::path(image_file_name_), std::ios::binary);
        if (!file) {
            LOG(Log::ERR) << "Cannot open file: " << utl::UTF16ToUTF8(image_file_name_);
            return;
        }

        if (!pe_parser_.parse(file)) {
            LOG(Log::ERR) << "Cannot parse file: " << utl::UTF16ToUTF8(image_file_name_);
            return;
        }

        auto& coff = pe_parser_.getCOFFHeader();
        auto& opt = pe_parser_.getOptHeaderStd();
        if (opt.magic == pe::OptionalHeaderMagic::PE32) {
            if (coff.machine != pe::MachineType::I386) {
                LOG(Log::ERR) << "Cannot parse file: " << utl::UTF16ToUTF8(image_file_name_);
                return;
            }
        } else {
            if (coff.machine != pe::MachineType::AMD64) {
                LOG(Log::ERR) << "Cannot parse file: " << utl::UTF16ToUTF8(image_file_name_);
                return;
            }
        }

        /*if (!(coff.chrs & pe::COFFCharacteristics::EXECUTABLE_IMAGE) ||
            !(coff.chrs & pe::COFFCharacteristics::_32BIT_MACHINE)) {
        }*/

        bool hit = false;
        auto& sections = pe_parser_.getSectionHeaders();
        for (const auto& s : sections) {
            if (opt.ep_addr >= s.virtual_addr &&
                opt.ep_addr < s.virtual_addr + s.virtual_size)
            {
                ep_sec_vir_addr_ = s.virtual_addr;
                ep_sec_vir_size_ = s.virtual_size;
                hit = true;
                break;
            }
        }

        if (!hit) {
            LOG(Log::ERR) << "Cannot find EP section: " << utl::UTF16ToUTF8(image_file_name_);
            return;
        }

        image_base_addr_ = reinterpret_cast<intptr_t>(info.lpBaseOfImage);
        setBreakpoint(opt.ep_addr + image_base_addr_);
    }

    void Debugger::onThreadCreated(const CREATE_THREAD_DEBUG_INFO& info, DWORD pid, DWORD tid) {
        auto it = thread_map_.find(tid);
        if (it == thread_map_.end()) {
            thread_map_[tid] = info.hThread;
        }
        //LOG(Log::INFO) << "Debugger::onThreadCreated";
    }

    void Debugger::onException(const EXCEPTION_DEBUG_INFO& info, DWORD pid, DWORD tid) {
        auto addr = reinterpret_cast<intptr_t>(info.ExceptionRecord.ExceptionAddress);

        switch (info.ExceptionRecord.ExceptionCode) {
        case EXCEPTION_BREAKPOINT:
            if (is_first_breakpoint_) {
                is_first_breakpoint_ = false;
                break;
            }
            if (info.dwFirstChance == 0) {
                break;
            }
            if (!hasBreakpoint(addr)) {
                break;
            }
            if (!clearBreakpoint(addr)) {
                LOG(Log::ERR) << "Cannot clear breakpoint!";
            }
            if (!backwardEIP(tid)) {
                LOG(Log::ERR) << "Cannot backward EIP!";
            }
            if (!setTFFlag(tid)) {
                LOG(Log::WARNING) << "Cannot set TF!";
            }
            onBreakpoint(tid, addr);
            break;

        case EXCEPTION_SINGLE_STEP:
            if (!setTFFlag(tid)) {
                LOG(Log::WARNING) << "Cannot set TF!";
            }
            onSingleStep(tid, addr);
            break;

        default:
            continue_status_ = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }

        LOG(Log::INFO) << "An exception was occured. "
            << "Exception code: " << std::hex << std::uppercase << info.ExceptionRecord.ExceptionCode;
        if (info.dwFirstChance != 0) {
            LOG(Log::INFO) << "First chance.";
        } else {
            LOG(Log::INFO) << "Second chance.";
        }
    }

    void Debugger::onThreadExited(const EXIT_THREAD_DEBUG_INFO& info, DWORD pid, DWORD tid) {
        auto it = thread_map_.find(tid);
        if (it != thread_map_.end()) {
            thread_map_.erase(it);
        }
        //LOG(Log::INFO) << "Debugger::onThreadExited " << info.dwExitCode;
    }

    void Debugger::onProcessExited(const EXIT_PROCESS_DEBUG_INFO& info) {
        LOG(Log::INFO) << "Debugger::onProcessExited " << info.dwExitCode;
        debugged_proc_ = nullptr;
    }

    void Debugger::onDLLLoaded(const LOAD_DLL_DEBUG_INFO& info) {
        ::CloseHandle(info.hFile);
        //LOG(Log::INFO) << "Debugger::onDLLLoaded";
    }

    void Debugger::onDLLUnloaded(const UNLOAD_DLL_DEBUG_INFO& info) {
        //LOG(Log::INFO) << "Debugger::onDLLUnloaded";
    }

    void Debugger::onOutputDebugString(const OUTPUT_DEBUG_STRING_INFO& info) {
        auto debug_str_length = info.nDebugStringLength;
        std::unique_ptr<BYTE[]> buffer(new BYTE[debug_str_length]);
        SIZE_T read_count = 0;
        BOOL ret = ::ReadProcessMemory(
            debugged_proc_, info.lpDebugStringData, buffer.get(), debug_str_length, &read_count);
        if (ret == 0) {
            LOG(Log::ERR) << "Cannot read debug string: " << ::GetLastError();
        }

        if (read_count == 0) {
            return;
        }
        --read_count;

        auto str = ANSIToUTF16(
            std::string(reinterpret_cast<char*>(buffer.get()), read_count));
        LOG(Log::INFO) << "Debugger::onOutputDebugString " << utl::UTF16ToUTF8(str);
    }

    void Debugger::onRIPEvent(const RIP_INFO& info) {
        LOG(Log::INFO) << "Debugger::onRIPEvent " << info.dwType << " " << info.dwError;
    }

    void Debugger::onBreakpoint(DWORD tid, intptr_t addr) {
        DebuggerBridge::DebugInfo dbg_info;
        dbg_info.img_base_addr = image_base_addr_;
        dbg_info.bp_addr = addr;
        dbg_info.sec_base_addr = ep_sec_vir_addr_ + image_base_addr_;
        dbg_info.sec_size = ep_sec_vir_size_;
        dbg_info.tid = tid;
        dbg_info.process = debugged_proc_;
        dbg_info.thread = thread_map_[tid];
        getRegisterInfo(tid, &dbg_info.context);

        utl::Message msg;
        msg.id = CYCLER_BREAKPOINT;
        msg.data = &dbg_info;
        cycler_.post(&msg);

        {
            std::unique_lock<std::mutex> lk(mutex_);
            cv_.wait(lk, [this] { return cv_pred_; });
            cv_pred_ = false;
        }
    }

    void Debugger::onSingleStep(DWORD tid, intptr_t addr) {
        DebuggerBridge::DebugInfo dbg_info;
        dbg_info.img_base_addr = image_base_addr_;
        dbg_info.bp_addr = addr;
        dbg_info.sec_base_addr = ep_sec_vir_addr_ + image_base_addr_;
        dbg_info.sec_size = ep_sec_vir_size_;
        dbg_info.tid = tid;
        dbg_info.process = debugged_proc_;
        dbg_info.thread = thread_map_[tid];
        getRegisterInfo(tid, &dbg_info.context);

        utl::Message msg;
        msg.id = CYCLER_SINGLE_STEP;
        msg.data = &dbg_info;
        cycler_.post(&msg);

        {
            std::unique_lock<std::mutex> lk(mutex_);
            cv_.wait(lk, [this] { return cv_pred_; });
            cv_pred_ = false;
        }
    }


    std::u16string Debugger::ANSIToUTF16(const std::string& str) {
        int req_length = ::MultiByteToWideChar(
            CP_ACP, MB_PRECOMPOSED, str.data(), utl::num_cast<int>(str.length()), nullptr, 0);
        if (req_length <= 0) {
            return {};
        }

        std::unique_ptr<WCHAR[]> w_buffer(new WCHAR[req_length]);

        req_length = ::MultiByteToWideChar(
            CP_ACP, MB_PRECOMPOSED,
            str.data(), utl::num_cast<int>(str.length()), w_buffer.get(), req_length);
        if (req_length <= 0) {
            return {};
        }

        return std::u16string(reinterpret_cast<char16_t*>(w_buffer.get()), req_length);
    }


}
