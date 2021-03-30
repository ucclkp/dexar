// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_TEST_UI_DEXAR_WINDOW_H_
#define DEXAR_TEST_UI_DEXAR_WINDOW_H_

#include "ukive/window/window.h"
#include "ukive/views/click_listener.h"

#include "dexar/debugger.h"


namespace ukive {
    class Button;
    class ListView;
    class TextView;
}

namespace dexar {

    class OpcodeListSource;

    class DisassemblerWindow :
        public ukive::Window,
        public ukive::OnClickListener,
        public DebuggerBridge {
    public:
        DisassemblerWindow();

        // ukive::Window
        void onCreated() override;

        // ukive::OnClickListener
        void onClick(ukive::View* v) override;

        // dpr::DebuggerBridge
        void onBreakpoint(const DebugInfo& info) override;
        void onSingleStep(const DebugInfo& info) override;

    private:
        void processStaticInstructions(const uint8_t* buf, uint32_t ep, uint32_t size);
        void processDynamicInstructions(const DebugInfo& dbg_info);

        std::u16string file_path_;
        ukive::Button* browser_button_ = nullptr;
        ukive::Button* parse_button_ = nullptr;
        ukive::TextView* path_tv_ = nullptr;

        Debugger debugger_;
        ukive::Button* continue_btn_ = nullptr;
        ukive::ListView* op_list_view_ = nullptr;
        OpcodeListSource* op_list_source_ = nullptr;
    };

}

#endif  // DEXAR_TEST_UI_DEXAR_WINDOW_H_