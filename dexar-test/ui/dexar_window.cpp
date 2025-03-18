// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar-test/ui/dexar_window.h"

#include <iomanip>
#include <fstream>

#include "utils/log.h"
#include "utils/strings/string_utils.hpp"

#include "ukive/views/list/list_view.h"
#include "ukive/views/layout/restraint_layout.h"
#include "ukive/views/list/linear_list_layouter.h"
#include "ukive/views/button.h"
#include "ukive/system/dialogs/sys_open_file_dialog.h"
#include "ukive/elements/texteditor_element.h"

#include "dexar/intel/intel_instruction.h"
#include "dexar/intel/intel_instruction_parser.h"
#include "dexar/intel/intel_opcode_map.h"
#include "dexar/code_data_provider.h"

#include "dexar-test/ui/opcode_list_source.h"
#include "dexar-test/resources/necro_resources_id.h"


namespace dexar {

    DisassemblerWindow::DisassemblerWindow()
    {
    }

    void DisassemblerWindow::onCreated() {
        Window::onCreated();

        showTitleBar();
        setContentView(Res::Layout::dexar_layout_xml);

        path_tv_ = findView<ukive::TextView>(Res::Id::tv_dexar_file_path);
        path_tv_->setBackground(new ukive::TextEditorElement(getContext()));

        browser_button_ = findView<ukive::Button>(Res::Id::bt_dexar_browser_button);
        browser_button_->setOnClickListener(this);

        parse_button_ = findView<ukive::Button>(Res::Id::bt_dexar_parse_button);
        parse_button_->setOnClickListener(this);

        continue_btn_ = findView<ukive::Button>(Res::Id::bt_dexar_continue_button);
        continue_btn_->setEnabled(false);
        continue_btn_->setOnClickListener(this);

        op_list_view_ = findView<ukive::ListView>(Res::Id::lv_dexar_info_list);
        op_list_view_->setLayouter(new ukive::LinearListLayouter());
        op_list_source_ = new OpcodeListSource();
        op_list_view_->setSource(op_list_source_);

        intel::initOneByteOpcodeMap();
        intel::initTwoByteOpcodeMap();
        intel::initThreeByteOpcodeMap();
        intel::initExtensionOpcodeMap();
        intel::initModRMMap();
        intel::initSIBMap();
    }

    void DisassemblerWindow::onClick(ukive::View* v) {
        if (v == continue_btn_) {
            continue_btn_->setEnabled(false);
            debugger_.resume();
        } else if (v == browser_button_) {
            std::unique_ptr<ukive::OpenFileDialog> dialog(ukive::OpenFileDialog::create());
            dialog->addType(u"*.exe;*.dll", u"PE文件");
            dialog->addType(u"*.*", u"所有文件");
            if (dialog->show(this, 0) == 1) {
                auto& files = dialog->getSelectedFiles();
                if (!files.empty()) {
                    file_path_ = files.front();
                    path_tv_->setText(file_path_);
                }
            }
        } else if (v == parse_button_) {
            std::ifstream file(std::filesystem::path(file_path_), std::ios::binary);
            if (!file) {
                jour_e("Cannot open file: %s", file_path_);
                return;
            }

            pe::PEParser parser;
            if (!parser.parse(file)) {
                jour_e("Cannot parse file: %s", file_path_);
                return;
            }

            if (!debugger_.isRunning()) {
                debugger_.setDebuggerBridge(this);
                debugger_.create(file_path_);
            }
        }
    }

    void DisassemblerWindow::onBreakpoint(const DebugInfo& info) {
        /*processStaticInstructions(
            reinterpret_cast<uint8_t*>(info.sec_base_addr),
            info.bp_addr - info.sec_base_addr,
            info.sec_size);*/
        processDynamicInstructions(info);
        continue_btn_->setEnabled(true);
        //debugger_.resume();
    }

    void DisassemblerWindow::onSingleStep(const DebugInfo& info) {
        /*processStaticInstructions(
            reinterpret_cast<uint8_t*>(info.sec_base_addr),
            info.bp_addr - info.sec_base_addr,
            info.sec_size);*/
        processDynamicInstructions(info);
        continue_btn_->setEnabled(true);
        //debugger_.resume();
    }

    void DisassemblerWindow::processStaticInstructions(const uint8_t* buf, uint32_t ep, uint32_t size) {
        intel::Instruction info;

        intel::CodeSegment csi;
        csi.provider = new StaticCodeDataProvider(buf);
        csi.cur = ep;
        csi.size = size;
        csi.env.cpu_mode = intel::CPUMode::_32Bit;
        csi.env.d = true;

        intel::InstructionParser parser;

        for (int i = 0; i < 50; ++i) {
            if (parser.parse(csi, &info)) {
                csi += info.length();
                info.reset();
            } else {
                break;
            }
        }

        delete csi.provider;
    }

    void DisassemblerWindow::processDynamicInstructions(const DebugInfo& dbg_info) {
        intel::Instruction info;

        op_list_source_->clear();

        intel::CodeSegment csi;
        csi.provider = new DynamicCodeDataProvider(dbg_info.sec_base_addr, dbg_info.process);
        csi.cur = dbg_info.bp_addr - dbg_info.sec_base_addr;
        csi.size = dbg_info.sec_size;
        csi.env.cpu_mode = intel::CPUMode::_32Bit;
        csi.env.d = true;

        intel::InstructionParser parser;

        uint32_t offset = 0;
        for (int i = 0; i < 50; ++i) {
            std::stringstream addr_ss;
            addr_ss << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                << (dbg_info.bp_addr + offset);
            auto addr_str = utl::u8to16(addr_ss.str());

            if (parser.parse(csi, &info)) {
                op_list_source_->addOpcode(addr_str, utl::u8to16(info.toString()));
                csi += info.length();
                offset += info.length();
                info.reset();
            } else {
                op_list_source_->addOpcode(addr_str, u"Unknown!!!");
                break;
            }
        }

        delete csi.provider;
    }

}
