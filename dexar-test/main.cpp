// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "utils/log.h"
#include "utils/platform_utils.h"
#include "utils/platform_entrances.h"

#include "ukive/app/application.h"

#include "dexar-test/ui/dexar_window.h"


GUI_MAIN()
{
    utl::Log::Params log_params;
    log_params.file_name = u"dexar-debug.log";
    log_params.short_file_name = false;
    log_params.target = utl::Log::OutputTarget::DEBUGGER | utl::Log::OutputTarget::FILE;
    utl::InitLogging(log_params);

    LOG(Log::INFO) << "dexar-test start.";

    ukive::Application::Options options;
    options.is_auto_dpi_scale = false;

    auto app = std::make_shared<ukive::Application>(options);

    auto dar_window = std::make_shared<dexar::DisassemblerWindow>();
    dar_window->init(ukive::Window::InitParams());
    dar_window->setTitle(u"Disassembler");
    dar_window->setWidth(ukive::Application::dp2pxi(600));
    dar_window->setHeight(ukive::Application::dp2pxi(600));
    dar_window->center();
    dar_window->show();

    app->run();

    LOG(Log::INFO) << "dexar-test exit.\n";

    utl::UninitLogging();

    return 0;
}