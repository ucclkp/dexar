// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#include "dexar-test/ui/opcode_list_source.h"

#include "utils/number.hpp"

#include "ukive/views/layout/restraint_layout.h"
#include "ukive/views/layout_info/restraint_layout_info.h"
#include "ukive/views/text_view.h"
#include "ukive/window/window.h"


namespace dexar {

    OpcodeListSource::OpcodeListSource() {
    }

    void OpcodeListSource::addOpcode(const std::u16string& addr, const std::u16string& op) {
        BindData dat;
        dat.addr = addr;
        dat.opcode = op;
        data_.push_back(dat);
        notifyDataChanged();
    }

    void OpcodeListSource::clear() {
        data_.clear();
        notifyDataChanged();
    }

    ukive::ListItem* OpcodeListSource::onListCreateItem(
        ukive::LayoutView* parent, int position)
    {
        using Rlp = ukive::RestraintLayoutInfo;
        auto layout = new ukive::RestraintLayout(parent->getContext());
        layout->setLayoutSize(ukive::View::LS_FILL, ukive::View::LS_AUTO);

        auto op_addr_view = new ukive::TextView(parent->getContext());
        op_addr_view->setId(ID_OPCODE_ADDRESS);
        op_addr_view->setFontFamilyName(u"Consolas");
        op_addr_view->setLayoutSize(ukive::View::LS_AUTO, ukive::View::LS_AUTO);
        auto op_ad_lp = Rlp::Builder()
            .start(layout->getId())
            .top(layout->getId()).bottom(layout->getId()).build();
        op_addr_view->setExtraLayoutInfo(op_ad_lp);
        layout->addView(op_addr_view);

        auto op_text_view = new ukive::TextView(parent->getContext());
        op_text_view->setId(ID_OPCODE_TEXT);
        op_text_view->setFontFamilyName(u"Consolas");
        op_text_view->setLayoutSize(ukive::View::LS_AUTO, ukive::View::LS_AUTO);
        op_text_view->setLayoutMargin(parent->getContext().dp2pxi(16), 0, 0, 0);
        auto op_tv_lp = Rlp::Builder()
            .start(op_addr_view->getId(), Rlp::END)
            .top(layout->getId()).bottom(layout->getId()).build();
        op_text_view->setExtraLayoutInfo(op_tv_lp);
        layout->addView(op_text_view);

        return new OpcodeListItem(layout);
    }

    void OpcodeListSource::onListSetItemData(ukive::ListItem* item, int position) {
        auto op_item = reinterpret_cast<OpcodeListItem*>(item);
        op_item->addr_tv->setText(data_[position].addr);
        op_item->opcode_tv->setText(data_[position].opcode);
    }

    int OpcodeListSource::onListGetDataCount() {
        return utl::num_cast<int>(data_.size());
    }

}
