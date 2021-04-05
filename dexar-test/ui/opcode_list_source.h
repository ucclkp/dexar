// Copyright (c) 2019 ucclkp <ucclkp@gmail.com>.
// This file is part of dexar project.
//
// This program is licensed under GPLv3 license that can be
// found in the LICENSE file.

#ifndef DEXAR_TEST_UI_OPCODE_LIST_SOURCE_H_
#define DEXAR_TEST_UI_OPCODE_LIST_SOURCE_H_

#include <vector>

#include "ukive/views/list/list_item.h"
#include "ukive/views/list/list_source.h"
#include "ukive/views/view.h"


namespace ukive {
    class TextView;
}

namespace dexar {

    class OpcodeListSource : public ukive::ListSource {
    public:
        enum {
            ID_OPCODE_ADDRESS = 1,
            ID_OPCODE_TEXT,
        };

        struct BindData {
            std::u16string addr;
            std::u16string opcode;
        };

        class OpcodeListItem : public ukive::ListItem {
        public:
            explicit OpcodeListItem(ukive::View* v)
                : ListItem(v),
                  addr_tv(nullptr),
                  opcode_tv(nullptr)
            {
                addr_tv = reinterpret_cast<ukive::TextView*>(v->findView(ID_OPCODE_ADDRESS));
                opcode_tv = reinterpret_cast<ukive::TextView*>(v->findView(ID_OPCODE_TEXT));
            }

            ukive::TextView* addr_tv;
            ukive::TextView* opcode_tv;
        };

        OpcodeListSource();

        void addOpcode(const std::u16string& addr, const std::u16string& op);
        void clear();

    protected:
        // ukive::ListSource
        ukive::ListItem* onCreateListItem(
            ukive::LayoutView* parent, ukive::ListItemEventRouter* router,
            size_t position) override;
        void onSetListItemData(
            ukive::LayoutView* parent, ukive::ListItemEventRouter* router,
            ukive::ListItem* item) override;
        size_t onGetListDataCount(ukive::LayoutView* parent) const override;

    private:
        std::vector<BindData> data_;
    };

}

#endif  // DEXAR_TEST_UI_OPCODE_LIST_SOURCE_H_