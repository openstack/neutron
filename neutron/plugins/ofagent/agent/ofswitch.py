# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from ryu.app.ofctl import api as ofctl_api


class OpenFlowSwitch(object):
    def __init__(self, *args, **kwargs):
        super(OpenFlowSwitch, self).__init__(*args, **kwargs)
        self._dp = None
        # logically app doesn't belong here.  just for convenience.
        self._app = None

    def set_dp(self, dp):
        self._dp = dp

    def set_app(self, app):
        self._app = app

    def _get_dp(self):
        """a convenient method for openflow message composers"""
        dp = self._dp
        return (dp, dp.ofproto, dp.ofproto_parser)

    def _send_msg(self, msg):
        return ofctl_api.send_msg(self._app, msg)

    def delete_flows(self, table_id=None, strict=False, priority=0,
                     match=None, **match_kwargs):
        (dp, ofp, ofpp) = self._get_dp()
        if table_id is None:
            table_id = ofp.OFPTT_ALL
        if match is None:
            match = ofpp.OFPMatch(**match_kwargs)
        if strict:
            cmd = ofp.OFPFC_DELETE_STRICT
        else:
            cmd = ofp.OFPFC_DELETE
        msg = ofpp.OFPFlowMod(dp,
                              command=cmd,
                              table_id=table_id,
                              match=match,
                              priority=priority,
                              out_group=ofp.OFPG_ANY,
                              out_port=ofp.OFPP_ANY)
        self._send_msg(msg)

    def install_default_drop(self, table_id):
        (dp, _ofp, ofpp) = self._get_dp()
        msg = ofpp.OFPFlowMod(dp,
                              table_id=table_id,
                              priority=0)
        self._send_msg(msg)

    def install_default_goto(self, table_id, dest_table_id):
        (dp, _ofp, ofpp) = self._get_dp()
        instructions = [ofpp.OFPInstructionGotoTable(table_id=dest_table_id)]
        msg = ofpp.OFPFlowMod(dp,
                              table_id=table_id,
                              priority=0,
                              instructions=instructions)
        self._send_msg(msg)

    def install_default_goto_next(self, table_id):
        self.install_default_goto(table_id, table_id + 1)
