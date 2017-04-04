# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import re

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# Field name mappings (from Ryu to ovs-ofctl)
_keywords = {
    'eth_src': 'dl_src',
    'eth_dst': 'dl_dst',
    'ipv4_src': 'nw_src',
    'ipv4_dst': 'nw_dst',
    'table_id': 'table',
}


class OpenFlowSwitchMixin(object):
    """Mixin to provide common convenient routines for an openflow switch."""

    @staticmethod
    def _conv_args(kwargs):
        for our_name, ovs_ofctl_name in _keywords.items():
            if our_name in kwargs:
                kwargs[ovs_ofctl_name] = kwargs.pop(our_name)
        return kwargs

    def dump_flows(self, table_id):
        return self.dump_flows_for_table(table_id)

    def dump_flows_all_tables(self):
        return self.dump_all_flows()

    def install_goto_next(self, table_id):
        self.install_goto(table_id=table_id, dest_table_id=table_id + 1)

    def install_output(self, port, table_id=0, priority=0, **kwargs):
        self.add_flow(table=table_id,
                      priority=priority,
                      actions="output:%s" % port,
                      **self._conv_args(kwargs))

    def install_normal(self, table_id=0, priority=0, **kwargs):
        self.add_flow(table=table_id,
                      priority=priority,
                      actions="normal",
                      **self._conv_args(kwargs))

    def install_goto(self, dest_table_id, table_id=0, priority=0, **kwargs):
        self.add_flow(table=table_id,
                      priority=priority,
                      actions="resubmit(,%s)" % dest_table_id,
                      **self._conv_args(kwargs))

    def install_drop(self, table_id=0, priority=0, **kwargs):
        self.add_flow(table=table_id,
                      priority=priority,
                      actions="drop",
                      **self._conv_args(kwargs))

    def install_instructions(self, instructions,
                             table_id=0, priority=0, **kwargs):
        self.add_flow(table=table_id,
                      priority=priority,
                      actions=instructions,
                      **self._conv_args(kwargs))

    def uninstall_flows(self, **kwargs):
        # NOTE(yamamoto): super() points to ovs_lib.OVSBridge.
        # See ovs_bridge.py how this class is actually used.
        super(OpenFlowSwitchMixin, self).delete_flows(
              **self._conv_args(kwargs))

    def _filter_flows(self, flows):
        cookie_list = self.reserved_cookies
        LOG.debug("Bridge cookies used to filter flows: %s",
                  cookie_list)
        cookie_re = re.compile('cookie=(0x[A-Fa-f0-9]*)')
        table_re = re.compile('table=([0-9]*)')
        for flow in flows:
            fl_cookie = cookie_re.search(flow)
            if not fl_cookie:
                continue
            fl_cookie = fl_cookie.group(1)
            if int(fl_cookie, 16) not in cookie_list:
                fl_table = table_re.search(flow)
                if not fl_table:
                    continue
                fl_table = fl_table.group(1)
                yield flow, fl_cookie, fl_table

    def cleanup_flows(self):
        flows = self.dump_flows_all_tables()
        for flow, cookie, table in self._filter_flows(flows):
            # deleting a stale flow should be rare.
            # it might deserve some attention
            LOG.warning("Deleting flow %s", flow)
            self.delete_flows(cookie=cookie + '/-1', table=table)
