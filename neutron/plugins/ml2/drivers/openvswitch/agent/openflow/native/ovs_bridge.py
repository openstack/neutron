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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron._i18n import _LI
from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ofswitch


LOG = logging.getLogger(__name__)


class OVSAgentBridge(ofswitch.OpenFlowSwitchMixin, ovs_lib.OVSBridge):
    """Common code for bridges used by OVS agent"""

    _cached_dpid = None

    def _get_dp(self):
        """Get (dp, ofp, ofpp) tuple for the switch.

        A convenient method for openflow message composers.
        """
        while True:
            dpid_int = self._cached_dpid
            if dpid_int is None:
                dpid_str = self.get_datapath_id()
                LOG.info(_LI("Bridge %(br_name)s has datapath-ID %(dpid)s"),
                         {"br_name": self.br_name, "dpid": dpid_str})
                dpid_int = int(dpid_str, 16)
            try:
                dp = self._get_dp_by_dpid(dpid_int)
            except RuntimeError:
                with excutils.save_and_reraise_exception() as ctx:
                    self._cached_dpid = None
                    # Retry if dpid has been changed.
                    # NOTE(yamamoto): Open vSwitch change its dpid on
                    # some events.
                    # REVISIT(yamamoto): Consider to set dpid statically.
                    new_dpid_str = self.get_datapath_id()
                    if new_dpid_str != dpid_str:
                        LOG.info(_LI("Bridge %(br_name)s changed its "
                                     "datapath-ID from %(old)s to %(new)s"), {
                            "br_name": self.br_name,
                            "old": dpid_str,
                            "new": new_dpid_str,
                        })
                        ctx.reraise = False
            else:
                self._cached_dpid = dpid_int
                return dp, dp.ofproto, dp.ofproto_parser

    def setup_controllers(self, conf):
        controllers = [
            "tcp:%(address)s:%(port)s" % {
                "address": conf.OVS.of_listen_address,
                "port": conf.OVS.of_listen_port,
            }
        ]
        self.set_protocols("OpenFlow13")
        self.set_controller(controllers)

    def drop_port(self, in_port):
        self.install_drop(priority=2, in_port=in_port)
