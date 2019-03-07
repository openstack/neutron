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

from neutron.agent.common import ovs_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow \
    import br_cookie
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.native \
    import ofswitch


LOG = logging.getLogger(__name__)


class OVSAgentBridge(ofswitch.OpenFlowSwitchMixin,
                     br_cookie.OVSBridgeCookieMixin, ovs_lib.OVSBridge):
    """Common code for bridges used by OVS agent"""

    _cached_dpid = None

    def _get_dp(self):
        """Get (dp, ofp, ofpp) tuple for the switch.

        A convenient method for openflow message composers.
        """
        while True:
            if self._cached_dpid is None:
                dpid = self.get_datapath_id()
                LOG.info("Bridge %(br_name)s has datapath-ID %(dpid)s",
                         {"br_name": self.br_name, "dpid": dpid})
                if dpid is None:
                    raise RuntimeError("Unknown datapath id.")
                self._cached_dpid = int(dpid, 16)
            try:
                dp = self._get_dp_by_dpid(self._cached_dpid)
                return dp, dp.ofproto, dp.ofproto_parser
            except RuntimeError:
                with excutils.save_and_reraise_exception() as ctx:
                    # Retry if dpid has been changed.
                    # NOTE(yamamoto): Open vSwitch change its dpid on
                    # some events.
                    # REVISIT(yamamoto): Consider to set dpid statically.
                    new_dpid = int(self.get_datapath_id(), 16)
                    if new_dpid != self._cached_dpid:
                        LOG.info("Bridge %(br_name)s changed its "
                                 "datapath-ID from %(old)x to %(new)x", {
                                     "br_name": self.br_name,
                                     "old": self._cached_dpid,
                                     "new": new_dpid,
                                 })
                        ctx.reraise = False
                    self._cached_dpid = new_dpid

    def setup_controllers(self, conf):
        controllers = [
            "tcp:%(address)s:%(port)s" % {
                "address": conf.OVS.of_listen_address,
                "port": conf.OVS.of_listen_port,
            }
        ]
        self.add_protocols(ovs_consts.OPENFLOW13)
        self.set_controller(controllers)

        # NOTE(ivc): Force "out-of-band" controller connection mode (see
        # "In-Band Control" [1]).
        #
        # By default openvswitch uses "in-band" controller connection mode
        # which adds hidden OpenFlow rules (only visible by issuing ovs-appctl
        # bridge/dump-flows <br>) and leads to a network loop on br-tun. As of
        # now the OF controller is hosted locally with OVS which fits the
        # "out-of-band" mode. If the remote OF controller is ever to be
        # supported by openvswitch agent in the future, "In-Band Control" [1]
        # should be taken into consideration for physical bridge only, but
        # br-int and br-tun must be configured with the "out-of-band"
        # controller connection mode.
        #
        # [1] https://github.com/openvswitch/ovs/blob/master/DESIGN.md
        self.set_controllers_connection_mode("out-of-band")
        self.set_controllers_inactivity_probe(conf.OVS.of_inactivity_probe)

    def drop_port(self, in_port):
        self.install_drop(priority=2, in_port=in_port)
