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

from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from os_ken.lib.packet import arp
from os_ken.lib.packet import ether_types
from oslo_log import log as logging
from oslo_utils import excutils

from neutron._i18n import _
from neutron.agent.common import ovs_lib
from neutron.common import ipv6_utils
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
                    raise RuntimeError(_("Unknown datapath id."))
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
        # NOTE(slaweq): Disable remote in-band management for all controllers
        # in the bridge
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
        # Setting connection_mode for controllers should be done in single
        # transaction together with controllers setup but it will be easier to
        # disable in-band remote management for bridge which
        # effectively means that this configurations will applied to all
        # controllers in the bridge
        #
        # [1] https://github.com/openvswitch/ovs/blob/master/DESIGN.md
        # [2] https://bugzilla.redhat.com/show_bug.cgi?id=2134772
        self.disable_in_band()

        url = ipv6_utils.valid_ipv6_url(conf.OVS.of_listen_address,
                                        conf.OVS.of_listen_port)
        controller = "tcp:" + url
        existing_controllers = self.get_controller()
        if controller not in existing_controllers:
            LOG.debug("Setting controller %s for bridge %s.",
                      controller, self.br_name)
            self.set_controller([controller])

        self.add_protocols(ovs_consts.OPENFLOW10, ovs_consts.OPENFLOW13)
        self.set_controllers_inactivity_probe(conf.OVS.of_inactivity_probe)

    def drop_port(self, in_port):
        self.install_drop(priority=2, in_port=in_port)

    @staticmethod
    def _arp_responder_match(ofp, ofpp, vlan, ip):
        return ofpp.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                             arp_tpa=ip)

    def install_arp_responder(self, vlan, ip, mac,
                              table_id=ovs_consts.ARP_RESPONDER):
        (dp, ofp, ofpp) = self._get_dp()
        match = self._arp_responder_match(ofp, ofpp, vlan, ip)
        actions = [ofpp.OFPActionSetField(arp_op=arp.ARP_REPLY),
                   ofpp.NXActionRegMove(src_field='arp_sha',
                                        dst_field='arp_tha',
                                        n_bits=48),
                   ofpp.NXActionRegMove(src_field='arp_spa',
                                        dst_field='arp_tpa',
                                        n_bits=32),
                   ofpp.OFPActionSetField(arp_sha=mac),
                   ofpp.OFPActionSetField(arp_spa=ip),
                   ofpp.NXActionRegMove(src_field='eth_src',
                                        dst_field='eth_dst',
                                        n_bits=48),
                   ofpp.OFPActionSetField(eth_src=mac),
                   ofpp.OFPActionOutput(ofp.OFPP_IN_PORT, 0)]
        self.install_apply_actions(table_id=table_id,
                                   priority=1,
                                   match=match,
                                   actions=actions)

    def delete_arp_responder(self, vlan, ip,
                             table_id=ovs_consts.ARP_RESPONDER):
        (_dp, ofp, ofpp) = self._get_dp()
        match = self._arp_responder_match(ofp, ofpp, vlan, ip)
        self.uninstall_flows(table_id=table_id,
                             priority=1,
                             match=match)
