# Copyright 2026 Red Hat, LLC
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

import dataclasses

from neutron_lib.utils import net as net_lib
from oslo_config import cfg
from oslo_log import log
from pyroute2.netlink import rtnl

from neutron.agent.linux import nl_constants as nl_const
from neutron.agent.linux import nl_dispatcher
from neutron.agent.linux import svd as linux_svd
from neutron.agent.ovn.extensions.evpn import constants as evpn_const
from neutron.agent.ovn.extensions.evpn import events as evpn_events
from neutron.agent.ovn.extensions.evpn import fsm
from neutron.agent.ovn.extensions.evpn import fsm_frr_driver
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.agent.ovn.extensions.evpn import svd
from neutron.agent.ovn.extensions import extension_manager as ovn_ext_mgr
from neutron.privileged.agent.linux import svd as privileged_svd

LOG = log.getLogger(__name__)
CONF = cfg.CONF


@dataclasses.dataclass(frozen=True)
class EvpnConfig:
    local_ip: str
    dstport: int
    vxlan_parent: str
    mac: str
    br_mtu: int


class EVPNAgentExtension(ovn_ext_mgr.OVNAgentExtension):
    def __init__(self):
        super().__init__()
        self._evpn_fsm = fsm.EvpnFSM()
        self.nl_dispatcher = None

    def _get_evpn_config(self):
        ext_ids = self.agent_api.ovs_idl.db_get(
            'Open_vSwitch', '.', 'external_ids').execute()
        local_ip = ext_ids['ovn-evpn-local-ip']
        vxlan_port = ext_ids['ovn-evpn-vxlan-ports']
        vxlan_parent = 'vxlan_sys_%s' % vxlan_port
        dstport = CONF.ovn_evpn.child_vxlan_port
        mac = net_lib.get_random_mac(CONF.base_mac.split(':'))
        self.cfg = EvpnConfig(local_ip=local_ip, dstport=dstport,
                              vxlan_parent=vxlan_parent, mac=mac,
                              br_mtu=evpn_const.EVPN_BR_MTU)
        LOG.debug("EVPN config: local_ip %s vxlan_parent %s "
                  "child vxlan port %d SVD MAC %s",
                  self.cfg.local_ip, self.cfg.vxlan_parent,
                  self.cfg.dstport, self.cfg.mac)

    def start(self):
        self._get_evpn_config()

        privileged_svd.register_vxlan_vnifilter()
        br_evpn = '%s%d' % (evpn_const.EVPN_LB_NAME_PREFIX, 0)
        vxlan_evpn = '%s%d' % (evpn_const.EVPN_VXLAN_IFNAME, 0)
        self.svd = svd.EvpnSvd(br_evpn=br_evpn, vxlan_evpn=vxlan_evpn)
        try:
            self.svd.create(local_ip=self.cfg.local_ip,
                            mac=self.cfg.mac,
                            vxlan_parent=self.cfg.vxlan_parent,
                            dstport=self.cfg.dstport, br_mtu=self.cfg.br_mtu)
        except linux_svd.SvdDeviceAlreadyExists:
            LOG.warning("SVD already exists, reusing")
        driver = fsm_frr_driver.FsmFrrVtyshDriver(
            peer_interface=CONF.ovn_evpn.bgp_local_interface,
            bgp_router_id=self.cfg.local_ip)
        self._evpn_fsm.setup(self.svd, self.cfg, driver)
        vrf_handler = netlink_monitor.VrfHandler(self._evpn_fsm)
        self.nl_dispatcher = nl_dispatcher.NetlinkDispatcher(
            rtnl.RTMGRP_LINK)
        self.nl_dispatcher.register_handler(
            nl_const.RTM_NEWLINK, vrf_handler.handle_newlink)
        self.nl_dispatcher.register_handler(
            nl_const.RTM_DELLINK, vrf_handler.handle_dellink)
        self.nl_dispatcher.register_replay_callbacks(
            on_start=vrf_handler.replay_start,
            on_end=vrf_handler.replay_end)
        self.nl_dispatcher.start()
        LOG.info("NetlinkDispatcher started as part of EVPN extension")
        super().start()

    @property
    def name(self):
        return evpn_const.EVPN_EXT_NAME

    @property
    def ovs_idl_events(self):
        return []

    @property
    def nb_idl_tables(self):
        return []

    @property
    def nb_idl_events(self):
        return []

    @property
    def sb_idl_tables(self):
        return ['Port_Binding', 'Chassis']

    @property
    def sb_idl_events(self):
        return [
            evpn_events.PortBindingLrpEvpnCreateEvent(self._evpn_fsm,
                                                      self.agent_api.chassis),
            evpn_events.PortBindingLrpEvpnDeleteEvent(self._evpn_fsm,
                                                      self.agent_api.chassis),
        ]
