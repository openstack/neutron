# Copyright 2026 Red Hat, Inc.
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

from oslo_log import log
from pyroute2.netlink import rtnl

from neutron.agent.linux import nl_constants as nl_const
from neutron.agent.linux import nl_dispatcher
from neutron.agent.ovn.extensions.evpn import constants as evpn_const
from neutron.agent.ovn.extensions.evpn import events as evpn_events
from neutron.agent.ovn.extensions.evpn import fsm
from neutron.agent.ovn.extensions.evpn import netlink_monitor
from neutron.agent.ovn.extensions import extension_manager as ovn_ext_mgr

LOG = log.getLogger(__name__)


class EVPNAgentExtension(ovn_ext_mgr.OVNAgentExtension):
    def __init__(self):
        super().__init__()
        self._evpn_fsm = None
        self.nl_dispatcher = None

    def start(self):
        super().start()
        self._evpn_fsm = fsm.EvpnFSM()
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
        return ['Port_Binding']

    @property
    def sb_idl_events(self):
        return [
            evpn_events.PortBindingLrpEvpnCreateEvent(self._evpn_fsm),
            evpn_events.PortBindingLrpEvpnDeleteEvent(self._evpn_fsm),
        ]
