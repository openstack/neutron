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

from neutron_lib.utils import net as n_net
from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.ovn_northbound import commands as ovn_nb_commands

from neutron.agent.ovn.extensions.evpn import constants as evpn_agent_const
from neutron.agent.ovn.extensions.evpn import utils as evpn_agent_utils
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.services.bgp import constants as bgp_const
from neutron.services.evpn import constants as evpn_const


def _evpn_ls_name(vni):
    return '%s%s' % (evpn_const.EVPN_LS_NAME_PREFIX, vni)


def _evpn_lrp_name(router_id, vni):
    evpn_ls_name = _evpn_ls_name(vni)
    return evpn_const.EVPN_LRP_NAME_PATTERN % {
        'lrp_uuid': router_id[:12],
        'evpn_ls_name': evpn_ls_name,
    }


def _evpn_lsp_name(router_id, vni):
    evpn_ls_name = _evpn_ls_name(vni)
    return evpn_const.EVPN_LSP_NAME_PATTERN % {
        'evpn_ls_name': evpn_ls_name,
        'lrp_uuid': router_id[:12],
    }


def _evpn_hcg_name(router_id):
    return '%s%s' % (evpn_const.EVPN_HCG_NAME_PREFIX, router_id)


class CreateEVPNRouterCommand(command.BaseCommand):
    """Create the full EVPN OVN topology for a router.

    Sets dynamic-routing options on the logical router, creates a dummy
    logical switch for the VNI bridge domain, connects them with a
    logical router port and logical switch port pair.
    """
    # We support only one SVD at this time.
    SVD_INDEX = 0

    def __init__(self, api, router_id, vni, vlan, gw_chassis):
        super().__init__(api)
        self.lrouter_name = ovn_utils.ovn_name(router_id)
        self.vni = vni
        self.vlan = vlan
        self.router_id = router_id
        self.gw_chassis = gw_chassis

    def run_idl(self, txn):
        self._set_router_options()

        ls_name = _evpn_ls_name(self.vni)
        lrp_name = _evpn_lrp_name(self.router_id, self.vni)
        lsp_name = _evpn_lsp_name(self.router_id, self.vni)
        mac = n_net.get_random_mac(cfg.CONF.base_mac.split(':'))

        self._create_dummy_ls(txn, ls_name)
        self._create_lrp(txn, lrp_name, mac)
        self._create_lsp(txn, ls_name, lsp_name, lrp_name)

    def _set_router_options(self):
        lrouter = idlutils.row_by_value(
            self.api.idl, 'Logical_Router',
            'name', self.lrouter_name)

        ovn_utils.setkeys(lrouter, 'options', {
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING: 'true',
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_VRF_ID: str(self.vni),
            ovn_const.LR_OPTIONS_DR_VRF_NAME:
                evpn_agent_utils.evpn_vrf_name(self.router_id),
        })

    def _create_dummy_ls(self, txn, ls_name):
        ovn_nb_commands.LsAddCommand(
            self.api, ls_name, may_exist=True,
            other_config={
                ovn_const.LS_OTHER_CFG_DR_VNI:
                    str(self.vni),
                ovn_const.LS_OTHER_CFG_DR_BRIDGE_IFNAME:
                    evpn_agent_const.EVPN_VLAN_IFNAME_PATTERN % {
                        'index': self.SVD_INDEX,
                        'vid': self.vlan,
                    },
                ovn_const.LS_OTHER_CFG_DR_VXLAN_IFNAME:
                    "%s%d" % (
                        evpn_agent_const.EVPN_VXLAN_IFNAME, self.SVD_INDEX),
            }).run_idl(txn)

    def _create_lrp(self, txn, lrp_name, mac):
        options = {
            bgp_const.LRP_OPTIONS_DYNAMIC_ROUTING_MAINTAIN_VRF: 'true',
        }
        external_ids = {
            evpn_const.EVPN_LRP_VNI_EXT_ID_KEY: str(self.vni),
            evpn_const.EVPN_LRP_VLAN_EXT_ID_KEY: str(self.vlan),
        }

        hcg_name = _evpn_hcg_name(self.router_id)
        hcg = self._create_ha_chassis_group(txn, hcg_name)

        try:
            lrp = self.api.lookup('Logical_Router_Port', lrp_name)
        except idlutils.RowNotFound:
            ovn_nb_commands.LrpAddCommand(
                self.api, self.lrouter_name, lrp_name, mac,
                networks=[],
                options=options,
                external_ids=external_ids,
                ha_chassis_group=hcg.uuid).run_idl(txn)
            return

        for column_name, column_data in (
                ('options', options), ('external_ids', external_ids)):
            ovn_utils.setkeys(lrp, column_name, column_data)
        lrp.ha_chassis_group = hcg.uuid

    def _create_ha_chassis_group(self, txn, hcg_name):
        hcg_external_ids = {
            ovn_const.OVN_ROUTER_ID_EXT_ID_KEY: self.router_id,
        }
        hcg_cmd = ovn_nb_commands.HAChassisGroupAddCommand(
            self.api, hcg_name, may_exist=True,
            external_ids=hcg_external_ids)
        hcg_cmd.run_idl(txn)
        hcg = self.api.lookup('HA_Chassis_Group', hcg_name)

        chassis_priority = ovn_utils.get_chassis_priority(self.gw_chassis)
        for chassis_name, priority in chassis_priority.items():
            ovn_nb_commands.HAChassisGroupAddChassisCommand(
                self.api, hcg.uuid, chassis_name, priority).run_idl(txn)

        return hcg

    def _create_lsp(self, txn, ls_name, lsp_name, lrp_name):
        options = {'router-port': lrp_name}
        addresses = [ovn_const.DEFAULT_ADDR_FOR_LSP_WITH_PEER]
        try:
            lsp = self.api.lookup('Logical_Switch_Port', lsp_name)
        except idlutils.RowNotFound:
            ovn_nb_commands.LspAddCommand(
                self.api, ls_name, lsp_name,
                type='router',
                options=options,
                addresses=addresses,
            ).run_idl(txn)
            return

        lsp.type = 'router'
        ovn_utils.setkeys(lsp, 'options', options)
        lsp.addresses = addresses


class AdvertiseHostCommand(command.BaseCommand):
    """Set dynamic-routing-redistribute on a logical router port."""

    def __init__(self, api, port_id):
        super().__init__(api)
        self.lrp_name = ovn_utils.ovn_lrouter_port_name(port_id)

    def run_idl(self, txn):
        lrp = idlutils.row_by_value(
            self.api.idl, 'Logical_Router_Port',
            'name', self.lrp_name)

        ovn_utils.setkeys(lrp, 'options', {
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE:
                'connected-as-host',
        })


class DeleteEVPNRouterCommand(command.BaseCommand):
    """Delete the EVPN OVN topology for a router.

    Deletes the dummy logical switch (cascades to its LSP).
    The LR and its LRP are deleted by the OvnDriver.
    """

    def __init__(self, api, vni):
        super().__init__(api)
        self.vni = vni

    def run_idl(self, txn):
        ls_name = _evpn_ls_name(self.vni)
        ovn_nb_commands.LsDelCommand(
            self.api, ls_name, if_exists=True).run_idl(txn)
