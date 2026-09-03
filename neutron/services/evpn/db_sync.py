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

from datetime import datetime

from neutron_lib import context
from neutron_lib.ovn import constants as n_lib_ovn_const
from neutron_lib.ovn import db_sync as db_sync_base
from oslo_log import log

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.db import evpn_db
from neutron.services.bgp import constants as bgp_const
from neutron.services.evpn import commands as evpn_commands
from neutron.services.evpn import constants as evpn_const
from neutron.services.evpn import helpers as evpn_helpers


LOG = log.getLogger(__name__)


class EvpnLoggingSynchronizer:

    def __enter__(self):
        return None

    def __exit__(self, *args, **kwargs):
        pass

    def _sync_topology(self, router_id, inst):
        LOG.warning("EVPN topology for router %s missing or "
                    "incomplete in OVN NB DB", router_id)

    def _sync_missing_advertised(self, port_id, lrp_name):
        LOG.warning("EVPN advertise-host for port %s (LRP %s) "
                    "found in Neutron but not in OVN NB DB",
                    port_id, lrp_name)

    def _sync_orphan_ls(self, name):
        LOG.warning("EVPN Logical Switch %s found in OVN NB "
                    "DB but not in Neutron", name)

    def _sync_orphan_hcg(self, name):
        LOG.warning("EVPN HA Chassis Group %s found in OVN "
                    "NB DB but not in Neutron", name)

    def _sync_orphan_lsp(self, name):
        LOG.warning("EVPN Logical Switch Port %s found in "
                    "OVN NB DB but not in Neutron", name)

    def _sync_orphan_advertised(self, name):
        LOG.warning("EVPN advertise-host option on LRP %s "
                    "found in OVN NB DB but not in Neutron",
                    name)


class EvpnRepairSynchronizer(EvpnLoggingSynchronizer):

    def __init__(self, ovn_nb_api, gw_chassis):
        self.ovn_nb_api = ovn_nb_api
        self.gw_chassis = gw_chassis
        self._txn_ctx = ovn_nb_api.transaction(check_error=True)

    def __enter__(self):
        self._txn = self._txn_ctx.__enter__()

    def __exit__(self, *args, **kwargs):
        self._txn_ctx.__exit__(*args, **kwargs)

    def _sync_topology(self, router_id, inst):
        super()._sync_topology(router_id, inst)
        LOG.warning("Repairing EVPN topology for router %s",
                    router_id)
        self._txn.add(evpn_commands.CreateEVPNRouterCommand(
            self.ovn_nb_api, router_id,
            inst['vni'], inst['vlan'], self.gw_chassis))

    def _sync_missing_advertised(self, port_id, lrp_name):
        super()._sync_missing_advertised(port_id, lrp_name)
        LOG.warning("Repairing EVPN advertise-host "
                    "for port %s", port_id)
        self._txn.add(evpn_commands.AdvertiseHostCommand(
            self.ovn_nb_api, port_id))

    def _sync_orphan_ls(self, name):
        super()._sync_orphan_ls(name)
        LOG.warning("Deleting orphan EVPN Logical "
                    "Switch %s", name)
        self._txn.add(self.ovn_nb_api.ls_del(
            name, if_exists=True))

    def _sync_orphan_hcg(self, name):
        super()._sync_orphan_hcg(name)
        LOG.warning("Deleting orphan EVPN HA Chassis "
                    "Group %s", name)
        self._txn.add(self.ovn_nb_api.ha_chassis_group_del(
            name, if_exists=True))

    def _sync_orphan_lsp(self, name):
        super()._sync_orphan_lsp(name)
        LOG.warning("Deleting orphan EVPN Logical Switch "
                    "Port %s", name)
        self._txn.add(self.ovn_nb_api.lsp_del(
            name, if_exists=True))

    def _sync_orphan_advertised(self, name):
        super()._sync_orphan_advertised(name)
        LOG.warning("Removing orphan EVPN advertise-host "
                    "option from LRP %s", name)
        self._txn.add(self.ovn_nb_api.db_remove(
            'Logical_Router_Port', name, 'options',
            bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE,
            if_exists=True))


class EvpnOvnSynchronizer(db_sync_base.BaseOvnDbSynchronizer):

    _required_mechanism_drivers = ['ovn-sync']
    _required_service_plugins = ['evpn']
    _required_ml2_ext_drivers = []
    _sync_order = 1

    def do_sync(self):
        LOG.debug('OVN-NB Sync EVPN started @ %s', str(datetime.now()))
        ctx = context.get_admin_context()

        db_helper = evpn_db.EVPNDbHelper()
        db_instances = db_helper.get_all_evpn_l3_instances(ctx)
        db_advertised_ports = db_helper.get_all_evpn_advertised_ports(ctx)

        db_routers = {}
        expected_ls = set()
        expected_hcg = set()
        expected_lrp = set()
        expected_lsp = set()
        for inst in db_instances:
            router_id = inst['router_id']
            vni = inst['vni']
            db_routers[router_id] = inst
            expected_ls.add(evpn_helpers.evpn_ls_name(vni))
            expected_hcg.add(evpn_helpers.evpn_hcg_name(router_id))
            expected_lrp.add(evpn_helpers.evpn_lrp_name(router_id, vni))
            expected_lsp.add(evpn_helpers.evpn_lsp_name(router_id, vni))

        expected_advertised = {
            utils.ovn_lrouter_port_name(port_id)
            for port_id in db_advertised_ports}

        ovn_ls = {
            row.name for row in self.ovn_nb_api.db_find_rows(
                'Logical_Switch',
                ('other_config', '!=', {
                    ovn_const.LS_OTHER_CFG_DR_VNI: ''}),
            ).execute(check_error=True)}

        ovn_hcg = {
            row.name for row in self.ovn_nb_api.db_find_rows(
                'HA_Chassis_Group',
                ('external_ids', '!=', {
                    ovn_const.OVN_ROUTER_ID_EXT_ID_KEY: ''}),
            ).execute(check_error=True)}

        ovn_lrp = {
            row.name for row in self.ovn_nb_api.db_find_rows(
                'Logical_Router_Port',
                ('external_ids', '!=', {
                    evpn_const.EVPN_LRP_VNI_EXT_ID_KEY: ''}),
            ).execute(check_error=True)}

        ovn_advertised = {
            row.name for row in self.ovn_nb_api.db_find_rows(
                'Logical_Router_Port',
                ('options', '!=', {
                    bgp_const.LR_OPTIONS_DYNAMIC_ROUTING_REDISTRIBUTE: ''}),
            ).execute(check_error=True)}

        ovn_lsp = {
            row.name for row in self.ovn_nb_api.db_find_rows(
                'Logical_Switch_Port',
                ('type', '=', 'router'),
                ('options', '!=', {'router-port': ''}),
            ).execute(check_error=True)
            if row.options.get('router-port', '').startswith('evpn-lrp-')}

        if not any((expected_ls, ovn_ls, expected_advertised, ovn_advertised)):
            LOG.debug('No EVPN state in DB or OVN, skipping EVPN sync')
            LOG.debug('OVN-NB Sync EVPN completed @ %s', str(datetime.now()))
            return

        missing_ls = expected_ls - ovn_ls
        missing_hcg = expected_hcg - ovn_hcg
        missing_lrp = expected_lrp - ovn_lrp
        missing_lsp = expected_lsp - ovn_lsp
        missing_advertised = expected_advertised - ovn_advertised

        orphan_ls = ovn_ls - expected_ls
        orphan_hcg = ovn_hcg - expected_hcg
        orphan_lsp = ovn_lsp - expected_lsp
        orphan_advertised = ovn_advertised - expected_advertised

        routers_to_repair = set()
        for inst in db_instances:
            router_id = inst['router_id']
            vni = inst['vni']
            ls_name = evpn_helpers.evpn_ls_name(vni)
            hcg_name = evpn_helpers.evpn_hcg_name(router_id)
            lrp_name = evpn_helpers.evpn_lrp_name(router_id, vni)
            lsp_name = evpn_helpers.evpn_lsp_name(router_id, vni)
            if any(name in missing
                   for name, missing in ((ls_name, missing_ls),
                                         (hcg_name, missing_hcg),
                                         (lrp_name, missing_lrp),
                                         (lsp_name, missing_lsp))):
                routers_to_repair.add(router_id)

        advertised_lrp_to_port = {
            utils.ovn_lrouter_port_name(port_id): port_id
            for port_id in db_advertised_ports}

        repair = self.mode == n_lib_ovn_const.OVN_DB_SYNC_MODE_REPAIR
        if repair:
            gw_chassis = (
                self.ovn_sb_api.get_gateway_chassis_from_cms_options())
            syncer = EvpnRepairSynchronizer(self.ovn_nb_api, gw_chassis)
        else:
            syncer = EvpnLoggingSynchronizer()

        with syncer:
            for router_id in routers_to_repair:
                syncer._sync_topology(router_id, db_routers[router_id])

            for lrp_name in missing_advertised:
                try:
                    port_id = advertised_lrp_to_port[lrp_name]
                except KeyError:
                    continue
                syncer._sync_missing_advertised(port_id, lrp_name)

            for name in orphan_ls:
                syncer._sync_orphan_ls(name)

            for name in orphan_hcg:
                syncer._sync_orphan_hcg(name)

            for name in orphan_lsp:
                syncer._sync_orphan_lsp(name)

            for name in orphan_advertised:
                syncer._sync_orphan_advertised(name)

        LOG.debug('OVN-NB Sync EVPN completed @ %s', str(datetime.now()))
