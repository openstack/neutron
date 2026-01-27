# Copyright 2025 Red Hat, Inc.
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

from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl

from neutron.common import utils as common_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf.services import bgp as bgp_config
from neutron.services.bgp import constants
from neutron.services.bgp import helpers
from neutron.services.bgp import ovn as bgp_ovn
from neutron.services.bgp import reconciler
from neutron.tests.functional import base
from neutron.tests.functional.services import bgp as bgp_tests


class TestBGPReconciler(base.TestOVNFunctionalBase):
    def setUp(self):
        ovn_conf.register_opts()
        bgp_config.register_opts(cfg.CONF)
        sb_impl_idl.OvnSbApiIdlImpl._ovsdb_connection = None
        bgp_ovn.BgpOvnSbIdl._ovsdb_connection = None
        bgp_ovn.BgpOvnNbIdl._ovsdb_connection = None
        super().setUp()
        self.reconciler = reconciler.BGPTopologyReconciler()

        if not bgp_tests.is_policy_output_port_column_supported(
                self.reconciler.nb_api.idl):
            raise self.skipException("Policy output port column not supported")

        self.nb_api = self.reconciler.nb_api
        self.sb_api = self.reconciler.sb_api

        self.test_sb_idl = self._create_additional_sb_idl()
        self.chassis_bgp_networks = ('bgp-net-1', 'bgp-net-2')

    @staticmethod
    def _create_additional_sb_idl():
        """Create a secondary SB IDL for testing.

        The sb_api instance does not register the Encap table and can't be used
        to create a chassis. This secondary SB IDL is there to control the
        chassis used for testing.
        """
        tables = ['Chassis', 'Chassis_Private', 'Encap']
        connection_string = ovn_conf.get_ovn_sb_connection()
        idl = connection.OvsdbIdl.from_server(
            connection_string, 'OVN_Southbound', helper_tables=tables)
        conn = connection.Connection(idl, timeout=10)
        return sb_impl_idl.OvnSbApiIdlImpl(conn)

    def _create_chassis(self, chassis_name, ip, bgp_bridges=None):
        external_ids = {}
        chassis = self.test_sb_idl.chassis_add(
            chassis_name,
            ['geneve'],
            ip,
            hostname=chassis_name,
        ).execute(check_error=True)

        if bgp_bridges:
            external_ids[
                constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY] = ','.join(
                    bgp_bridges)
        self.sb_api.db_create(
            'Chassis_Private', name=chassis_name,
            chassis=chassis.uuid,
            external_ids=external_ids
        ).execute(check_error=True)

        return self.sb_api.db_list_rows(
            'Chassis_Private', [chassis_name]).execute(check_error=True)[0]

    def _get_all_chassis_private(self):
        return self.sb_api.db_list_rows('Chassis_Private').execute(
            check_error=True)

    def validate_topology(self, chassis):
        self._validate_main_router()
        for ch in chassis:
            self._validate_chassis(ch)

    def _validate_main_router(self):
        main_router_name = bgp_config.get_main_router_name()
        main_router = self.nb_api.lr_get(
            main_router_name).execute(check_error=True)
        all_chassis_names = {
            chassis.name for chassis in self._get_all_chassis_private()}
        for chassis_name in list(all_chassis_names):
            chassis_router_name = helpers.get_chassis_router_name(chassis_name)
            lrp_to_chassis_router_name = helpers.get_lrp_name(
                main_router_name, chassis_router_name)
            lrp = self.nb_api.lrp_get(
                lrp_to_chassis_router_name).execute(check_error=True)
            self.assertIn(lrp, main_router.ports)

            try:
                ha_chassis = lrp.ha_chassis_group[0].ha_chassis[0]
            except IndexError:
                self.fail(
                    f"LRP {lrp.name} on the main BGP router has no chassis "
                    f"binding: {lrp.ha_chassis_group}")

            self.assertEqual(ha_chassis.chassis_name, chassis_name)
            try:
                all_chassis_names.remove(chassis_name)
            except KeyError:
                self.fail(f"Chassis {chassis_name} not found for LRP "
                          f"{lrp_to_chassis_router_name} on the main BGP "
                          f"router")
        if all_chassis_names:
            self.fail(f"There are some chassis remaining that do not have an "
                      f"LRP from the main BGP router bound to it: "
                      f"{all_chassis_names}")

    def _validate_chassis(self, chassis):
        router_name = helpers.get_chassis_router_name(chassis.name)
        router = self.nb_api.lr_get(router_name).execute(check_error=True)

        self.assertEqual(chassis.name, router.options.get('chassis'))
        # each router has two connections out and one to the main BGP router
        self.assertEqual(3, len(router.ports))

        # each router should be connected to two switches with name format
        # bgp-ls-<chassis_name>-<network_name> where network names are from
        # the bgp_peer_connections: bgp-net-1 and bgp-net-2
        for network_name in self.chassis_bgp_networks:
            switch_name = helpers.get_chassis_peer_switch_name(
                chassis.name, network_name)
            ls = self.nb_api.ls_get(switch_name).execute(check_error=True)

            # each switch should have a localnet port with the network name set
            # and one port plugged to the router
            self.assertEqual(2, len(ls.ports))
            for lsp in ls.ports:
                if lsp.type == 'localnet':
                    self.assertEqual(
                        network_name, lsp.options.get('network_name'))
                elif lsp.type == 'router':
                    lrp = self.nb_api.lrp_get(
                        lsp.options.get('router-port')).execute(
                            check_error=True)
                    self.assertIn(lrp, router.ports)
                    ext_ids = lrp.external_ids
                    self.assertEqual(
                        network_name, ext_ids[
                            constants.LRP_NETWORK_NAME_EXT_ID_KEY])

    def test_full_sync(self):
        for i in range(0, 6):
            chassis_name = f'chassis{i}'
            self._create_chassis(
                chassis_name, f'192.168.1.10{i}',
                bgp_bridges=self.chassis_bgp_networks)
        self.reconciler.full_sync()

        self.validate_topology(self._get_all_chassis_private())

    def test_setting_chassis_bgp_bridges_configures_lrps(self):
        chassis = self._create_chassis(
            'chassis', '192.168.1.100')

        self.reconciler.full_sync()

        # we have an environment with one chassis without bgp peer connections
        # set
        chassis = self._get_all_chassis_private()[0]

        # There should be no switches in the environment
        switches = self.nb_api.db_list_rows('Logical_Switch').execute(
            check_error=True)
        self.assertEqual(0, len(switches))

        external_ids = {constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY: ','.join(
            self.chassis_bgp_networks)}

        self.test_sb_idl.db_set(
            'Chassis_Private', 'chassis', external_ids=external_ids).execute(
                check_error=True)

        def switches_created():
            return len(self.nb_api.db_list_rows('Logical_Switch').execute(
                check_error=True)) == 2

        common_utils.wait_until_true(
            switches_created,
            timeout=10,
            exception=Exception(
                "Peer switches were not created")
        )

        self.validate_topology([chassis])
