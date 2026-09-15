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

import queue
from unittest import mock

from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.schema.ovn_southbound import impl_idl as sb_impl_idl

from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as common_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.conf.services import bgp as bgp_config
from neutron.services.bgp import constants
from neutron.services.bgp import helpers
from neutron.services.bgp import ovn as bgp_ovn
from neutron.services.bgp import reconciler
from neutron.tests.functional import base
from neutron.tests.functional.services import bgp


class BGPReconcilerTestBase(base.TestOVNFunctionalBase):
    """Chassis creation and topology validation helpers.

    Everything here works off test_sb_idl and self.nb_api, neither of which
    has to belong to the reconciler under test, so subclasses are free to
    decide how many reconcilers to run and when to start them.
    """

    def setUp(self):
        ovn_conf.register_opts()
        bgp_config.register_opts(cfg.CONF)
        sb_impl_idl.OvnSbApiIdlImpl._ovsdb_connection = None
        bgp_ovn.BgpOvnSbIdl._ovsdb_connection = None
        bgp_ovn.BgpOvnNbIdl._ovsdb_connection = None
        super().setUp()
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
        self.test_sb_idl.db_create(
            'Chassis_Private', name=chassis_name,
            chassis=chassis.uuid,
            external_ids=external_ids
        ).execute(check_error=True)

        return self.test_sb_idl.db_list_rows(
            'Chassis_Private', [chassis_name]).execute(check_error=True)[0]

    def _get_all_chassis_private(self):
        return self.test_sb_idl.db_list_rows('Chassis_Private').execute(
            check_error=True)

    def validate_topology(self, chassis):
        self._validate_main_router()
        for ch in chassis:
            self._validate_chassis(ch)

    def _validate_main_router(self):
        main_router = self.nb_api.lr_get(
            constants.MAIN_ROUTER_NAME).execute(check_error=True)
        all_chassis_names = {
            chassis.name for chassis in self._get_all_chassis_private()}
        for chassis_name in list(all_chassis_names):
            chassis_router_name = helpers.get_chassis_router_name(chassis_name)
            lrp_to_chassis_router_name = helpers.get_lrp_name(
                constants.MAIN_ROUTER_NAME, chassis_router_name)
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

    def _wait_for_topology(self, chassis):
        """Wait for the reconciler to build a valid topology for chassis."""
        def reconciled():
            try:
                self.validate_topology(chassis)
            except Exception:
                return False
            return True

        try:
            common_utils.wait_until_true(reconciled, timeout=30)
        except common_utils.WaitTimeout:
            # Run it once more outside the predicate so the failure says
            # what is actually wrong with the topology.
            self.validate_topology(chassis)
            raise


class SyncRecordingReconciler(reconciler.BGPTopologyReconciler):
    """Reconciler that records its full syncs so a test can wait on one."""

    def __init__(self):
        super().__init__()
        self.syncs = queue.Queue()

    def full_sync(self):
        super().full_sync()
        self.syncs.put(True)


class TestBGPReconciler(BGPReconcilerTestBase):
    def setUp(self):
        super().setUp()
        self.reconciler = SyncRecordingReconciler()
        self.addCleanup(self.reconciler.stop)
        self.reconciler.start()

        self.nb_api = self.reconciler.nb_api
        self.sb_api = self.reconciler.sb_api

        # Taking the lock kicks off a full sync on the notify_loop thread.
        # Let it finish so it can't overlap the full_sync() calls the tests
        # below make from the test thread.
        self.reconciler.syncs.get(timeout=30)

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

    def test_fip_created_updates_arp_proxy(self):
        self._create_chassis(
            'chassis', '192.168.1.100',
            bgp_bridges=self.chassis_bgp_networks)

        net_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        ls_name = f'neutron-{net_id}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.lsp_add(
                ls_name, f'{ls_name}-localnet',
                type='localnet',
                options={'network_name': 'physnet1'},
                addresses=['unknown'],
            ))
            txn.add(self.nb_api.db_set(
                'Logical_Switch', ls_name,
                external_ids={
                    ovn_const.OVN_NETTYPE_EXT_ID_KEY: 'flat'}))

        self.reconciler.full_sync()

        interconnect_name = helpers.get_provider_interconnect_switch_name(
            ls_name)
        lsp_name = helpers.get_lsp_name(
            interconnect_name, constants.MAIN_ROUTER_NAME)

        router_name = 'neutron-tenant-router'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(router_name))
            txn.add(bgp.AddNATToRouterCommand(
                self.nb_api, router_name,
                type='dnat_and_snat',
                logical_ip='10.0.0.100',
                external_ip='172.24.4.10',
                external_ids={ovn_const.OVN_FIP_NET_ID: net_id},
            ))

        def arp_proxy_set():
            lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
            return ovn_const.LSP_OPTIONS_ARP_PROXY in lsp.options

        common_utils.wait_until_true(
            arp_proxy_set,
            timeout=10,
            exception=Exception("arp_proxy was not set after FIP creation"))

        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.assertEqual(
            '172.24.4.10',
            lsp.options.get(ovn_const.LSP_OPTIONS_ARP_PROXY))


def _unowned_api_cls(api_cls):
    """Return a subclass of api_cls that won't share an ovsdb_connection.

    ovsdbapp caches the connection on the API class, so two reconcilers in
    one process would otherwise end up sharing a connection -- and therefore
    a single OVSDB lock, which is exactly what these tests need two of.
    """
    cls = type('Unowned' + api_cls.__name__, (api_cls,), {})
    cls._ovsdb_connection = None
    return cls


class TestBGPReconcilerLockEvents(BGPReconcilerTestBase):
    """The full sync is driven by the OVSDB lock, not by worker startup.

    With several neutron servers every BGP worker connects at roughly the
    same time and exactly one of them wins bgp_topology_lock. A worker that
    tested has_lock once during startup could easily test before its grant
    arrived, or see a lock still held by a worker that is going away, and
    skip the initial sync -- leaving the topology unbuilt until something
    else happened to change. Hanging the sync off the lock_acquired hook
    instead means whichever worker holds the lock reconciles, whenever it
    gets it.
    """

    TIMEOUT = 30

    def _start_reconciler(self):
        rec = SyncRecordingReconciler()
        self.addCleanup(rec.stop)
        with mock.patch.object(bgp_ovn.OvnNbIdl, 'api_cls',
                               _unowned_api_cls(bgp_ovn.BgpOvnNbIdl)), \
            mock.patch.object(bgp_ovn.OvnSbIdl, 'api_cls',
                          _unowned_api_cls(bgp_ovn.BgpOvnSbIdl)):
            rec.start()
        return rec

    def _wait_for_lock_holder(self, *reconcilers):
        """Return the reconciler holding the lock and the one that isn't."""
        common_utils.wait_until_true(
            lambda: sum(r.nb_api.ovsdb_connection.idl.has_lock
                        for r in reconcilers) == 1,
            timeout=self.TIMEOUT,
            exception=AssertionError(
                "Exactly one reconciler should hold the BGP topology lock"))
        holder = [r for r in reconcilers
                  if r.nb_api.ovsdb_connection.idl.has_lock][0]
        standby = [r for r in reconcilers
                   if not r.nb_api.ovsdb_connection.idl.has_lock][0]
        return holder, standby

    def test_full_sync_runs_when_the_lock_is_acquired(self):
        for i in range(0, 3):
            self._create_chassis(
                f'chassis{i}', f'192.168.1.10{i}',
                bgp_bridges=self.chassis_bgp_networks)

        rec = self._start_reconciler()
        self.nb_api = rec.nb_api

        # Nothing here calls full_sync(): winning the lock is what triggers
        # it, so the topology appears on its own.
        self.assertTrue(rec.syncs.get(timeout=self.TIMEOUT))
        self.validate_topology(self._get_all_chassis_private())

    def test_only_the_lock_holder_syncs(self):
        self._create_chassis(
            'chassis0', '192.168.1.100',
            bgp_bridges=self.chassis_bgp_networks)

        holder, standby = self._wait_for_lock_holder(
            self._start_reconciler(), self._start_reconciler())
        self.nb_api = standby.nb_api

        self.assertTrue(holder.syncs.get(timeout=self.TIMEOUT))
        self.validate_topology(self._get_all_chassis_private())
        # The worker that lost the race must not reconcile in parallel.
        self.assertTrue(standby.syncs.empty())

    def test_standby_syncs_when_it_takes_over_the_lock(self):
        self._create_chassis(
            'chassis0', '192.168.1.100',
            bgp_bridges=self.chassis_bgp_networks)

        holder, standby = self._wait_for_lock_holder(
            self._start_reconciler(), self._start_reconciler())
        self.nb_api = standby.nb_api
        self.assertTrue(holder.syncs.get(timeout=self.TIMEOUT))

        # The standby started long ago and never had the lock, so a startup
        # has_lock check would have been its only chance to sync and it
        # would have failed it. Hand it the lock and it syncs anyway.
        holder.stop()
        self._create_chassis(
            'chassis1', '192.168.1.101',
            bgp_bridges=self.chassis_bgp_networks)

        self.assertTrue(standby.syncs.get(timeout=self.TIMEOUT))
        self._wait_for_topology(self._get_all_chassis_private())
