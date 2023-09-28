# Copyright 2020 Red Hat, Inc.
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
import datetime
import functools
from unittest import mock

import fixtures as og_fixtures
from neutron_lib.api.definitions import allowedaddresspairs
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_concurrency import processutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db as db_hash_ring
from neutron.plugins.ml2.drivers.ovn.agent import neutron_agent
from neutron.plugins.ml2.drivers.ovn.mech_driver import mech_driver
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.tests.functional import base
from neutron.tests.functional.resources.ovsdb import events as test_events
from neutron.tests.functional.resources.ovsdb import fixtures
from neutron.tests.functional.resources import process
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3


class WaitForDataPathBindingCreateEvent(event.WaitEvent):
    event_name = 'WaitForDataPathBindingCreateEvent'

    def __init__(self, net_name):
        table = 'Datapath_Binding'
        events = (self.ROW_CREATE,)
        conditions = (('external_ids', '=', {'name2': net_name}),)
        super(WaitForDataPathBindingCreateEvent, self).__init__(
            events, table, conditions, timeout=15)


class WaitForChassisPrivateCreateEvent(event.WaitEvent):
    event_name = 'WaitForChassisPrivateCreateEvent'

    def __init__(self, chassis_name, chassis_table):
        events = (self.ROW_CREATE,)
        conditions = (('name', '=', chassis_name),)
        super().__init__(events, chassis_table, conditions, timeout=15)


class DistributedLockTestEvent(event.WaitEvent):
    ONETIME = False
    COUNTER = 0

    def __init__(self):
        table = 'Logical_Switch_Port'
        events = (self.ROW_CREATE,)
        super(DistributedLockTestEvent, self).__init__(
            events, table, (), timeout=15)
        self.event_name = 'DistributedLockTestEvent'

    def run(self, event, row, old):
        self.COUNTER += 1
        self.event.set()


class GlobalTestEvent(DistributedLockTestEvent):
    GLOBAL = True


class TestNBDbMonitor(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestNBDbMonitor, self).setUp()
        self.chassis = self.add_fake_chassis('ovs-host1')
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, self.net, '20.0.0.1', '20.0.0.0/24',
                          ip_version=4)

    def create_port(self, device_owner='compute:nova', host='ovs-host1',
                    allowed_address_pairs=None):
        allowed_address_pairs = allowed_address_pairs or []
        arg_list = ('device_owner', 'device_id', portbindings.HOST_ID,
                    allowedaddresspairs.ADDRESS_PAIRS)
        host_arg = {'device_owner': device_owner,
                    'device_id': uuidutils.generate_uuid(),
                    portbindings.HOST_ID: host,
                    allowedaddresspairs.ADDRESS_PAIRS: allowed_address_pairs
                    }
        port_res = self._create_port(self.fmt, self.net['network']['id'],
                                     is_admin=True,
                                     arg_list=arg_list, **host_arg)
        port = self.deserialize(self.fmt, port_res)['port']
        return port

    def _create_fip(self, port, fip_address):
        e1 = self._make_network(self.fmt, 'e1', True, as_admin=True,
                                arg_list=('router:external',
                                          'provider:network_type',
                                          'provider:physical_network'),
                                **{'router:external': True,
                                   'provider:network_type': 'flat',
                                   'provider:physical_network': 'public'})
        res = self._create_subnet(self.fmt, e1['network']['id'],
                                  '100.0.0.0/24', gateway_ip='100.0.0.254',
                                  allocation_pools=[{'start': '100.0.0.2',
                                                     'end': '100.0.0.253'}],
                                  enable_dhcp=False)
        e1_s1 = self.deserialize(self.fmt, res)
        r1 = self.l3_plugin.create_router(
            self.context,
            {'router': {
                'name': 'r1', 'admin_state_up': True,
                'tenant_id': self._tenant_id,
                'external_gateway_info': {
                    'enable_snat': True,
                    'network_id': e1['network']['id'],
                    'external_fixed_ips': [
                        {'ip_address': '100.0.0.2',
                         'subnet_id': e1_s1['subnet']['id']}]}}})
        self.l3_plugin.add_router_interface(
            self.context, r1['id'],
            {'subnet_id': port['fixed_ips'][0]['subnet_id']})
        r1_f2 = self.l3_plugin.create_floatingip(
            self.context, {'floatingip': {
                'tenant_id': self._tenant_id,
                'floating_network_id': e1['network']['id'],
                'subnet_id': None,
                'floating_ip_address': fip_address,
                'port_id': port['id']}})
        return r1_f2

    def _check_mac_binding_exists(self, macb_id):
        cmd = ['ovsdb-client', 'transact',
               self.mech_driver.sb_ovn.connection_string]

        if self._ovsdb_protocol == 'ssl':
            cmd += ['-p', self.ovsdb_server_mgr.private_key, '-c',
                    self.ovsdb_server_mgr.certificate, '-C',
                    self.ovsdb_server_mgr.ca_cert]

        cmd += ['["OVN_Southbound", {"op": "select", "table": "MAC_Binding", '
                '"where": [["_uuid", "==", ["uuid", "%s"]]]}]' % macb_id]

        out, _ = processutils.execute(*cmd,
                                      log_errors=False)
        return str(macb_id) in out

    def test_floatingip_mac_bindings(self):
        """Check that MAC_Binding entries are cleared on FIP add/removal

        This test will:
        * Create a MAC_Binding entry for an IP address on the
        'network1' datapath.
        * Create a FIP with that same IP address on an external.
        network and associate it to a Neutron port on a private network.
        * Check that the MAC_Binding entry gets deleted.
        * Create a new MAC_Binding entry for the same IP address.
        * Delete the FIP.
        * Check that the MAC_Binding entry gets deleted.
        """
        net_name = 'network1'
        self.mech_driver.sb_ovn.idl.update_tables(
            ['MAC_Binding'], self.mech_driver.sb_schema_helper.schema_json)
        row_event = WaitForDataPathBindingCreateEvent(net_name)
        self.mech_driver.sb_ovn.idl.notify_handler.watch_event(row_event)
        self._make_network(self.fmt, net_name, True)
        self.assertTrue(row_event.wait())
        dp = self.sb_api.db_find(
            'Datapath_Binding',
            ('external_ids', '=', {'name2': net_name})).execute()
        macb_id = self.sb_api.db_create('MAC_Binding', datapath=dp[0]['_uuid'],
                                        ip='100.0.0.21').execute()
        port = self.create_port()

        # Ensure that the MAC_Binding entry gets deleted after creating a FIP
        fip = self._create_fip(port, '100.0.0.21')
        n_utils.wait_until_true(
            lambda: not self._check_mac_binding_exists(macb_id),
            timeout=15, sleep=1)

        # Now that the FIP is created, add a new MAC_Binding entry with the
        # same IP address
        macb_id = self.sb_api.db_create('MAC_Binding', datapath=dp[0]['_uuid'],
                                        ip='100.0.0.21').execute()

        # Ensure that the MAC_Binding entry gets deleted after deleting the FIP
        self.l3_plugin.delete_floatingip(self.context, fip['id'])
        n_utils.wait_until_true(
            lambda: not self._check_mac_binding_exists(macb_id),
            timeout=15, sleep=1)

    def _test_port_binding_and_status(self, port_id, action, status):
        # This function binds or unbinds port to chassis and
        # checks if port status matches with input status
        core_plugin = directory.get_plugin()
        self.sb_api.check_for_row_by_value_and_retry(
            'Port_Binding', 'logical_port', port_id)

        def check_port_status(status):
            port = core_plugin.get_ports(
                self.context, filters={'id': [port_id]})[0]
            return port['status'] == status
        if action == 'bind':
            self.sb_api.lsp_bind(port_id, self.chassis,
                                 may_exist=True).execute(check_error=True)
        else:
            self.sb_api.lsp_unbind(port_id).execute(check_error=True)
        n_utils.wait_until_true(lambda: check_port_status(status))

    def test_port_up_down_events(self):
        """Test the port up down events.

        This test case creates a port, binds the port to chassis,
        tests if the ovsdb monitor calls mech_driver to set port status
        to 'ACTIVE'. Then unbinds the port and checks if the port status
        is set to "DOWN'
        """
        port = self.create_port()
        self._test_port_binding_and_status(port['id'], 'bind', 'ACTIVE')
        self._test_port_binding_and_status(port['id'], 'unbind', 'DOWN')

    def _create_workers(self, row_event, worker_num):
        self.mech_driver.nb_ovn.idl.notify_handler.watch_event(row_event)
        worker_list = [self.mech_driver.nb_ovn]

        # Create 10 fake workers
        for _ in range(worker_num):
            node_uuid = uuidutils.generate_uuid()
            db_hash_ring.add_node(
                self.context, ovn_const.HASH_RING_ML2_GROUP, node_uuid)
            fake_driver = mock.MagicMock(
                node_uuid=node_uuid,
                hash_ring_group=ovn_const.HASH_RING_ML2_GROUP)
            _idl = ovsdb_monitor.OvnNbIdl.from_server(
                self.ovsdb_server_mgr.get_ovsdb_connection_path(),
                self.nb_api.schema_helper, fake_driver)
            worker = self.useFixture(
                fixtures.OVNIdlConnectionFixture(
                    idl=_idl, timeout=10)).connection
            worker.idl.notify_handler.watch_event(row_event)
            worker.start()
            worker_list.append(worker)

        # Refresh the hash rings just in case
        [worker.idl._hash_ring.refresh() for worker in worker_list]

        # Assert we have 11 active workers in the ring
        self.assertEqual(
            worker_num + 1,
            len(db_hash_ring.get_active_nodes(
                self.context,
                interval=ovn_const.HASH_RING_NODES_TIMEOUT,
                group_name=ovn_const.HASH_RING_ML2_GROUP)))

        return worker_list

    def test_distributed_lock(self):
        row_event = DistributedLockTestEvent()
        self._create_workers(row_event, worker_num=10)
        # Trigger the event
        self.create_port()

        # Wait for the event to complete
        self.assertTrue(row_event.wait())

        # Assert that only one worker handled the event
        self.assertEqual(1, row_event.COUNTER)

    def test_global_events(self):
        worker_num = 10
        distributed_event = DistributedLockTestEvent()
        global_event = GlobalTestEvent()
        worker_list = self._create_workers(distributed_event, worker_num)
        for worker in worker_list:
            worker.idl.notify_handler.watch_event(global_event)

        # This should generate one distributed even handled by a single worker
        # and one global event, that should be handled by all workers
        self.create_port()

        # Wait for the distributed event to complete
        self.assertTrue(distributed_event.wait())

        # Assert that only one worker handled the distributed event
        self.assertEqual(1, distributed_event.COUNTER)

        n_utils.wait_until_true(
            lambda: global_event.COUNTER == worker_num + 1,
            exception=Exception(
                "Fanout event didn't get handled expected %d times" %
                (worker_num + 1)))

    def _find_port_binding(self, port_id):
        cmd = self.sb_api.db_find_rows('Port_Binding',
                                       ('logical_port', '=', port_id))
        rows = cmd.execute(check_error=True)
        return rows[0] if rows else None

    def _set_port_binding_virtual_parent(self, port_id, parent_port_id):
        pb_port_parent = self.sb_api.db_find_rows(
            'Port_Binding', ('logical_port', '=', parent_port_id)).execute(
            check_error=True)[0]
        pb_port_vip = self.sb_api.db_find_rows(
            'Port_Binding', ('logical_port', '=', port_id)).execute(
            check_error=True)[0]
        self.sb_api.db_set(
            'Port_Binding', pb_port_vip.uuid,
            ('virtual_parent', pb_port_parent.uuid)).execute(check_error=True)

    def _check_port_binding_type(self, port_id, port_type):
        def is_port_binding_type(port_id, port_type):
            bp = self._find_port_binding(port_id)
            return port_type == bp.type

        check = functools.partial(is_port_binding_type, port_id, port_type)
        n_utils.wait_until_true(check, timeout=10)

    def _check_port_virtual_parents(self, port_id, vparents):
        def is_port_virtual_parents(port_id, vparents):
            bp = self._find_port_binding(port_id)
            return (vparents ==
                    bp.options.get(ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY))

        check = functools.partial(is_port_virtual_parents, port_id, vparents)
        n_utils.wait_until_true(check, timeout=10)

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       'update_virtual_port_host')
    def test_virtual_port_host_update(self, mock_update_vip_host):
        # NOTE: because we can't simulate traffic from a port, this check is
        # not done in this test. This test checks the VIP host is unset when
        # the port allowed address pairs are removed.
        vip = self.create_port(device_owner='', host='')
        vip_address = vip['fixed_ips'][0]['ip_address']
        allowed_address_pairs = [{'ip_address': vip_address}]
        port = self.create_port()
        self._check_port_binding_type(vip['id'], '')

        # 1) Set the allowed address pairs.
        data = {'port': {'allowed_address_pairs': allowed_address_pairs}}
        req = self.new_update_request('ports', data, port['id'])
        req.get_response(self.api)
        # This test checks that the VIP "Port_Binding" register gets the type
        # and the corresponding "virtual-parents".
        self._check_port_binding_type(vip['id'], ovn_const.LSP_TYPE_VIRTUAL)
        self._check_port_virtual_parents(vip['id'], port['id'])

        # 2) Unset the allowed address pairs.
        # Assign the VIP again and delete the virtual port.
        # Before unsetting the allowed address pairs, we first manually add
        # the Port_Binding.virtual_parent of the virtual port. That happens
        # when an ovn-controller detects traffic with the VIP and assign the
        # port hosting the VIP as virtual parent.
        self._set_port_binding_virtual_parent(vip['id'], port['id'])
        mock_update_vip_host.reset_mock()
        data = {'port': {'allowed_address_pairs': []}}
        req = self.new_update_request('ports', data, port['id'])
        req.get_response(self.api)
        self._check_port_binding_type(vip['id'], '')
        self._check_port_virtual_parents(vip['id'], None)
        n_utils.wait_until_true(lambda: mock_update_vip_host.called,
                                timeout=10)
        # The virtual port is no longer considered as virtual. The
        # "Port_Binding" register is deleted.
        mock_update_vip_host.assert_called_once_with(vip['id'], None)

        # 3) Set again the allowed address pairs.
        mock_update_vip_host.reset_mock()
        data = {'port': {'allowed_address_pairs': allowed_address_pairs}}
        req = self.new_update_request('ports', data, port['id'])
        req.get_response(self.api)
        # This test checks that the VIP "Port_Binding" register gets the type
        # and the corresponding "virtual-parents".
        self._check_port_binding_type(vip['id'], ovn_const.LSP_TYPE_VIRTUAL)
        self._check_port_virtual_parents(vip['id'], port['id'])
        mock_update_vip_host.reset_mock()
        self._delete('ports', vip['id'])
        n_utils.wait_until_true(lambda: mock_update_vip_host.called,
                                timeout=10)
        # The virtual port is deleted and so the associated "Port_Binding".
        # With OVN v22.03.3 sometimes 2 delete events are received with the
        # same arguments.
        # TODO(lajoskatona): check when new OVN version is out
        # if this behaviour is changed.
        mock_update_vip_host.assert_called_with(vip['id'], None)

    @mock.patch.object(mech_driver.OVNMechanismDriver,
                       'update_virtual_port_host')
    def test_non_virtual_port_no_host_update(self, mock_update_vip_host):
        # The ``PortBindingUpdateVirtualPortsEvent`` delete event should affect
        # only to virtual ports. This check is done for virtual ports in
        # ``test_virtual_port_host_update``.
        port = self.create_port()
        self._delete('ports', port['id'])
        # We actively wait for 5 seconds for the ``Port_Binding`` event to
        # arrive and be processed, but the port host must not be updated.
        self.assertRaises(n_utils.WaitTimeout, n_utils.wait_until_true,
                          lambda: mock_update_vip_host.called, timeout=5)


class TestNBDbMonitorOverTcp(TestNBDbMonitor):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestNBDbMonitorOverSsl(TestNBDbMonitor):
    def get_ovsdb_server_protocol(self):
        return 'ssl'


class TestSBDbMonitor(base.TestOVNFunctionalBase, test_l3.L3NatTestCaseMixin):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.chassis = self.add_fake_chassis('ovs-host1',
                                             enable_chassis_as_gw=True)
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        ext_mgr = test_l3.L3TestExtensionManager()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.handler = event.RowEventHandler()
        self.sb_api.idl.notify = self.handler.notify

    def _find_port_binding(self, port_type):
        rows = self.sb_api.db_find_rows(
            'Port_Binding', ('type', '=', port_type)).execute(check_error=True)
        return rows[0] if rows else None

    def test_router_port_binding(self):
        # This test will check the router GW port creation and binding.
        def check_ext_ids():
            pb = self._find_port_binding(ovn_const.OVN_CHASSIS_REDIRECT)
            _, lrp = list(
                self.nb_api.tables['Logical_Router_Port'].rows.data.items())[0]
            if pb.external_ids == {}:
                # The current version of OVN installed in FT CI could not have
                # [1]. In this case, the Port_Binding.external_ids value is an
                # empty dictionary.
                # [1]https://www.mail-archive.com/ovs-dev@openvswitch.org/
                #    msg62836.html
                return True
            return lrp.external_ids == pb.external_ids

        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, 'ext_net', True, as_admin=True,
                                     **kwargs)
        self._make_subnet(self.fmt, ext_net, '10.251.0.1', '10.251.0.0/24',
                          enable_dhcp=True)
        router = self._make_router(self.fmt, self._tenant_id)
        row_event = test_events.WaitForCreatePortBindingEventPerType()
        self.handler.watch_event(row_event)
        self._add_external_gateway_to_router(router['router']['id'],
                                             ext_net['network']['id'])
        self.assertTrue(row_event.wait())

        # Check SB pb.external_ids == NB lrp.external_ids
        port_binding = self._find_port_binding(ovn_const.OVN_CHASSIS_REDIRECT)
        self.sb_api.db_set('Port_Binding', port_binding.uuid,
                           ('up', True)).execute(check_error=True)
        try:
            n_utils.wait_until_true(check_ext_ids, timeout=5)
        except n_utils.WaitTimeout:
            pb = self._find_port_binding(ovn_const.OVN_CHASSIS_REDIRECT)
            _, lrp = list(
                self.nb_api.tables['Logical_Router_Port'].rows.data.items())[0]
            self.fail('pb.ext_ids: %s  --  lrp.ext_ids: %s' %
                      (pb.external_ids, lrp.external_ids))


class TestAgentMonitor(base.TestOVNFunctionalBase):
    FAKE_CHASSIS_HOST = 'fake-chassis-host'

    def setUp(self):
        super(TestAgentMonitor, self).setUp()
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        self.mock_ovsdb_idl = mock.Mock()
        self.handler = self.sb_api.idl.notify_handler
        self.mock_ovsdb_idl = mock.Mock()
        chassis_name = uuidutils.generate_uuid()
        row_event = WaitForChassisPrivateCreateEvent(
            chassis_name, self.mech_driver.agent_chassis_table)
        self.mech_driver.sb_ovn.idl.notify_handler.watch_event(row_event)
        self.chassis_name = self.add_fake_chassis(
            self.FAKE_CHASSIS_HOST, name=chassis_name,
            enable_chassis_as_gw=True)
        self.assertTrue(row_event.wait())
        n_utils.wait_until_true(
            lambda: len(list(neutron_agent.AgentCache())) == 1)

    def test_agent_change_controller(self):
        self.assertEqual(neutron_agent.ControllerGatewayAgent,
                type(neutron_agent.AgentCache().get(self.chassis_name)))
        self.sb_api.db_set('Chassis', self.chassis_name, ('other_config',
                {'ovn-cms-options': ''})).execute(check_error=True)
        n_utils.wait_until_true(lambda:
                neutron_agent.AgentCache().get(self.chassis_name).
                chassis.other_config['ovn-cms-options'] == '')
        self.assertEqual(neutron_agent.ControllerAgent,
                type(neutron_agent.AgentCache().get(self.chassis_name)))

    def test_agent_updated_at_use_nb_cfg_timestamp(self):
        def check_agent_ts():
            agent = neutron_agent.AgentCache().get(self.chassis_name)
            chassis_ts = self.sb_api.db_get(
                'Chassis_Private', self.chassis_name,
                'nb_cfg_timestamp').execute(check_error=True)
            updated_at = datetime.datetime.fromtimestamp(
                int(chassis_ts / 1000), datetime.timezone.utc)
            return agent.updated_at == updated_at

        if not self.sb_api.is_table_present('Chassis_Private'):
            self.skipTest('Ovn sb not support Chassis_Private')
        timestamp = timeutils.utcnow_ts()
        nb_cfg_timestamp = timestamp * 1000
        self.sb_api.db_set('Chassis_Private', self.chassis_name, (
            'nb_cfg_timestamp', nb_cfg_timestamp)).execute(check_error=True)
        # Also increment nb_cfg by 1 to trigger ChassisAgentWriteEvent which
        # is responsible to update AgentCache
        old_nb_cfg = self.sb_api.db_get('Chassis_Private', self.chassis_name,
            'nb_cfg').execute(check_error=True)
        self.sb_api.db_set('Chassis_Private', self.chassis_name, (
            'nb_cfg', old_nb_cfg + 1)).execute(check_error=True)
        try:
            n_utils.wait_until_true(check_agent_ts, timeout=5)
        except n_utils.WaitTimeout:
            agent = neutron_agent.AgentCache().get(self.chassis_name)
            chassis_ts = self.sb_api.db_get(
                'Chassis_Private', self.chassis_name,
                'nb_cfg_timestamp').execute(check_error=True)
            self.fail('Chassis timestamp: %s, agent updated_at: %s' %
                      (chassis_ts, str(agent.updated_at)))

    def test_agent_restart(self):
        def check_agent_up():
            agent = neutron_agent.AgentCache().get(self.chassis_name)
            return agent.alive

        def check_agent_down():
            return not check_agent_up()

        def check_nb_cfg_timestamp_is_not_null():
            agent = neutron_agent.AgentCache().get(self.chassis_name)
            return agent.updated_at != 0

        if not self.sb_api.is_table_present('Chassis_Private'):
            self.skipTest('Ovn sb not support Chassis_Private')

        # Set nb_cfg to some realistic value, so that the alive check can
        # actually work
        self.nb_api.db_set(
            'NB_Global', '.', ('nb_cfg', 1337)).execute(check_error=True)
        self.sb_api.db_set(
            'Chassis_Private', self.chassis_name, ('nb_cfg', 1337)
        ).execute(check_error=True)

        chassis_uuid = self.sb_api.db_get(
            'Chassis', self.chassis_name, 'uuid').execute(check_error=True)

        self.assertTrue(check_agent_up())
        n_utils.wait_until_true(check_nb_cfg_timestamp_is_not_null, timeout=5)

        # Lets start by shutting down the ovn-controller
        # (where it will remove the Chassis_Private table entry)
        self.sb_api.db_destroy(
            'Chassis_Private', self.chassis_name).execute(check_error=True)
        try:
            n_utils.wait_until_true(check_agent_down, timeout=5)
        except n_utils.WaitTimeout:
            self.fail('Agent did not go down after Chassis_Private removal')

        # Now the ovn-controller starts up again and has not yet synced with
        # the southbound database
        self.sb_api.db_create(
            'Chassis_Private', name=self.chassis_name,
            external_ids={}, chassis=chassis_uuid,
            nb_cfg_timestamp=0, nb_cfg=0
        ).execute(check_error=True)
        self.assertTrue(check_agent_down())

        # Now the ovn-controller has synced with the southbound database
        nb_cfg_timestamp = timeutils.utcnow_ts() * 1000
        with self.sb_api.transaction() as txn:
            txn.add(self.sb_api.db_set('Chassis_Private', self.chassis_name,
                                       ('nb_cfg_timestamp', nb_cfg_timestamp)))
            txn.add(self.sb_api.db_set('Chassis_Private', self.chassis_name,
                                       ('nb_cfg', 1337)))
        try:
            n_utils.wait_until_true(check_agent_up, timeout=5)
        except n_utils.WaitTimeout:
            self.fail('Agent did not go up after sync is done')
        self.assertTrue(check_nb_cfg_timestamp_is_not_null())


class TestOvnIdlProbeInterval(base.TestOVNFunctionalBase):
    def setUp(self):
        # We need an OvsdbServer that uses TCP because probe_interval is always
        # zero for unix socket connections, which is what the parent uses
        temp_dir = self.useFixture(og_fixtures.TempDir()).path
        install_share_path = self._get_install_share_path()
        mgr = self.useFixture(
            process.OvsdbServer(temp_dir, install_share_path,
                                ovn_nb_db=True, ovn_sb_db=True,
                                protocol='tcp'))
        connection = mgr.get_ovsdb_connection_path
        self.connections = {'OVN_Northbound': connection(),
                            'OVN_Southbound': connection(db_type='sb')}
        super().setUp()

    def test_ovsdb_probe_interval(self):
        klasses = {
            ovsdb_monitor.BaseOvnIdl: ('OVN_Northbound', {}),
            ovsdb_monitor.OvnNbIdl: ('OVN_Northbound',
                                     {'driver': self.mech_driver}),
            ovsdb_monitor.OvnSbIdl: ('OVN_Southbound',
                                     {'driver': self.mech_driver})}
        idls = [
            kls.from_server(
                self.connections[schema],
                idlutils.get_schema_helper(self.connections[schema], schema),
                **kwargs) for kls, (schema, kwargs) in klasses.items()]
        interval = ovn_conf.get_ovn_ovsdb_probe_interval()
        for idl in idls:
            self.assertEqual(interval, idl._session.reconnect.probe_interval)


class TestOvnIdlConnections(base.TestOVNFunctionalBase):
    def setUp(self):
        temp_dir = self.useFixture(og_fixtures.TempDir()).path
        install_share_path = self._get_install_share_path()
        mgr = self.useFixture(
            process.OvsdbServer(temp_dir, install_share_path,
                                ovn_nb_db=True, ovn_sb_db=True,
                                protocol='tcp'))
        connection = mgr.get_ovsdb_connection_path

        nb_conns = connection()
        sb_conns = connection(db_type='sb')
        # add fake address, idl support multiple addresses, as long as there
        # is an available address, it will run successfully.
        nb_conns += ',tcp:192.168.0.1:6641'
        sb_conns += ',tcp:192.168.0.1:6642'
        self.connections = {'OVN_Northbound': nb_conns,
                            'OVN_Southbound': sb_conns}
        super().setUp()

    def test_ovsdb_connections(self):
        klasses = {
            ovsdb_monitor.OvnNbIdl: ('OVN_Northbound',
                                     {'driver': self.mech_driver}),
            ovsdb_monitor.OvnSbIdl: ('OVN_Southbound',
                                     {'driver': self.mech_driver})}
        for kls, (schema, kwargs) in klasses.items():
            conns = self.connections[schema]
            idl = kls.from_server(
                conns,
                idlutils.get_schema_helper(conns, schema),
                **kwargs)
            self.assertEqual(set(idlutils.parse_connection(conns)),
                             set(idl._session.remotes))


class TestPortBindingChassisEvent(base.TestOVNFunctionalBase,
                                  test_l3.L3NatTestCaseMixin):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.chassis = self.add_fake_chassis('ovs-host1')
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        self.net = self._make_network(
            self.fmt, 'ext_net', True, as_admin=True, **kwargs)
        self._make_subnet(self.fmt, self.net, '20.0.10.1', '20.0.10.0/24')
        port_res = self._create_port(self.fmt, self.net['network']['id'])
        self.port = self.deserialize(self.fmt, port_res)['port']

        self.ext_api = test_extensions.setup_extensions_middleware(
            test_l3.L3TestExtensionManager())
        self.pb_event_match = mock.patch.object(
            self.sb_api.idl._portbinding_event, 'match_fn').start()

    def _check_pb_type(self, _type):
        def check_pb_type(_type):
            if len(self.pb_event_match.call_args_list) < 1:
                return False

            pb_row = self.pb_event_match.call_args_list[0].args[1]
            return _type == pb_row.type

        n_utils.wait_until_true(lambda: check_pb_type(_type), timeout=5)

    def test_pb_type_patch(self):
        router = self._make_router(self.fmt, self._tenant_id)
        self._add_external_gateway_to_router(router['router']['id'],
                                             self.net['network']['id'])
        self._check_pb_type('patch')

    def test_pb_type_empty(self):
        self.sb_api.lsp_bind(self.port['id'], self.chassis,
                             may_exist=True).execute(check_error=True)
        self._check_pb_type('')
