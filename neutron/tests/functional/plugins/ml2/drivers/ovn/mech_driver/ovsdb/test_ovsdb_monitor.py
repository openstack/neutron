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

import mock

import fixtures as og_fixtures
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_hash_ring_db as db_hash_ring
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor
from neutron.tests.functional import base
from neutron.tests.functional.resources.ovsdb import fixtures
from neutron.tests.functional.resources import process
from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from ovsdbapp.backend.ovs_idl import event


class WaitForMACBindingDeleteEvent(event.WaitEvent):
    event_name = 'WaitForMACBindingDeleteEvent'

    def __init__(self, entry):
        table = 'MAC_Binding'
        events = (self.ROW_DELETE,)
        conditions = (('_uuid', '=', entry),)
        super(WaitForMACBindingDeleteEvent, self).__init__(
            events, table, conditions, timeout=15)


class WaitForDataPathBindingCreateEvent(event.WaitEvent):
    event_name = 'WaitForDataPathBindingCreateEvent'

    def __init__(self, net_name):
        table = 'Datapath_Binding'
        events = (self.ROW_CREATE,)
        conditions = (('external_ids', '=', {'name2': net_name}),)
        super(WaitForDataPathBindingCreateEvent, self).__init__(
            events, table, conditions, timeout=15)


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


class TestNBDbMonitor(base.TestOVNFunctionalBase):

    def setUp(self):
        super(TestNBDbMonitor, self).setUp()
        self.chassis = self.add_fake_chassis('ovs-host1')
        self.l3_plugin = directory.get_plugin(plugin_constants.L3)

    def create_port(self):
        net = self._make_network(self.fmt, 'net1', True)
        self._make_subnet(self.fmt, net, '20.0.0.1',
                          '20.0.0.0/24', ip_version=4)
        arg_list = ('device_owner', 'device_id', portbindings.HOST_ID)
        host_arg = {'device_owner': 'compute:nova',
                    'device_id': uuidutils.generate_uuid(),
                    portbindings.HOST_ID: 'ovs-host1'}
        port_res = self._create_port(self.fmt, net['network']['id'],
                                     arg_list=arg_list, **host_arg)
        port = self.deserialize(self.fmt, port_res)['port']
        return port

    def _create_fip(self, port, fip_address):
        e1 = self._make_network(self.fmt, 'e1', True,
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
        row_event = WaitForDataPathBindingCreateEvent(net_name)
        self.mech_driver._sb_ovn.idl.notify_handler.watch_event(row_event)
        self._make_network(self.fmt, net_name, True)
        self.assertTrue(row_event.wait())
        dp = self.sb_api.db_find(
            'Datapath_Binding',
            ('external_ids', '=', {'name2': net_name})).execute()
        macb_id = self.sb_api.db_create('MAC_Binding', datapath=dp[0]['_uuid'],
                                        ip='100.0.0.21').execute()
        port = self.create_port()

        # Ensure that the MAC_Binding entry gets deleted after creating a FIP
        row_event = WaitForMACBindingDeleteEvent(macb_id)
        self.mech_driver._sb_ovn.idl.notify_handler.watch_event(row_event)
        fip = self._create_fip(port, '100.0.0.21')
        self.assertTrue(row_event.wait())

        # Now that the FIP is created, add a new MAC_Binding entry with the
        # same IP address

        macb_id = self.sb_api.db_create('MAC_Binding', datapath=dp[0]['_uuid'],
                                        ip='100.0.0.21').execute()

        # Ensure that the MAC_Binding entry gets deleted after deleting the FIP
        row_event = WaitForMACBindingDeleteEvent(macb_id)
        self.mech_driver._sb_ovn.idl.notify_handler.watch_event(row_event)
        self.l3_plugin.delete_floatingip(self.context, fip['id'])
        self.assertTrue(row_event.wait())

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

    def test_distributed_lock(self):
        api_workers = 11
        cfg.CONF.set_override('api_workers', api_workers)
        row_event = DistributedLockTestEvent()
        self.mech_driver._nb_ovn.idl.notify_handler.watch_event(row_event)
        worker_list = [self.mech_driver._nb_ovn, ]

        # Create 10 fake workers
        for _ in range(api_workers - len(worker_list)):
            node_uuid = uuidutils.generate_uuid()
            db_hash_ring.add_node(
                self.context, ovn_const.HASH_RING_ML2_GROUP, node_uuid)
            fake_driver = mock.MagicMock(
                node_uuid=node_uuid,
                hash_ring_group=ovn_const.HASH_RING_ML2_GROUP)
            _idl = ovsdb_monitor.OvnNbIdl.from_server(
                self.ovsdb_server_mgr.get_ovsdb_connection_path(),
                'OVN_Northbound', fake_driver)
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
            11, len(db_hash_ring.get_active_nodes(
                    self.context,
                    interval=ovn_const.HASH_RING_NODES_TIMEOUT,
                    group_name=ovn_const.HASH_RING_ML2_GROUP)))

        # Trigger the event
        self.create_port()

        # Wait for the event to complete
        self.assertTrue(row_event.wait())

        # Assert that only one worker handled the event
        self.assertEqual(1, row_event.COUNTER)


class TestNBDbMonitorOverTcp(TestNBDbMonitor):
    def get_ovsdb_server_protocol(self):
        return 'tcp'


class TestNBDbMonitorOverSsl(TestNBDbMonitor):
    def get_ovsdb_server_protocol(self):
        return 'ssl'


class TestOvnIdlProbeInterval(base.TestOVNFunctionalBase):
    def setUp(self):
        # skip parent setUp, we don't need it, but we do need grandparent
        # pylint: disable=bad-super-call
        super(base.TestOVNFunctionalBase, self).setUp()
        mm = directory.get_plugin().mechanism_manager
        self.mech_driver = mm.mech_drivers['ovn'].obj
        self.temp_dir = self.useFixture(og_fixtures.TempDir()).path
        install_share_path = self._get_install_share_path()
        self.mgr = self.useFixture(
            process.OvsdbServer(self.temp_dir, install_share_path,
                                ovn_nb_db=True, ovn_sb_db=True,
                                protocol='tcp'))
        connection = self.mgr.get_ovsdb_connection_path
        self.connections = {'OVN_Northbound': connection(),
                            'OVN_Southbound': connection(db_type='sb')}

    def test_ovsdb_probe_interval(self):
        klasses = {
            ovsdb_monitor.BaseOvnIdl: ('OVN_Northbound', {}),
            ovsdb_monitor.OvnNbIdl: ('OVN_Northbound',
                                     {'driver': self.mech_driver}),
            ovsdb_monitor.OvnSbIdl: ('OVN_Southbound',
                                     {'driver': self.mech_driver})}
        idls = [kls.from_server(self.connections[schema], schema, **kwargs)
                for kls, (schema, kwargs) in klasses.items()]
        interval = ovn_conf.get_ovn_ovsdb_probe_interval()
        for idl in idls:
            self.assertEqual(interval, idl._session.reconnect.probe_interval)
