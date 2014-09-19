# Copyright (c) 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock
from oslo.config import cfg

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers.arista import db
from neutron.plugins.ml2.drivers.arista import exceptions as arista_exc
from neutron.plugins.ml2.drivers.arista import mechanism_arista as arista
from neutron.tests import base
from neutron.tests.unit import testlib_api


def setup_arista_wrapper_config(value=''):
    cfg.CONF.keystone_authtoken = fake_keystone_info_class()
    cfg.CONF.set_override('eapi_host', value, "ml2_arista")
    cfg.CONF.set_override('eapi_username', value, "ml2_arista")
    cfg.CONF.set_override('sync_interval', 10, "ml2_arista")


def setup_valid_config():
    # Config is not valid if value is not set
    setup_arista_wrapper_config('value')


class AristaProvisionedVlansStorageTestCase(testlib_api.SqlTestCase):
    """Test storing and retriving functionality of Arista mechanism driver.

    Tests all methods of this class by invoking them separately as well
    as a group.
    """

    def test_tenant_is_remembered(self):
        tenant_id = 'test'

        db.remember_tenant(tenant_id)
        net_provisioned = db.is_tenant_provisioned(tenant_id)
        self.assertTrue(net_provisioned, 'Tenant must be provisioned')

    def test_tenant_is_removed(self):
        tenant_id = 'test'

        db.remember_tenant(tenant_id)
        db.forget_tenant(tenant_id)
        net_provisioned = db.is_tenant_provisioned(tenant_id)
        self.assertFalse(net_provisioned, 'The Tenant should be deleted')

    def test_network_is_remembered(self):
        tenant_id = 'test'
        network_id = '123'
        segmentation_id = 456

        db.remember_network(tenant_id, network_id, segmentation_id)
        net_provisioned = db.is_network_provisioned(tenant_id,
                                                    network_id)
        self.assertTrue(net_provisioned, 'Network must be provisioned')

    def test_network_is_removed(self):
        tenant_id = 'test'
        network_id = '123'

        db.remember_network(tenant_id, network_id, '123')
        db.forget_network(tenant_id, network_id)
        net_provisioned = db.is_network_provisioned(tenant_id, network_id)
        self.assertFalse(net_provisioned, 'The network should be deleted')

    def test_vm_is_remembered(self):
        vm_id = 'VM-1'
        tenant_id = 'test'
        network_id = '123'
        port_id = 456
        host_id = 'ubuntu1'

        db.remember_vm(vm_id, host_id, port_id, network_id, tenant_id)
        vm_provisioned = db.is_vm_provisioned(vm_id, host_id, port_id,
                                              network_id, tenant_id)
        self.assertTrue(vm_provisioned, 'VM must be provisioned')

    def test_vm_is_removed(self):
        vm_id = 'VM-1'
        tenant_id = 'test'
        network_id = '123'
        port_id = 456
        host_id = 'ubuntu1'

        db.remember_vm(vm_id, host_id, port_id, network_id, tenant_id)
        db.forget_vm(vm_id, host_id, port_id, network_id, tenant_id)
        vm_provisioned = db.is_vm_provisioned(vm_id, host_id, port_id,
                                              network_id, tenant_id)
        self.assertFalse(vm_provisioned, 'The vm should be deleted')

    def test_remembers_multiple_networks(self):
        tenant_id = 'test'
        expected_num_nets = 100
        nets = ['id%s' % n for n in range(expected_num_nets)]
        for net_id in nets:
            db.remember_network(tenant_id, net_id, 123)

        num_nets_provisioned = db.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_removes_all_networks(self):
        tenant_id = 'test'
        num_nets = 100
        old_nets = db.num_nets_provisioned(tenant_id)
        nets = ['id_%s' % n for n in range(num_nets)]
        for net_id in nets:
            db.remember_network(tenant_id, net_id, 123)
        for net_id in nets:
            db.forget_network(tenant_id, net_id)

        num_nets_provisioned = db.num_nets_provisioned(tenant_id)
        expected = old_nets
        self.assertEqual(expected, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected, num_nets_provisioned))

    def test_remembers_multiple_tenants(self):
        expected_num_tenants = 100
        tenants = ['id%s' % n for n in range(expected_num_tenants)]
        for tenant_id in tenants:
            db.remember_tenant(tenant_id)

        num_tenants_provisioned = db.num_provisioned_tenants()
        self.assertEqual(expected_num_tenants, num_tenants_provisioned,
                         'There should be %d tenants, not %d' %
                         (expected_num_tenants, num_tenants_provisioned))

    def test_removes_multiple_tenants(self):
        num_tenants = 100
        tenants = ['id%s' % n for n in range(num_tenants)]
        for tenant_id in tenants:
            db.remember_tenant(tenant_id)
        for tenant_id in tenants:
            db.forget_tenant(tenant_id)

        num_tenants_provisioned = db.num_provisioned_tenants()
        expected = 0
        self.assertEqual(expected, num_tenants_provisioned,
                         'There should be %d tenants, not %d' %
                         (expected, num_tenants_provisioned))

    def test_num_vm_is_valid(self):
        tenant_id = 'test'
        network_id = '123'
        port_id = 456
        host_id = 'ubuntu1'

        vm_to_remember = ['vm1', 'vm2', 'vm3']
        vm_to_forget = ['vm2', 'vm1']

        for vm in vm_to_remember:
            db.remember_vm(vm, host_id, port_id, network_id, tenant_id)
        for vm in vm_to_forget:
            db.forget_vm(vm, host_id, port_id, network_id, tenant_id)

        num_vms = len(db.get_vms(tenant_id))
        expected = len(vm_to_remember) - len(vm_to_forget)

        self.assertEqual(expected, num_vms,
                         'There should be %d records, '
                         'got %d records' % (expected, num_vms))
        # clean up afterwards
        db.forget_vm('vm3', host_id, port_id, network_id, tenant_id)

    def test_get_network_list_returns_eos_compatible_data(self):
        tenant = u'test-1'
        segm_type = 'vlan'
        network_id = u'123'
        network2_id = u'1234'
        vlan_id = 123
        vlan2_id = 1234
        expected_eos_net_list = {network_id: {u'networkId': network_id,
                                              u'segmentationTypeId': vlan_id,
                                              u'segmentationType': segm_type},
                                 network2_id: {u'networkId': network2_id,
                                               u'segmentationTypeId': vlan2_id,
                                               u'segmentationType': segm_type}}

        db.remember_network(tenant, network_id, vlan_id)
        db.remember_network(tenant, network2_id, vlan2_id)

        net_list = db.get_networks(tenant)
        self.assertNotEqual(net_list != expected_eos_net_list, ('%s != %s' %
                            (net_list, expected_eos_net_list)))


class PositiveRPCWrapperValidConfigTestCase(base.BaseTestCase):
    """Test cases to test the RPC between Arista Driver and EOS.

    Tests all methods used to send commands between Arista Driver and EOS
    """

    def setUp(self):
        super(PositiveRPCWrapperValidConfigTestCase, self).setUp()
        setup_valid_config()
        self.drv = arista.AristaRPCWrapper()
        self.region = 'RegionOne'
        self.drv._server = mock.MagicMock()

    def _get_exit_mode_cmds(self, modes):
        return ['exit'] * len(modes)

    def test_no_exception_on_correct_configuration(self):
        self.assertIsNotNone(self.drv)

    def test_sync_start(self):
        self.drv.sync_start()
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'sync start',
                'exit', 'exit', 'exit']

        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_sync_end(self):
        self.drv.sync_end()
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'sync end',
                'exit', 'exit', 'exit']

        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_plug_host_into_network(self):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        port_name = '123-port'

        self.drv.plug_host_into_network(vm_id, host, port_id,
                                        network_id, tenant_id, port_name)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'vm id vm-1 hostid host',
                'port id 123 name "123-port" network-id net-id',
                'exit', 'exit', 'exit', 'exit', 'exit']

        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_plug_dhcp_port_into_network(self):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        port_name = '123-port'

        self.drv.plug_dhcp_port_into_network(vm_id, host, port_id,
                                             network_id, tenant_id, port_name)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id',
                'dhcp id vm-1 hostid host port-id 123 name "123-port"',
                'exit', 'exit', 'exit', 'exit']

        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_unplug_host_from_network(self):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'
        self.drv.unplug_host_from_network(vm_id, host, port_id,
                                          network_id, tenant_id)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'vm id vm-1 hostid host',
                'no port id 123',
                'exit', 'exit', 'exit', 'exit', 'exit']
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_unplug_dhcp_port_from_network(self):
        tenant_id = 'ten-1'
        vm_id = 'vm-1'
        port_id = 123
        network_id = 'net-id'
        host = 'host'

        self.drv.unplug_dhcp_port_from_network(vm_id, host, port_id,
                                               network_id, tenant_id)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id',
                'no dhcp id vm-1 port-id 123',
                'exit', 'exit', 'exit', 'exit']

        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_create_network(self):
        tenant_id = 'ten-1'
        network = {
            'network_id': 'net-id',
            'network_name': 'net-name',
            'segmentation_id': 123}
        self.drv.create_network(tenant_id, network)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'network id net-id name "net-name"',
                'segment 1 type vlan id 123',
                'exit', 'exit', 'exit', 'exit', 'exit', 'exit']
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_create_network_bulk(self):
        tenant_id = 'ten-2'
        num_networks = 10
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segmentation_id': net_id} for net_id in range(1, num_networks)
        ]

        self.drv.create_network_bulk(tenant_id, networks)
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-2']
        for net_id in range(1, num_networks):
            cmds.append('network id net-id-%d name "net-name-%d"' %
                        (net_id, net_id))
            cmds.append('segment 1 type vlan id %d' % net_id)

        cmds.extend(self._get_exit_mode_cmds(['tenant', 'region', 'openstack',
                                              'cvx', 'configure', 'enable']))
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_network(self):
        tenant_id = 'ten-1'
        network_id = 'net-id'
        self.drv.delete_network(tenant_id, network_id)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'no network id net-id',
                'exit', 'exit', 'exit', 'exit', 'exit']
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_network_bulk(self):
        tenant_id = 'ten-2'
        num_networks = 10
        networks = [{
            'network_id': 'net-id-%d' % net_id,
            'network_name': 'net-name-%d' % net_id,
            'segmentation_id': net_id} for net_id in range(1, num_networks)
        ]

        networks = ['net-id-%d' % net_id for net_id in range(1, num_networks)]
        self.drv.delete_network_bulk(tenant_id, networks)
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-2']
        for net_id in range(1, num_networks):
            cmds.append('no network id net-id-%d' % net_id)

        cmds.extend(self._get_exit_mode_cmds(['tenant', 'region', 'openstack',
                                              'cvx', 'configure']))
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_vm(self):
        tenant_id = 'ten-1'
        vm_id = 'vm-id'
        self.drv.delete_vm(tenant_id, vm_id)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne',
                'tenant ten-1', 'no vm id vm-id',
                'exit', 'exit', 'exit', 'exit', 'exit']
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_vm_bulk(self):
        tenant_id = 'ten-2'
        num_vms = 10
        vm_ids = ['vm-id-%d' % vm_id for vm_id in range(1, num_vms)]
        self.drv.delete_vm_bulk(tenant_id, vm_ids)

        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-2']

        for vm_id in range(1, num_vms):
            cmds.append('no vm id vm-id-%d' % vm_id)

        cmds.extend(self._get_exit_mode_cmds(['tenant', 'region', 'openstack',
                                              'cvx', 'configure']))
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_create_vm_port_bulk(self):
        tenant_id = 'ten-3'
        num_vms = 10
        num_ports_per_vm = 2

        vms = dict(
            ('vm-id-%d' % vm_id, {
                'vmId': 'vm-id-%d' % vm_id,
                'host': 'host_%d' % vm_id,
            }
            ) for vm_id in range(1, num_vms)
        )

        devices = [n_const.DEVICE_OWNER_DHCP, 'compute']
        vm_port_list = []

        net_count = 1
        for vm_id in range(1, num_vms):
            for port_id in range(1, num_ports_per_vm):
                port = {
                    'id': 'port-id-%d-%d' % (vm_id, port_id),
                    'device_id': 'vm-id-%d' % vm_id,
                    'device_owner': devices[(vm_id + port_id) % 2],
                    'network_id': 'network-id-%d' % net_count,
                    'name': 'port-%d-%d' % (vm_id, port_id)
                }
                vm_port_list.append(port)
                net_count += 1

        self.drv.create_vm_port_bulk(tenant_id, vm_port_list, vms)
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne',
                'tenant ten-3']

        net_count = 1
        for vm_count in range(1, num_vms):
            host = 'host_%s' % vm_count
            for port_count in range(1, num_ports_per_vm):
                vm_id = 'vm-id-%d' % vm_count
                device_owner = devices[(vm_count + port_count) % 2]
                port_name = '"port-%d-%d"' % (vm_count, port_count)
                network_id = 'network-id-%d' % net_count
                port_id = 'port-id-%d-%d' % (vm_count, port_count)
                if device_owner == 'network:dhcp':
                    cmds.append('network id %s' % network_id)
                    cmds.append('dhcp id %s hostid %s port-id %s name %s' % (
                                vm_id, host, port_id, port_name))
                elif device_owner == 'compute':
                    cmds.append('vm id %s hostid %s' % (vm_id, host))
                    cmds.append('port id %s name %s network-id %s' % (
                                port_id, port_name, network_id))
                net_count += 1

        cmds.extend(self._get_exit_mode_cmds(['tenant', 'region',
                                              'openstack', 'cvx']))
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_tenant(self):
        tenant_id = 'ten-1'
        self.drv.delete_tenant(tenant_id)
        cmds = ['enable', 'configure', 'cvx', 'service openstack',
                'region RegionOne', 'no tenant ten-1',
                'exit', 'exit', 'exit', 'exit']
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_delete_tenant_bulk(self):
        num_tenants = 10
        tenant_list = ['ten-%d' % t_id for t_id in range(1, num_tenants)]
        self.drv.delete_tenant_bulk(tenant_list)
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region RegionOne']
        for ten_id in range(1, num_tenants):
            cmds.append('no tenant ten-%d' % ten_id)

        cmds.extend(self._get_exit_mode_cmds(['region', 'openstack',
                                              'cvx', 'configure']))
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_get_network_info_returns_none_when_no_such_net(self):
        expected = []
        self.drv.get_tenants = mock.MagicMock()
        self.drv.get_tenants.return_value = []

        net_info = self.drv.get_tenants()

        self.drv.get_tenants.assert_called_once_with()
        self.assertEqual(net_info, expected, ('Network info must be "None"'
                                              'for unknown network'))

    def test_get_network_info_returns_info_for_available_net(self):
        valid_network_id = '12345'
        valid_net_info = {'network_id': valid_network_id,
                          'some_info': 'net info'}
        known_nets = valid_net_info

        self.drv.get_tenants = mock.MagicMock()
        self.drv.get_tenants.return_value = known_nets

        net_info = self.drv.get_tenants()
        self.assertEqual(net_info, valid_net_info,
                         ('Must return network info for a valid net'))

    def test_check_cli_commands(self):
        self.drv.check_cli_commands()
        cmds = ['show openstack config region RegionOne timestamp']
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)

    def test_register_with_eos(self):
        self.drv.register_with_eos()
        auth = fake_keystone_info_class()
        keystone_url = '%s://%s:%s/v2.0/' % (auth.auth_protocol,
                                             auth.auth_host,
                                             auth.auth_port)
        auth_cmd = 'auth url %s user %s password %s tenant %s' % (keystone_url,
                    auth.admin_user,
                    auth.admin_password,
                    auth.admin_tenant_name)
        cmds = ['enable',
                'configure',
                'cvx',
                'service openstack',
                'region %s' % self.region,
                auth_cmd,
                'sync interval %d' % cfg.CONF.ml2_arista.sync_interval,
                'exit',
                'exit',
                'exit',
                ]
        self.drv._server.runCmds.assert_called_once_with(version=1, cmds=cmds)


class AristaRPCWrapperInvalidConfigTestCase(base.BaseTestCase):
    """Negative test cases to test the Arista Driver configuration."""

    def setUp(self):
        super(AristaRPCWrapperInvalidConfigTestCase, self).setUp()
        self.setup_invalid_config()  # Invalid config, required options not set

    def setup_invalid_config(self):
        setup_arista_wrapper_config('')

    def test_raises_exception_on_wrong_configuration(self):
        self.assertRaises(arista_exc.AristaConfigError,
                          arista.AristaRPCWrapper)


class NegativeRPCWrapperTestCase(base.BaseTestCase):
    """Negative test cases to test the RPC between Arista Driver and EOS."""

    def setUp(self):
        super(NegativeRPCWrapperTestCase, self).setUp()
        setup_valid_config()

    def test_exception_is_raised_on_json_server_error(self):
        drv = arista.AristaRPCWrapper()

        drv._server = mock.MagicMock()
        drv._server.runCmds.side_effect = Exception('server error')
        self.assertRaises(arista_exc.AristaRpcError, drv.get_tenants)


class RealNetStorageAristaDriverTestCase(testlib_api.SqlTestCase):
    """Main test cases for Arista Mechanism driver.

    Tests all mechanism driver APIs supported by Arista Driver. It invokes
    all the APIs as they would be invoked in real world scenarios and
    verifies the functionality.
    """
    def setUp(self):
        super(RealNetStorageAristaDriverTestCase, self).setUp()
        self.fake_rpc = mock.MagicMock()
        self.drv = arista.AristaDriver(self.fake_rpc)

    def tearDown(self):
        super(RealNetStorageAristaDriverTestCase, self).tearDown()
        self.drv.stop_synchronization_thread()

    def test_create_and_delete_network(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id)
        self.drv.create_network_precommit(network_context)
        net_provisioned = db.is_network_provisioned(tenant_id, network_id)
        self.assertTrue(net_provisioned, 'The network should be created')

        expected_num_nets = 1
        num_nets_provisioned = db.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

        #Now test the delete network
        self.drv.delete_network_precommit(network_context)
        net_provisioned = db.is_network_provisioned(tenant_id, network_id)
        self.assertFalse(net_provisioned, 'The network should be created')

        expected_num_nets = 0
        num_nets_provisioned = db.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_create_and_delete_multiple_networks(self):
        tenant_id = 'ten-1'
        expected_num_nets = 100
        segmentation_id = 1001
        nets = ['id%s' % n for n in range(expected_num_nets)]
        for net_id in nets:
            network_context = self._get_network_context(tenant_id,
                                                        net_id,
                                                        segmentation_id)
            self.drv.create_network_precommit(network_context)

        num_nets_provisioned = db.num_nets_provisioned(tenant_id)
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

        #now test the delete networks
        for net_id in nets:
            network_context = self._get_network_context(tenant_id,
                                                        net_id,
                                                        segmentation_id)
            self.drv.delete_network_precommit(network_context)

        num_nets_provisioned = db.num_nets_provisioned(tenant_id)
        expected_num_nets = 0
        self.assertEqual(expected_num_nets, num_nets_provisioned,
                         'There should be %d nets, not %d' %
                         (expected_num_nets, num_nets_provisioned))

    def test_create_and_delete_ports(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vms = ['vm1', 'vm2', 'vm3']

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id)
        self.drv.create_network_precommit(network_context)

        for vm_id in vms:
            port_context = self._get_port_context(tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context)
            self.drv.create_port_precommit(port_context)

        vm_list = db.get_vms(tenant_id)
        provisioned_vms = len(vm_list)
        expected_vms = len(vms)
        self.assertEqual(expected_vms, provisioned_vms,
                         'There should be %d '
                         'hosts, not %d' % (expected_vms, provisioned_vms))

        # Now test the delete ports
        for vm_id in vms:
            port_context = self._get_port_context(tenant_id,
                                                  network_id,
                                                  vm_id,
                                                  network_context)
            self.drv.delete_port_precommit(port_context)

        vm_list = db.get_vms(tenant_id)
        provisioned_vms = len(vm_list)
        expected_vms = 0
        self.assertEqual(expected_vms, provisioned_vms,
                         'There should be %d '
                         'VMs, not %d' % (expected_vms, provisioned_vms))

    def _get_network_context(self, tenant_id, net_id, seg_id):
        network = {'id': net_id,
                   'tenant_id': tenant_id}
        network_segments = [{'segmentation_id': seg_id}]
        return FakeNetworkContext(network, network_segments, network)

    def _get_port_context(self, tenant_id, net_id, vm_id, network):
        port = {'device_id': vm_id,
                'device_owner': 'compute',
                'binding:host_id': 'ubuntu1',
                'tenant_id': tenant_id,
                'id': 101,
                'network_id': net_id
                }
        return FakePortContext(port, port, network)


class fake_keystone_info_class(object):
    """To generate fake Keystone Authentification token information

    Arista Driver expects Keystone auth info. This fake information
    is for testing only
    """
    auth_protocol = 'abc'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    admin_password = 'fun'
    admin_tenant_name = 'tenant_name'


class FakeNetworkContext(object):
    """To generate network context for testing purposes only."""

    def __init__(self, network, segments=None, original_network=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, original_port, network):
        self._port = port
        self._original_port = original_port
        self._network_context = network

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def network(self):
        return self._network_context

    @property
    def host(self):
        return self._port.get(portbindings.HOST_ID)

    @property
    def original_host(self):
        return self._original_port.get(portbindings.HOST_ID)
