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

import sys

import mock

from neutron.extensions import portbindings
with mock.patch.dict(sys.modules,
                     {'networking_arista': mock.Mock(),
                      'networking_arista.ml2': mock.Mock(),
                      'networking_arista.common': mock.Mock()}):
    from neutron.plugins.ml2.drivers.arista import mechanism_arista
from neutron.tests.unit import testlib_api


class AristaDriverTestCase(testlib_api.SqlTestCase):
    """Main test cases for Arista Mechanism driver.

    Tests all mechanism driver APIs supported by Arista Driver. It invokes
    all the APIs as they would be invoked in real world scenarios and
    verifies the functionality.
    """
    def setUp(self):
        super(AristaDriverTestCase, self).setUp()
        self.fake_rpc = mock.MagicMock()
        mechanism_arista.db_lib = self.fake_rpc
        self.drv = mechanism_arista.AristaDriver(self.fake_rpc)

    def tearDown(self):
        super(AristaDriverTestCase, self).tearDown()
        self.drv.stop_synchronization_thread()

    def test_create_network_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        self.drv.create_network_precommit(network_context)

        expected_calls = [
            mock.call.remember_tenant(tenant_id),
            mock.call.remember_network(tenant_id,
                                       network_id,
                                       segmentation_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_create_network_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        network = network_context.current
        segments = network_context.network_segments
        net_dict = {
            'network_id': network['id'],
            'segmentation_id': segments[0]['segmentation_id'],
            'network_name': network['name'],
            'shared': network['shared']}

        self.drv.create_network_postcommit(network_context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.create_network(tenant_id, net_dict),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_network_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        self.drv.delete_network_precommit(network_context)

        expected_calls = [
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.forget_network(tenant_id, network_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_network_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        self.drv.delete_network_postcommit(network_context)
        expected_calls = [
            mock.call.delete_network(tenant_id, network_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_create_port_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        host_id = port_context.current['binding:host_id']
        port_id = port_context.current['id']
        self.drv.create_port_precommit(port_context)

        expected_calls = [
            mock.call.remember_tenant(tenant_id),
            mock.call.remember_vm(vm_id, host_id, port_id,
                                  network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_create_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.is_vm_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1

        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        port_id = port['id']
        port_name = port['name']

        self.drv.create_port_postcommit(port_context)

        expected_calls = [
            mock.call.is_vm_provisioned(device_id, host_id, port_id,
                                        network_id, tenant_id),
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

        # Now test the delete ports
    def test_delete_port_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        mechanism_arista.db_lib.is_vm_provisioned.return_value = True
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 0
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 0
        self.drv.delete_port_precommit(port_context)

        host_id = port_context.current['binding:host_id']
        port_id = port_context.current['id']
        expected_calls = [
            mock.call.is_vm_provisioned(vm_id, host_id, port_id,
                                        network_id, tenant_id),
            mock.call.forget_vm(vm_id, host_id, port_id,
                                network_id, tenant_id),
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_delete_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        port = port_context.current
        device_id = port['device_id']
        host_id = port['binding:host_id']
        port_id = port['id']

        self.drv.delete_port_postcommit(port_context)

        expected_calls = [
            mock.call.unplug_host_from_network(device_id, host_id, port_id,
                                               network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_precommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)

        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)
        host_id = port_context.current['binding:host_id']
        port_context.original['binding:host_id'] = 'ubuntu0'
        port_id = port_context.current['id']
        self.drv.update_port_precommit(port_context)

        expected_calls = [
            mock.call.update_vm_host(vm_id, host_id, port_id,
                                     network_id, tenant_id)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def test_update_port_postcommit(self):
        tenant_id = 'ten-1'
        network_id = 'net1-id'
        segmentation_id = 1001
        vm_id = 'vm1'

        network_context = self._get_network_context(tenant_id,
                                                    network_id,
                                                    segmentation_id,
                                                    False)
        port_context = self._get_port_context(tenant_id,
                                              network_id,
                                              vm_id,
                                              network_context)

        mechanism_arista.db_lib.is_vm_provisioned.return_value = True
        mechanism_arista.db_lib.is_network_provisioned.return_value = True
        mechanism_arista.db_lib.get_shared_network_owner_id.return_value = 1
        mechanism_arista.db_lib.get_segmentation_id.return_value = 1001
        mechanism_arista.db_lib.num_nets_provisioned.return_value = 1
        mechanism_arista.db_lib.num_vms_provisioned.return_value = 1

        port = port_context.current
        device_id = port['device_id']
        device_owner = port['device_owner']
        host_id = port['binding:host_id']
        orig_host_id = 'ubuntu0'
        port_context.original['binding:host_id'] = orig_host_id
        port_id = port['id']
        port_name = port['name']

        self.drv.update_port_postcommit(port_context)

        expected_calls = [
            mock.call.NeutronNets(),
            mock.call.get_segmentation_id(tenant_id, network_id),
            mock.call.is_vm_provisioned(device_id, host_id, port_id,
                                        network_id, tenant_id),
            mock.call.is_network_provisioned(tenant_id, network_id,
                                             segmentation_id),
            mock.call.is_network_provisioned(tenant_id, network_id),
            mock.call.unplug_host_from_network(device_id, orig_host_id,
                                               port_id, network_id, tenant_id),
            mock.call.num_nets_provisioned(tenant_id),
            mock.call.num_vms_provisioned(tenant_id),
            mock.call.plug_port_into_network(device_id, host_id, port_id,
                                             network_id, tenant_id,
                                             port_name, device_owner)
        ]

        mechanism_arista.db_lib.assert_has_calls(expected_calls)

    def _get_network_context(self, tenant_id, net_id, seg_id, shared):
        network = {'id': net_id,
                   'tenant_id': tenant_id,
                   'name': 'test-net',
                   'shared': shared}
        network_segments = [{'segmentation_id': seg_id,
                             'network_type': 'vlan'}]
        return FakeNetworkContext(network, network_segments, network)

    def _get_port_context(self, tenant_id, net_id, vm_id, network):
        port = {'device_id': vm_id,
                'device_owner': 'compute',
                'binding:host_id': 'ubuntu1',
                'name': 'test-port',
                'tenant_id': tenant_id,
                'id': 101,
                'network_id': net_id
                }
        return FakePortContext(port, dict(port), network)


class fake_keystone_info_class(object):
    """To generate fake Keystone Authentification token information

    Arista Driver expects Keystone auth info. This fake information
    is for testing only
    """
    auth_uri = 'abc://host:35357/v2.0/'
    identity_uri = 'abc://host:5000'
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
