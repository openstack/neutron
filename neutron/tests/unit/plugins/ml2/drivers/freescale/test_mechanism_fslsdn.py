# Copyright (c) 2014 Freescale, Inc.
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
from oslo_config import cfg

from neutron.extensions import portbindings
from neutron.plugins.ml2.drivers.freescale import mechanism_fslsdn
from neutron.tests import base
from neutron.tests.unit.plugins.ml2 import test_plugin


"""Unit testing for Freescale SDN mechanism driver."""


class TestFslSdnMechDriverV2(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['fslsdn']

    """Testing mechanism driver with ML2 plugin."""

    def setUp(self):

        def mocked_fslsdn_init(self):
            # Mock CRD client, since it requires CRD service running.
            self._crdclient = mock.Mock()

        with mock.patch.object(mechanism_fslsdn.FslsdnMechanismDriver,
                               'initialize', new=mocked_fslsdn_init):
            super(TestFslSdnMechDriverV2, self).setUp()


class TestFslSdnMechDriverNetworksV2(test_plugin.TestMl2NetworksV2,
                                     TestFslSdnMechDriverV2):
    pass


class TestFslSdnMechDriverPortsV2(test_plugin.TestMl2PortsV2,
                                  TestFslSdnMechDriverV2):
    VIF_TYPE = portbindings.VIF_TYPE_OVS
    CAP_PORT_FILTER = True


class TestFslSdnMechDriverSubnetsV2(test_plugin.TestMl2SubnetsV2,
                                    TestFslSdnMechDriverV2):
    pass


class TestFslSdnMechanismDriver(base.BaseTestCase):

    """Testing FSL SDN Mechanism driver."""

    def setUp(self):
        super(TestFslSdnMechanismDriver, self).setUp()
        cfg.CONF.set_override('mechanism_drivers', ['fslsdn'], 'ml2')
        self.driver = mechanism_fslsdn.FslsdnMechanismDriver()
        self.driver.initialize()
        self.client = self.driver._crdclient = mock.Mock()

    def test_create_update_delete_network_postcommit(self):
        """Testing create/update/delete network postcommit operations."""

        tenant_id = 'test'
        network_id = '123'
        segmentation_id = 456
        expected_seg = [{'segmentation_id': segmentation_id}]
        expected_crd_network = {'network':
                                {'network_id': network_id,
                                 'tenant_id': tenant_id,
                                 'name': 'FakeNetwork',
                                 'status': 'ACTIVE',
                                 'admin_state_up': True,
                                 'segments': expected_seg}}
        network_context = self._get_network_context(tenant_id, network_id,
                                                    segmentation_id)
        network = network_context.current
        segments = network_context.network_segments
        net_id = network['id']
        req = self.driver._prepare_crd_network(network, segments)
        # test crd network dict
        self.assertEqual(expected_crd_network, req)
        # test create_network.
        self.driver.create_network_postcommit(network_context)
        self.client.create_network.assert_called_once_with(body=req)
        # test update_network.
        self.driver.update_network_postcommit(network_context)
        self.client.update_network.assert_called_once_with(net_id, body=req)
        # test delete_network.
        self.driver.delete_network_postcommit(network_context)
        self.client.delete_network.assert_called_once_with(net_id)

    def test_create_update_delete_subnet_postcommit(self):
        """Testing create/update/delete subnet postcommit operations."""

        tenant_id = 'test'
        network_id = '123'
        subnet_id = '122'
        cidr = '192.0.0.0/8'
        gateway_ip = '192.0.0.1'
        expected_crd_subnet = {'subnet':
                               {'subnet_id': subnet_id, 'tenant_id': tenant_id,
                                'name': 'FakeSubnet', 'network_id': network_id,
                                'ip_version': 4, 'cidr': cidr,
                                'gateway_ip': gateway_ip,
                                'dns_nameservers': '',
                                'allocation_pools': '',
                                'host_routes': ''}}
        subnet_context = self._get_subnet_context(tenant_id, network_id,
                                                  subnet_id, cidr, gateway_ip)
        subnet = subnet_context.current
        subnet_id = subnet['id']
        req = self.driver._prepare_crd_subnet(subnet)
        # test crd subnet dict
        self.assertEqual(expected_crd_subnet, req)
        # test create_subnet.
        self.driver.create_subnet_postcommit(subnet_context)
        self.client.create_subnet.assert_called_once_with(body=req)
        # test update_subnet.
        self.driver.update_subnet_postcommit(subnet_context)
        self.client.update_subnet.assert_called_once_with(subnet_id, body=req)
        # test delete_subnet.
        self.driver.delete_subnet_postcommit(subnet_context)
        self.client.delete_subnet.assert_called_once_with(subnet_id)

    def test_create_delete_port_postcommit(self):
        """Testing create/delete port postcommit operations."""

        tenant_id = 'test'
        network_id = '123'
        port_id = '453'
        expected_crd_port = {'port':
                             {'port_id': port_id, 'tenant_id': tenant_id,
                              'name': 'FakePort', 'network_id': network_id,
                              'subnet_id': '', 'mac_address': 'aabb',
                              'device_id': '1234', 'ip_address': '',
                              'admin_state_up': True, 'status': 'ACTIVE',
                              'device_owner': 'compute',
                              'security_groups': ''}}
        # Test with empty fixed IP
        port_context = self._get_port_context(tenant_id, network_id, port_id)
        port = port_context.current
        req = self.driver._prepare_crd_port(port)
        # Test crd port dict
        self.assertEqual(expected_crd_port, req)
        # test create_port.
        self.driver.create_port_postcommit(port_context)
        self.client.create_port.assert_called_once_with(body=req)
        # Test delete_port
        self.driver.delete_port_postcommit(port_context)
        self.client.delete_port.assert_called_once_with(port['id'])

    def test_prepare_port_with_single_fixed_ip(self):
        """Test _prepare_crd_port with single fixed_ip."""

        tenant_id = 'test'
        network_id = '123'
        port_id = '453'
        fips = [{"subnet_id": "sub-1", "ip_address": "10.0.0.1"}]
        expected_crd_port = {'port':
                             {'port_id': port_id, 'tenant_id': tenant_id,
                              'name': 'FakePort', 'network_id': network_id,
                              'subnet_id': '', 'mac_address': 'aabb',
                              'device_id': '1234', 'ip_address': '',
                              'admin_state_up': True, 'status': 'ACTIVE',
                              'device_owner': 'compute',
                              'security_groups': ''}}
        port_context = self._get_port_context(tenant_id, network_id, port_id,
                                              fips)
        port = port_context.current
        req = self.driver._prepare_crd_port(port)
        expected_crd_port['port']['subnet_id'] = 'sub-1'
        expected_crd_port['port']['ip_address'] = '10.0.0.1'
        self.assertEqual(expected_crd_port, req)

    def test_prepare_port_with_multiple_fixed_ips(self):
        """Test _prepare_crd_port with multiple fixed_ips."""

        tenant_id = 'test'
        network_id = '123'
        port_id = '453'
        multiple_fips = [{"subnet_id": "sub-1", "ip_address": "10.0.0.1"},
                         {"subnet_id": "sub-1", "ip_address": "10.0.0.4"}]
        expected_crd_port = {'port':
                             {'port_id': port_id, 'tenant_id': tenant_id,
                              'name': 'FakePort', 'network_id': network_id,
                              'subnet_id': '', 'mac_address': 'aabb',
                              'device_id': '1234', 'ip_address': '',
                              'admin_state_up': True, 'status': 'ACTIVE',
                              'device_owner': 'compute',
                              'security_groups': ''}}
        port_context = self._get_port_context(tenant_id, network_id, port_id,
                                              multiple_fips)
        port = port_context.current
        req = self.driver._prepare_crd_port(port)
        expected_crd_port['port']['subnet_id'] = 'sub-1'
        expected_crd_port['port']['ip_address'] = '10.0.0.1'
        self.assertEqual(expected_crd_port, req)

    def _get_subnet_context(self, tenant_id, net_id, subnet_id, cidr,
                            gateway_ip):
        # sample data for testing purpose only.
        subnet = {'tenant_id': tenant_id,
                  'network_id': net_id,
                  'id': subnet_id,
                  'cidr': cidr,
                  'name': 'FakeSubnet',
                  'ip_version': 4,
                  'gateway_ip': gateway_ip,
                  }
        return FakeContext(subnet)

    def _get_port_context(self, tenant_id, net_id, port_id,
                          fixed_ips=[]):
        # sample data for testing purpose only
        port = {'device_id': '1234',
                'name': 'FakePort',
                'mac_address': 'aabb',
                'device_owner': 'compute',
                'tenant_id': tenant_id,
                'id': port_id,
                'fixed_ips': fixed_ips,
                'admin_state_up': True,
                'status': 'ACTIVE',
                'network_id': net_id}
        return FakeContext(port)

    def _get_network_context(self, tenant_id, net_id, seg_id):
        # sample data for testing purpose only.
        network = {'id': net_id,
                   'tenant_id': tenant_id,
                   'admin_state_up': True,
                   'status': 'ACTIVE',
                   'name': 'FakeNetwork', }
        segments = [{'segmentation_id': seg_id}]
        return FakeNetworkContext(network, segments)


class FakeNetworkContext(object):

    """To generate network context for testing purposes only."""

    def __init__(self, network, segments):
        self._network = network
        self._segments = segments

    @property
    def current(self):
        return self._network

    @property
    def network_segments(self):
        return self._segments


class FakeContext(object):

    """To generate context for testing purposes only."""

    def __init__(self, record):
        self._record = record

    @property
    def current(self):
        return self._record
