# Copyright (c) 2014 Cisco Systems
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
#
# @author: Henry Gessau, Cisco Systems

import mock

from oslo.config import cfg

from neutron.plugins.ml2.drivers.cisco.apic import mechanism_apic as md
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.tests import base
from neutron.tests.unit.ml2.drivers.cisco.apic import (
    test_cisco_apic_common as mocked)


HOST_ID1 = 'ubuntu'
HOST_ID2 = 'rhel'
ENCAP = '101'

SUBNET_GATEWAY = '10.3.2.1'
SUBNET_CIDR = '10.3.1.0/24'
SUBNET_NETMASK = '24'

TEST_SEGMENT1 = 'test-segment1'
TEST_SEGMENT2 = 'test-segment2'


class TestCiscoApicMechDriver(base.BaseTestCase,
                              mocked.ControllerMixin,
                              mocked.ConfigMixin,
                              mocked.DbModelMixin):

    def setUp(self):
        super(TestCiscoApicMechDriver, self).setUp()
        mocked.ControllerMixin.set_up_mocks(self)
        mocked.ConfigMixin.set_up_mocks(self)
        mocked.DbModelMixin.set_up_mocks(self)

        self.mock_apic_manager_login_responses()
        self.driver = md.APICMechanismDriver()
        self.driver.vif_type = 'test-vif_type'
        self.driver.cap_port_filter = 'test-cap_port_filter'

    def test_initialize(self):
        cfg.CONF.set_override('network_vlan_ranges', ['physnet1:100:199'],
                              'ml2_type_vlan')
        ns = mocked.APIC_VLAN_NAME
        mode = mocked.APIC_VLAN_MODE
        self.mock_response_for_get('fvnsVlanInstP', name=ns, mode=mode)
        self.mock_response_for_get('physDomP', name=mocked.APIC_DOMAIN)
        self.mock_response_for_get('infraAttEntityP',
                                   name=mocked.APIC_ATT_ENT_PROF)
        self.mock_response_for_get('infraAccPortGrp',
                                   name=mocked.APIC_ACC_PORT_GRP)
        mock.patch('neutron.plugins.ml2.drivers.cisco.apic.apic_manager.'
                   'APICManager.ensure_infra_created_on_apic').start()
        self.driver.initialize()
        self.session = self.driver.apic_manager.apic.session
        self.assert_responses_drained()

    def test_update_port_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        port_ctx = self._get_port_context(mocked.APIC_TENANT,
                                          mocked.APIC_NETWORK,
                                          'vm1', net_ctx, HOST_ID1)
        mgr = self.driver.apic_manager = mock.Mock()
        self.driver.update_port_postcommit(port_ctx)
        mgr.ensure_tenant_created_on_apic.assert_called_once_with(
            mocked.APIC_TENANT)
        mgr.ensure_path_created_for_port.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK, HOST_ID1,
            ENCAP, mocked.APIC_NETWORK + '-name')

    def test_create_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1)
        mgr = self.driver.apic_manager = mock.Mock()
        self.driver.create_network_postcommit(ctx)
        mgr.ensure_bd_created_on_apic.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK)
        mgr.ensure_epg_created_for_network.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK,
            mocked.APIC_NETWORK + '-name')

    def test_delete_network_postcommit(self):
        ctx = self._get_network_context(mocked.APIC_TENANT,
                                        mocked.APIC_NETWORK,
                                        TEST_SEGMENT1)
        mgr = self.driver.apic_manager = mock.Mock()
        self.driver.delete_network_postcommit(ctx)
        mgr.delete_bd_on_apic.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK)
        mgr.delete_epg_for_network.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK)

    def test_create_subnet_postcommit(self):
        net_ctx = self._get_network_context(mocked.APIC_TENANT,
                                            mocked.APIC_NETWORK,
                                            TEST_SEGMENT1)
        subnet_ctx = self._get_subnet_context(SUBNET_GATEWAY,
                                              SUBNET_CIDR,
                                              net_ctx)
        mgr = self.driver.apic_manager = mock.Mock()
        self.driver.create_subnet_postcommit(subnet_ctx)
        mgr.ensure_subnet_created_on_apic.assert_called_once_with(
            mocked.APIC_TENANT, mocked.APIC_NETWORK,
            '%s/%s' % (SUBNET_GATEWAY, SUBNET_NETMASK))

    def _get_network_context(self, tenant_id, net_id, seg_id=None,
                             seg_type='vlan'):
        network = {'id': net_id,
                   'name': net_id + '-name',
                   'tenant_id': tenant_id,
                   'provider:segmentation_id': seg_id}
        if seg_id:
            network_segments = [{'id': seg_id,
                                 'segmentation_id': ENCAP,
                                 'network_type': seg_type,
                                 'physical_network': 'physnet1'}]
        else:
            network_segments = []
        return FakeNetworkContext(network, network_segments)

    def _get_subnet_context(self, gateway_ip, cidr, network):
        subnet = {'tenant_id': network.current['tenant_id'],
                  'network_id': network.current['id'],
                  'id': '[%s/%s]' % (gateway_ip, cidr),
                  'gateway_ip': gateway_ip,
                  'cidr': cidr}
        return FakeSubnetContext(subnet, network)

    def _get_port_context(self, tenant_id, net_id, vm_id, network, host):
        port = {'device_id': vm_id,
                'device_owner': 'compute',
                'binding:host_id': host,
                'tenant_id': tenant_id,
                'id': mocked.APIC_PORT,
                'name': mocked.APIC_PORT,
                'network_id': net_id}
        return FakePortContext(port, network)


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


class FakeSubnetContext(object):
    """To generate subnet context for testing purposes only."""

    def __init__(self, subnet, network):
        self._subnet = subnet
        self._network = network

    @property
    def current(self):
        return self._subnet

    @property
    def network(self):
        return self._network


class FakePortContext(object):
    """To generate port context for testing purposes only."""

    def __init__(self, port, network):
        self._fake_plugin = mock.Mock()
        self._fake_plugin.get_ports.return_value = []
        self._fake_plugin_context = None
        self._port = port
        self._network = network
        if network.network_segments:
            self._bound_segment = network.network_segments[0]
        else:
            self._bound_segment = None

    @property
    def current(self):
        return self._port

    @property
    def _plugin(self):
        return self._fake_plugin

    @property
    def _plugin_context(self):
        return self._fake_plugin_context

    @property
    def network(self):
        return self._network

    @property
    def bound_segment(self):
        return self._bound_segment

    def set_binding(self, segment_id, vif_type, cap_port_filter):
        pass
