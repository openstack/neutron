# Copyright 2022 Canonical
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

from unittest import mock

from neutron.common.ovn import constants
from neutron.conf.plugins.ml2 import config as ml2_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as const


class TestOVNClientBase(base.BaseTestCase):

    def setUp(self):
        ml2_conf.register_ml2_plugin_opts()
        ovn_conf.register_opts()
        super(TestOVNClientBase, self).setUp()
        self.nb_idl = mock.MagicMock()
        self.sb_idl = mock.MagicMock()
        self.ovn_client = ovn_client.OVNClient(self.nb_idl, self.sb_idl)


class TestOVNClient(TestOVNClientBase):

    def setUp(self):
        super(TestOVNClient, self).setUp()
        self.get_plugin = mock.patch(
            'neutron_lib.plugins.directory.get_plugin').start()

    def test__add_router_ext_gw_default_route(self):
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {
            'subnet_id': 'fake-subnet-id',
            'gateway_ip': '10.42.0.1',
            'ip_version': const.IP_VERSION_4,
        }
        plugin.get_subnet.return_value = subnet
        router = {
            'id': 'fake-router-id',
            l3.EXTERNAL_GW_INFO: {
                'external_fixed_ips': [{
                        'subnet_id': subnet.get('subnet_id'),
                        'ip_address': '10.42.0.42'}],
            },
            'gw_port_id': 'fake-port-id',
        }
        networks = mock.MagicMock()
        txn = mock.MagicMock()
        self.assertEqual(
            self.get_plugin().get_port(),
            self.ovn_client._add_router_ext_gw(router, networks, txn))
        self.nb_idl.add_static_route.assert_called_once_with(
            'neutron-' + router['id'],
            ip_prefix='0.0.0.0/0',
            nexthop='10.42.0.1',
            external_ids={
                'neutron:is_ext_gw': 'true',
                'neutron:subnet_id': subnet['subnet_id']})

    def test__add_router_ext_gw_no_default_route(self):
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {
            'subnet_id': 'fake-subnet-id',
            'gateway_ip': None,
            'ip_version': const.IP_VERSION_4
        }
        plugin.get_subnet.return_value = subnet
        router = {
            'id': 'fake-router-id',
            l3.EXTERNAL_GW_INFO: {
                'external_fixed_ips': [{
                        'subnet_id': subnet.get('subnet_id'),
                        'ip_address': '10.42.0.42'}],
            },
            'gw_port_id': 'fake-port-id',
        }
        networks = mock.MagicMock()
        txn = mock.MagicMock()
        self.assertEqual(
            self.get_plugin().get_port(),
            self.ovn_client._add_router_ext_gw(router, networks, txn))
        self.nb_idl.add_static_route.assert_not_called()


class TestOVNClientDetermineBindHost(TestOVNClientBase):

    def setUp(self):
        super(TestOVNClientDetermineBindHost, self).setUp()
        self.get_chassis_by_card_serial_from_cms_options = (
            self.sb_idl.get_chassis_by_card_serial_from_cms_options)
        self.fake_smartnic_hostname = 'fake-chassis-hostname'
        self.get_chassis_by_card_serial_from_cms_options.return_value = (
            fakes.FakeChassis.create(
                attrs={'hostname': self.fake_smartnic_hostname}))

    def test_vnic_normal_unbound_port(self):
        self.assertEqual(
            '',
            self.ovn_client.determine_bind_host({}))

    def test_vnic_normal_bound_port(self):
        port = {
            portbindings.HOST_ID: 'fake-binding-host-id',
        }
        self.assertEqual(
            'fake-binding-host-id',
            self.ovn_client.determine_bind_host(port))

    def test_vnic_normal_port_context(self):
        context = mock.MagicMock()
        context.host = 'fake-binding-host-id'
        self.assertEqual(
            'fake-binding-host-id',
            self.ovn_client.determine_bind_host({}, port_context=context))

    def test_vnic_remote_managed_unbound_port_no_binding_profile(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {},
        }
        self.assertEqual(
            '',
            self.ovn_client.determine_bind_host(port))

    def test_vnic_remote_managed_unbound_port(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        self.assertEqual(
            self.fake_smartnic_hostname,
            self.ovn_client.determine_bind_host(port))

    def test_vnic_remote_managed_bound_port(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            portbindings.HOST_ID: 'fake-binding-host-id',
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        self.assertEqual(
            self.fake_smartnic_hostname,
            self.ovn_client.determine_bind_host(port))

    def test_vnic_remote_managed_port_context(self):
        context = mock.MagicMock()
        context.current = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        context.host = 'fake-binding-host-id'
        self.assertEqual(
            self.fake_smartnic_hostname,
            self.ovn_client.determine_bind_host({}, port_context=context))
