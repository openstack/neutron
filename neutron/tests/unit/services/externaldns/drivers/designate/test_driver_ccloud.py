# Copyright 2025 SAP SE
# All rights reserved.
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

from unittest import mock

from oslo_config import cfg

from neutron.tests.unit.extensions.test_l3\
    import L3NatDBFloatingIpTestCaseWithDNS
from neutron.tests.unit.extensions.test_l3\
    import L3TestExtensionManagerWithDNS

from neutron.services.externaldns.drivers.designate import driver_ccloud

from .test_driver import TestDesignateDriver


class L3NatDBFloatingIpTestCaseWithDNSCcloud(L3NatDBFloatingIpTestCaseWithDNS):
    """Unit tests for floating ip with external DNS integration"""

    fmt = 'json'
    DNS_NAME = 'test'
    DNS_DOMAIN = 'test-domain.org.'
    PUBLIC_CIDR = '11.0.0.0/24'
    PRIVATE_CIDR = '10.0.0.0/24'
    mock_client = mock.MagicMock()
    mock_admin_client = mock.MagicMock()
    MOCK_PATH = ('neutron.services.externaldns.drivers.'
                 'designate.driver_ccloud.get_clients')
    mock_config = {'return_value': (mock_client, mock_admin_client)}
    _extension_drivers = ['dns']

    def setUp(self):
        ext_mgr = L3TestExtensionManagerWithDNS()
        plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(L3NatDBFloatingIpTestCaseWithDNS, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)
        cfg.CONF.set_override('external_dns_driver', 'designate_ccloud')
        self.mock_client.reset_mock()
        self.mock_admin_client.reset_mock()

    def _assert_recordset_created(self, floating_ip_address, floating_ip_id):
        # The recordsets.create function should be called with:
        # dns_domain, dns_name, 'A', ip_address ('A' for IPv4, 'AAAA' for IPv6)
        self.mock_client.recordsets.create.assert_called_with(
            self.DNS_DOMAIN,
            self.DNS_NAME,
            'A',
            [floating_ip_address]
        )
        self.mock_client.floatingips.set.assert_called_with(
            f"{None}:{floating_ip_id}",
            f"{self.DNS_NAME}.{self.DNS_DOMAIN}")

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create(self, mock_args):
        with self._create_floatingip_with_dns():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                                              port_dns_name=self.DNS_NAME,
                                              assoc_port=True) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_create_with_flip_and_net_port_dns(self, mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain='junkdomain.org.',
                                              port_dns_name='junk',
                                              flip_dns_domain=self.DNS_DOMAIN,
                                              flip_dns_name=self.DNS_NAME,
                                              assoc_port=True) as flip:
            floatingip = flip
        # External DNS service should have been called with floating ip's
        # dns information, not the network+port's dns information
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port(self, mock_args):
        with self._create_floatingip_with_dns_on_update():
            pass
        self.mock_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_flip_dns(self, mock_args):
        with self._create_floatingip_with_dns_on_update(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_net_port_dns(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns_on_update(
                net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_associate_port_with_flip_and_net_port_dns(self,
                                                                  mock_args):
        # If both network+port and the floating ip have dns domain and
        # dns name, floating ip's information should take priority
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns_on_update(
                net_dns_domain='junkdomain.org.',
                port_dns_name='junk',
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
        self._assert_recordset_created(floatingip['floating_ip_address'],
                                       floatingip["id"])
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_disassociate_port(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(net_dns_domain=self.DNS_DOMAIN,
                port_dns_name=self.DNS_NAME, assoc_port=True) as flip:
            fake_recordset = {'id': '',
                    'records': [flip['floating_ip_address']]}
            # This method is called during recordset deletion, which
            # will fail unless the list function call returns something like
            # this fake value
            self.mock_client.recordsets.list.return_value = ([fake_recordset])
            # Port gets disassociated if port_id is not in the request body
            data = {'floatingip': {}}
            req = self.new_update_request('floatingips', data, flip['id'])
            res = req.get_response(self._api_for_resource('floatingip'))
        floatingip = self.deserialize(self.fmt, res)['floatingip']
        flip_port_id = floatingip['port_id']
        self.assertEqual(200, res.status_code)
        self.assertIsNone(flip_port_id)
        in_addr_name, in_addr_zone_name = self._get_in_addr(
            floatingip['floating_ip_address'])
        self.mock_client.recordsets.delete.assert_called_with(
            self.DNS_DOMAIN, '')
        self.mock_admin_client.recordsets.delete.assert_called_with(
            in_addr_zone_name, in_addr_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_delete(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)
        with self._create_floatingip_with_dns(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME) as flip:
            floatingip = flip
            # This method is called during recordset deletion, which will
            # fail unless the list function call returns something like
            # this fake value
            fake_recordset = {'id': '',
                              'records': [floatingip['floating_ip_address']]}
            self.mock_client.recordsets.list.return_value = [fake_recordset]
        in_addr_name, in_addr_zone_name = self._get_in_addr(
                floatingip['floating_ip_address'])
        self.mock_client.recordsets.delete.assert_called_with(
                self.DNS_DOMAIN, '')
        self.mock_admin_client.recordsets.delete.assert_called_with(
                in_addr_zone_name, in_addr_name)

    @mock.patch(MOCK_PATH, **mock_config)
    def test_floatingip_no_PTR_record(self, mock_args):
        cfg.CONF.set_override('dns_domain', self.DNS_DOMAIN)

        # Disabling this option should stop the admin client from creating
        # PTR records. So set this option and make sure the admin client
        # wasn't called to create any records
        cfg.CONF.set_override('allow_reverse_dns_lookup', False,
                              group='designate')

        with self._create_floatingip_with_dns(
                flip_dns_domain=self.DNS_DOMAIN,
                flip_dns_name=self.DNS_NAME
        ) as flip:
            floatingip = flip

        self.mock_client.recordsets.create.assert_called_with(
            self.DNS_DOMAIN, self.DNS_NAME, 'A',
            [floatingip['floating_ip_address']]
        )
        self.mock_admin_client.recordsets.create.assert_not_called()
        self.mock_client.floatingips.set.assert_not_called()
        self.assertEqual(self.DNS_DOMAIN, floatingip['dns_domain'])
        self.assertEqual(self.DNS_NAME, floatingip['dns_name'])


class TestCCloudDesignateDriver(TestDesignateDriver):
    def setUp(self):
        # skip our parents setup and call it's parent instead:
        super(TestDesignateDriver, self).setUp()
        self.context = mock.Mock()
        self.client = mock.Mock()
        self.admin_client = mock.Mock()
        self.all_projects_client = mock.Mock()
        mock.patch.object(driver_ccloud, 'get_clients', return_value=(
            self.client, self.admin_client)).start()
        mock.patch.object(driver_ccloud, 'get_all_projects_client',
                          return_value=self.all_projects_client).start()
        self.driver = driver_ccloud.DesignateCcloud()

    def test_create_record_set_duplicate_recordset(self):

        # The Ccloud driver should not raise an exception here,
        # in contrast to the default driver. Let's ensure correct behavior
        self.driver.create_record_set(self.context, 'example.test.',
                                      'test', ['192.168.0.10'])
