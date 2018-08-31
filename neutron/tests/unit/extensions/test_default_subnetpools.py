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

import netaddr
from neutron_lib.api.definitions import default_subnetpools as api_def
from neutron_lib import constants
from oslo_config import cfg
import webob.exc

from neutron.db import db_base_plugin_v2
from neutron.extensions import default_subnetpools
from neutron.tests.unit.db import test_db_base_plugin_v2


class DefaultSubnetpoolsExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        extension = default_subnetpools.Default_subnetpools()
        return extension.get_extended_resources(version)


class DefaultSubnetpoolsExtensionTestPlugin(
        db_base_plugin_v2.NeutronDbPluginV2):
    """Test plugin to mixin the default subnet pools extension.
    """

    supported_extension_aliases = [api_def.ALIAS, "subnet_allocation"]


class DefaultSubnetpoolsExtensionTestCase(
         test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    """Test API extension default_subnetpools attributes.
    """

    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.test_default_subnetpools.' +
                  'DefaultSubnetpoolsExtensionTestPlugin')
        ext_mgr = DefaultSubnetpoolsExtensionManager()
        super(DefaultSubnetpoolsExtensionTestCase,
              self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _create_subnet_using_default_subnetpool(
            self, network_id, tenant_id, ip_version=constants.IP_VERSION_4,
            **kwargs):
        data = {'subnet': {
                    'network_id': network_id,
                    'ip_version': str(ip_version),
                    'tenant_id': tenant_id,
                    'use_default_subnetpool': True}}
        data['subnet'].update(kwargs)
        subnet_req = self.new_create_request('subnets', data)
        res = subnet_req.get_response(self.api)

        return self.deserialize(self.fmt, res)['subnet']

    def _update_subnetpool(self, subnetpool_id, **data):
        update_req = self.new_update_request(
            'subnetpools', {'subnetpool': data}, subnetpool_id)
        res = update_req.get_response(self.api)

        return self.deserialize(self.fmt, res)['subnetpool']

    def test_create_subnet_only_ip_version_v4(self):
        with self.network() as network:
            tenant_id = network['network']['tenant_id']
            subnetpool_prefix = '10.0.0.0/8'
            with self.subnetpool(prefixes=[subnetpool_prefix],
                                 admin=True,
                                 name="My subnet pool",
                                 tenant_id=tenant_id,
                                 min_prefixlen='25',
                                 is_default=True) as subnetpool:
                subnetpool_id = subnetpool['subnetpool']['id']
                subnet = self._create_subnet_using_default_subnetpool(
                    network['network']['id'], tenant_id, prefixlen='27')
                ip_net = netaddr.IPNetwork(subnet['cidr'])
                self.assertIn(ip_net, netaddr.IPNetwork(subnetpool_prefix))
                self.assertEqual(27, ip_net.prefixlen)
                self.assertEqual(subnetpool_id, subnet['subnetpool_id'])

    def test_convert_subnetpool_to_default_subnetpool(self):
        with self.network() as network:
            tenant_id = network['network']['tenant_id']
            subnetpool_prefix = '10.0.0.0/8'
            with self.subnetpool(prefixes=[subnetpool_prefix],
                                 admin=True,
                                 name="My subnet pool",
                                 tenant_id=tenant_id,
                                 min_prefixlen='25',
                                 is_default=False) as subnetpool:
                self.assertFalse(subnetpool['subnetpool']['is_default'])
                subnetpool_id = subnetpool['subnetpool']['id']
                updated_subnetpool = self._update_subnetpool(
                    subnetpool_id, is_default=True)
                self.assertTrue(updated_subnetpool['is_default'])

                subnet = self._create_subnet_using_default_subnetpool(
                    network['network']['id'], tenant_id)
                ip_net = netaddr.IPNetwork(subnet['cidr'])
                self.assertIn(ip_net, netaddr.IPNetwork(subnetpool_prefix))
                self.assertEqual(subnetpool_id, subnet['subnetpool_id'])

    def test_convert_default_subnetpool_to_non_default(self):
        with self.network() as network:
            tenant_id = network['network']['tenant_id']
            subnetpool_prefix = '10.0.0.0/8'
            with self.subnetpool(prefixes=[subnetpool_prefix],
                                 admin=True,
                                 name="My subnet pool",
                                 tenant_id=tenant_id,
                                 min_prefixlen='25',
                                 is_default=True) as subnetpool:
                self.assertTrue(subnetpool['subnetpool']['is_default'])
                subnetpool_id = subnetpool['subnetpool']['id']
                updated_subnetpool = self._update_subnetpool(
                    subnetpool_id, is_default=False)
                self.assertFalse(updated_subnetpool['is_default'])

    def test_create_subnet_only_ip_version_v6(self):
        # this test mirrors its v4 counterpart
        with self.network() as network:
            tenant_id = network['network']['tenant_id']
            subnetpool_prefix = '2000::/56'
            with self.subnetpool(prefixes=[subnetpool_prefix],
                                 admin=True,
                                 name="My ipv6 subnet pool",
                                 tenant_id=tenant_id,
                                 min_prefixlen='64',
                                 is_default=True) as subnetpool:
                subnetpool_id = subnetpool['subnetpool']['id']
                cfg.CONF.set_override('ipv6_pd_enabled', False)
                subnet = self._create_subnet_using_default_subnetpool(
                    network['network']['id'], tenant_id,
                    ip_version=constants.IP_VERSION_6)
                self.assertEqual(subnetpool_id, subnet['subnetpool_id'])
                ip_net = netaddr.IPNetwork(subnet['cidr'])
                self.assertIn(ip_net, netaddr.IPNetwork(subnetpool_prefix))
                self.assertEqual(64, ip_net.prefixlen)

    def _test_create_subnet_V6_pd_modes(self, ra_addr_mode, expect_fail=False):
        cfg.CONF.set_override('ipv6_pd_enabled', True)
        with self.network() as network:
            data = {'subnet': {'network_id': network['network']['id'],
                    'ip_version': constants.IP_VERSION_6,
                    'tenant_id': network['network']['tenant_id'],
                    'use_default_subnetpool': True}}
            if ra_addr_mode:
                data['subnet']['ipv6_ra_mode'] = ra_addr_mode
                data['subnet']['ipv6_address_mode'] = ra_addr_mode
            subnet_req = self.new_create_request('subnets', data)
            res = subnet_req.get_response(self.api)
            if expect_fail:
                self.assertEqual(webob.exc.HTTPClientError.code,
                                 res.status_int)
            else:
                subnet = self.deserialize(self.fmt, res)['subnet']
                self.assertEqual(constants.IPV6_PD_POOL_ID,
                                 subnet['subnetpool_id'])

    def test_create_subnet_V6_pd_slaac(self):
        self._test_create_subnet_V6_pd_modes('slaac')

    def test_create_subnet_V6_pd_stateless(self):
        self._test_create_subnet_V6_pd_modes('dhcpv6-stateless')

    def test_create_subnet_V6_pd_statefull(self):
        self._test_create_subnet_V6_pd_modes('dhcpv6-statefull',
                                             expect_fail=True)

    def test_create_subnet_V6_pd_no_mode(self):
        self._test_create_subnet_V6_pd_modes(None, expect_fail=True)
