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

from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import subnet_dns_publish_fixed_ip as api_def
from neutron_lib import constants
from oslo_config import cfg

from neutron.db import db_base_plugin_v2
from neutron.extensions import subnet_dns_publish_fixed_ip
from neutron.tests.unit.plugins.ml2 import test_plugin


class SubnetDNSPublishFixedIPExtensionManager:

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        extension = subnet_dns_publish_fixed_ip.Subnet_dns_publish_fixed_ip()
        return extension.get_extended_resources(version)


class SubnetDNSPublishFixedIPExtensionTestPlugin(
        db_base_plugin_v2.NeutronDbPluginV2):
    """Test plugin to mixin the subnet_dns_publish_fixed_ip extension.
    """

    supported_extension_aliases = [api_def.ALIAS,
                                   dns_apidef.ALIAS,
                                   l3_apidef.ALIAS]


class SubnetDNSPublishFixedIPExtensionTestCase(
         test_plugin.Ml2PluginV2TestCase):
    """Test API extension subnet_dns_publish_fixed_ip attributes.
    """

    _extension_drivers = ['subnet_dns_publish_fixed_ip']

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super().setUp()

    def _create_subnet(
            self, network, ip_version=constants.IP_VERSION_4, cidr=None,
            **kwargs):

        cidr = cidr or '192.0.2.0/24'
        network_id = network['network']['id']
        tenant_id = network['network']['tenant_id']
        data = {'subnet': {
                    'network_id': network_id,
                    'ip_version': str(ip_version),
                    'tenant_id': tenant_id,
                    'cidr': cidr}}
        data['subnet'].update(kwargs)
        subnet_req = self.new_create_request('subnets', data)
        res = subnet_req.get_response(self.api)

        return self.deserialize(self.fmt, res)['subnet']

    def test_create_subnet_default(self):
        with self.network() as network:
            subnet = self._create_subnet(network)
            self.assertIn('dns_publish_fixed_ip', subnet)
            self.assertFalse(subnet['dns_publish_fixed_ip'])
            data = {'subnet': {'dns_publish_fixed_ip': 'true'}}
            req = self.new_update_request('subnets', data,
                                          subnet['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.api))
            self.assertTrue(res['subnet']['dns_publish_fixed_ip'])

            data = {'subnet': {'dns_publish_fixed_ip': 'false'}}
            req = self.new_update_request('subnets', data,
                                          subnet['id'])
            res = self.deserialize(self.fmt,
                                   req.get_response(self.api))
            self.assertFalse(res['subnet']['dns_publish_fixed_ip'])

    def test_create_subnet_with_arg(self):
        with self.network() as network:
            subnet = self._create_subnet(network, dns_publish_fixed_ip=True)
            self.assertIn('dns_publish_fixed_ip', subnet)
            self.assertTrue(subnet['dns_publish_fixed_ip'])
