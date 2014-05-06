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

import contextlib

import webob.exc

from neutron.api import extensions as api_ext
from neutron.common import config
from neutron.db.grouppolicy import db_group_policy_mapping as gpdb
import neutron.extensions
from neutron.extensions import group_policy as gpolicy
from neutron.extensions import group_policy_mapping as gpm
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_db_plugin


_uuid = uuidutils.generate_uuid
DB_CORE_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
DB_GP_PLUGIN_KLASS = (
    "neutron.db.grouppolicy.db_group_policy_mapping.GroupPolicyMappingDbMixin"
)

extensions_path = ':'.join(neutron.extensions.__path__)


class GroupPolicyMappingTestExtensionManager(object):

    def get_resources(self):
        attr_map = gpolicy.RESOURCE_ATTRIBUTE_MAP
        attr_map['endpoints'].update(gpm.EXTENDED_ATTRIBUTES_2_0['endpoints'])
        attr_map['endpoint_groups'].update(
            gpm.EXTENDED_ATTRIBUTES_2_0['endpoint_groups'])
        attr_map['bridge_domains'].update(
            gpm.EXTENDED_ATTRIBUTES_2_0['bridge_domains'])
        attr_map['routing_domains'].update(
            gpm.EXTENDED_ATTRIBUTES_2_0['routing_domains'])
        return gpolicy.Group_policy.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class GroupPolicyMappingTestMixin(object):
    resource_prefix_map = dict(
        (k, constants.COMMON_PREFIXES[constants.GROUP_POLICY])
        for k in gpolicy.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def _get_test_endpoint_attrs(self, name='ep1', neutron_port_id=None):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'neutron_port_id': neutron_port_id}

        return attrs

    def _get_test_endpoint_group_attrs(self, name='epg1',
                                       neutron_subnets=None):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'neutron_subnets': neutron_subnets or []}

        return attrs

    def _get_test_bridge_domain_attrs(self, name='bd1',
                                      neutron_network_id=None):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'neutron_network_id': neutron_network_id}

        return attrs

    def _get_test_routing_domain_attrs(self, name='rd1', ip_version=4,
                                       ip_supernet='10.0.0.0/8',
                                       subnet_prefix_length=24,
                                       neutron_routers=None):
        attrs = {'name': name,
                 'tenant_id': self._tenant_id,
                 'neutron_routers': neutron_routers or []}

        return attrs

    def _create_endpoint(self, fmt, name, description, endpoint_group_id,
                         neutron_port_id, expected_res_status=None, **kwargs):
        data = {'endpoint': {'name': name,
                             'description': description,
                             'endpoint_group_id': endpoint_group_id,
                             'tenant_id': self._tenant_id,
                             'neutron_port_id': neutron_port_id}}

        ep_req = self.new_create_request('endpoints', data, fmt)
        ep_res = ep_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(ep_res.status_int, expected_res_status)

        return ep_res

    def _create_endpoint_group(self, fmt, name, description,
                               provided_contracts, consumed_contracts,
                               bridge_domain_id, neutron_subnets,
                               expected_res_status=None, **kwargs):
        data = {'endpoint_group': {'name': name,
                                   'tenant_id': self._tenant_id,
                                   'description': description,
                                   'provided_contracts': provided_contracts,
                                   'consumed_contracts': consumed_contracts,
                                   'bridge_domain_id': bridge_domain_id,
                                   'neutron_subnets': neutron_subnets}}

        epg_req = self.new_create_request('endpoint_groups', data, fmt)
        epg_res = epg_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(epg_res.status_int, expected_res_status)

        return epg_res

    def _create_bridge_domain(self, fmt, name, description, routing_domain_id,
                              neutron_network_id, expected_res_status=None,
                              **kwargs):
        data = {'bridge_domain': {'name': name,
                                  'description': description,
                                  'routing_domain_id': routing_domain_id,
                                  'tenant_id': self._tenant_id,
                                  'neutron_network_id': neutron_network_id}}

        bd_req = self.new_create_request('bridge_domains', data, fmt)
        bd_res = bd_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(bd_res.status_int, expected_res_status)

        return bd_res

    def _create_routing_domain(self, fmt, name, description, ip_version,
                               ip_supernet, subnet_prefix_length,
                               neutron_routers, expected_res_status=None,
                               **kwargs):
        data = {'routing_domain': {'name': name,
                                   'description': description,
                                   'ip_version': ip_version,
                                   'ip_supernet': ip_supernet,
                                   'subnet_prefix_length':
                                   subnet_prefix_length,
                                   'tenant_id': self._tenant_id,
                                   'neutron_routers': neutron_routers}}

        rd_req = self.new_create_request('routing_domains', data, fmt)
        rd_res = rd_req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(rd_res.status_int, expected_res_status)

        return rd_res

    @contextlib.contextmanager
    def endpoint(self, fmt=None, name='ep1', description="",
                 endpoint_group_id=None, neutron_port_id=None, no_delete=False,
                 **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_endpoint(fmt, name, description, endpoint_group_id,
                                    neutron_port_id, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        ep = self.deserialize(fmt or self.fmt, res)
        try:
            yield ep
        finally:
            if not no_delete:
                self._delete('endpoints', ep['endpoint']['id'])

    @contextlib.contextmanager
    def endpoint_group(self, fmt=None, name='epg1', description="",
                       provided_contracts=None, consumed_contracts=None,
                       bridge_domain_id=None, neutron_subnets=None,
                       no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        if not provided_contracts:
            provided_contracts = {}

        if not consumed_contracts:
            consumed_contracts = {}

        res = self._create_endpoint_group(fmt, name, description,
                                          provided_contracts,
                                          consumed_contracts,
                                          bridge_domain_id, neutron_subnets,
                                          **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        epg = self.deserialize(fmt or self.fmt, res)
        try:
            yield epg
        finally:
            if not no_delete:
                self._delete('endpoint_groups', epg['endpoint_group']['id'])

    @contextlib.contextmanager
    def bridge_domain(self, fmt=None, name='bd1', description="",
                      routing_domain_id=None, neutron_network_id=None,
                      no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_bridge_domain(fmt, name, description,
                                         routing_domain_id, neutron_network_id,
                                         **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        bd = self.deserialize(fmt or self.fmt, res)
        try:
            yield bd
        finally:
            if not no_delete:
                self._delete('bridge_domains', bd['bridge_domain']['id'])

    @contextlib.contextmanager
    def routing_domain(self, fmt=None, name='rd1', description="",
                       ip_version=4, ip_supernet='10.0.0.0/8',
                       subnet_prefix_length=24, neutron_routers=None,
                       no_delete=False, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_routing_domain(fmt, name, description,
                                          ip_version, ip_supernet,
                                          subnet_prefix_length,
                                          neutron_routers, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        rd = self.deserialize(fmt or self.fmt, res)
        try:
            yield rd
        finally:
            if not no_delete:
                self._delete('routing_domains', rd['routing_domain']['id'])


class GroupPolicyMappingDbTestCase(GroupPolicyMappingTestMixin,
                                   test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, core_plugin=None, gp_plugin=None, ext_mgr=None):
        self._saved_gp_attr_map = {}
        for k, v in gpolicy.RESOURCE_ATTRIBUTE_MAP.iteritems():
            self._saved_gp_attr_map[k] = v.copy()
        self.addCleanup(self._restore_gp_attr_map)

        if not gp_plugin:
            gp_plugin = DB_GP_PLUGIN_KLASS
        service_plugins = {'gp_plugin_name': gp_plugin}

        gpdb.GroupPolicyMappingDbMixin.supported_extension_aliases = [
            'group-policy', 'group-policy-mapping']
        ext_mgr = GroupPolicyMappingTestExtensionManager()
        super(GroupPolicyMappingDbTestCase, self).setUp(
            ext_mgr=ext_mgr,
            service_plugins=service_plugins
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def _restore_gp_attr_map(self):
        gpolicy.RESOURCE_ATTRIBUTE_MAP = self._saved_gp_attr_map


class TestGroupPolicyMappedResources(GroupPolicyMappingDbTestCase):

    def test_create_endpoint(self, **kwargs):
        name = "ep1"
        neutron_port_id = None
        attrs = self._get_test_endpoint_attrs(name, neutron_port_id)

        with self.endpoint(name=name) as ep:
            for k, v in attrs.iteritems():
                self.assertEqual(ep['endpoint'][k], v)

    def test_create_endpoint_group(self, **kwargs):
        name = "epg1"
        neutron_subnets = None
        attrs = self._get_test_endpoint_group_attrs(name, neutron_subnets)

        with self.endpoint_group(name=name) as epg:
            for k, v in attrs.iteritems():
                self.assertEqual(epg['endpoint_group'][k], v)
        # TODO(Sumit): Perhaps check wiht Contracts here as well

    def test_create_bridge_domain(self, **kwargs):
        name = "bd1"
        neutron_network_id = None
        attrs = self._get_test_bridge_domain_attrs(name,
                                                   neutron_network_id)

        with self.bridge_domain(name=name) as bd:
            for k, v in attrs.iteritems():
                self.assertEqual(bd['bridge_domain'][k], v)

    def test_create_routing_domain(self, **kwargs):
        name = "rd1"
        neutron_routers = None
        attrs = self._get_test_routing_domain_attrs(name,
                                                    neutron_routers)

        with self.routing_domain(name=name) as rd:
            for k, v in attrs.iteritems():
                self.assertEqual(rd['routing_domain'][k], v)


# TODO(Sumit): XML tests
