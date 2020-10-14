# Copyright (c) 2012 OpenStack Foundation.

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
import copy
from unittest import mock

from neutron_lib.api.definitions import security_groups_remote_address_group \
    as sgag_def
from neutron_lib.api import validators
from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_config import cfg
import oslo_db.exception as exc
import testtools
import webob.exc

from neutron.db import address_group_db
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron.extensions import address_group as ext_ag
from neutron.extensions import securitygroup as ext_sg
from neutron.extensions import standardattrdescription
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_address_group

DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_securitygroup.'
                   'SecurityGroupTestPlugin')
LONG_NAME_OK = 'x' * (db_const.NAME_FIELD_SIZE)
LONG_NAME_NG = 'x' * (db_const.NAME_FIELD_SIZE + 1)


class SecurityGroupTestExtensionManager(object):

    def get_resources(self):
        # The description of security_group_rules will be added by extending
        # standardattrdescription. But as API router will not be initialized
        # in test code, manually add it.
        ext_res = (standardattrdescription.Standardattrdescription().
                   get_extended_resources("2.0"))
        if ext_sg.SECURITYGROUPRULES in ext_res:
            existing_sg_rule_attr_map = (
                ext_sg.RESOURCE_ATTRIBUTE_MAP[ext_sg.SECURITYGROUPRULES])
            sg_rule_attr_desc = ext_res[ext_sg.SECURITYGROUPRULES]
            existing_sg_rule_attr_map.update(sg_rule_attr_desc)
        if ext_sg.SECURITYGROUPS in ext_res:
            existing_sg_attr_map = (
                ext_sg.RESOURCE_ATTRIBUTE_MAP[ext_sg.SECURITYGROUPS])
            sg_attr_desc = ext_res[ext_sg.SECURITYGROUPS]
            existing_sg_attr_map.update(sg_attr_desc)
        # update with the remote address group api definition
        ext_sg.Securitygroup().update_attributes_map(
            sgag_def.RESOURCE_ATTRIBUTE_MAP)
        return (ext_sg.Securitygroup.get_resources() +
                ext_ag.Address_group().get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def update_attributes_map(self, attributes):
        for resource, attrs in ext_sg.RESOURCE_ATTRIBUTE_MAP.items():
            extended_attrs = attributes.get(resource)
            if extended_attrs:
                attrs.update(extended_attrs)


class SecurityGroupsTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _build_security_group(self, name, description, **kwargs):
        data = {
            'security_group': {
                'name': name,
                'tenant_id': kwargs.get(
                    'tenant_id', test_db_base_plugin_v2.TEST_TENANT_ID),
                'description': description}}
        return data

    def _create_security_group_response(self, fmt, data, **kwargs):
        security_group_req = self.new_create_request('security-groups', data,
                                                     fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            security_group_req.environ['neutron.context'] = (
                context.Context('', kwargs['tenant_id']))
        return security_group_req.get_response(self.ext_api)

    def _create_security_group(self, fmt, name, description, **kwargs):
        data = self._build_security_group(name, description, **kwargs)
        return self._create_security_group_response(fmt, data, **kwargs)

    def _build_security_group_rule(
            self, security_group_id, direction, proto,
            port_range_min=None, port_range_max=None,
            remote_ip_prefix=None, remote_group_id=None,
            remote_address_group_id=None,
            tenant_id=test_db_base_plugin_v2.TEST_TENANT_ID,
            ethertype=const.IPv4):

        data = {'security_group_rule': {'security_group_id': security_group_id,
                                        'direction': direction,
                                        'protocol': proto,
                                        'ethertype': ethertype,
                                        'tenant_id': tenant_id}}
        if port_range_min:
            data['security_group_rule']['port_range_min'] = port_range_min

        if port_range_max:
            data['security_group_rule']['port_range_max'] = port_range_max

        if remote_ip_prefix:
            data['security_group_rule']['remote_ip_prefix'] = remote_ip_prefix

        if remote_group_id:
            data['security_group_rule']['remote_group_id'] = remote_group_id

        if remote_address_group_id:
            data['security_group_rule']['remote_address_group_id'] = \
                remote_address_group_id

        return data

    def _create_security_group_rule(self, fmt, rules, **kwargs):

        security_group_rule_req = self.new_create_request(
            'security-group-rules', rules, fmt)

        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            security_group_rule_req.environ['neutron.context'] = (
                context.Context('', kwargs['tenant_id']))
        elif kwargs.get('admin_context'):
            security_group_rule_req.environ['neutron.context'] = (
                context.Context(user_id='admin', tenant_id='admin-tenant',
                is_admin=True))
        return security_group_rule_req.get_response(self.ext_api)

    def _make_security_group(self, fmt, name, description, **kwargs):
        res = self._create_security_group(fmt, name, description, **kwargs)
        if res.status_int >= webob.exc.HTTPBadRequest.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    def _make_security_group_rule(self, fmt, rules, **kwargs):
        res = self._create_security_group_rule(self.fmt, rules)
        if res.status_int >= webob.exc.HTTPBadRequest.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def security_group(self, name='webservers', description='webservers',
                       fmt=None):
        if not fmt:
            fmt = self.fmt
        security_group = self._make_security_group(fmt, name, description)
        yield security_group

    @contextlib.contextmanager
    def security_group_rule(self, security_group_id='4cd70774-cc67-4a87-9b39-7'
                                                    'd1db38eb087',
                            direction='ingress', protocol=const.PROTO_NAME_TCP,
                            port_range_min='22', port_range_max='22',
                            remote_ip_prefix=None, remote_group_id=None,
                            remote_address_group_id=None,
                            fmt=None, ethertype=const.IPv4):
        if not fmt:
            fmt = self.fmt
        rule = self._build_security_group_rule(security_group_id,
                                               direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix,
                                               remote_group_id,
                                               remote_address_group_id,
                                               ethertype=ethertype)
        security_group_rule = self._make_security_group_rule(self.fmt, rule)
        yield security_group_rule

    def _delete_default_security_group_egress_rules(self, security_group_id):
        """Deletes default egress rules given a security group ID."""
        res = self._list(
            'security-group-rules',
            query_params='security_group_id=%s' % security_group_id)

        for r in res['security_group_rules']:
            if (r['direction'] == 'egress' and not r['port_range_max'] and
                    not r['port_range_min'] and not r['protocol'] and
                    not r['remote_ip_prefix']):
                self._delete('security-group-rules', r['id'])

    def _assert_sg_rule_has_kvs(self, security_group_rule, expected_kvs):
        """Asserts that the sg rule has expected key/value pairs passed
           in as expected_kvs dictionary
        """
        for k, v in expected_kvs.items():
            self.assertEqual(v, security_group_rule[k])


class SecurityGroupTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                              securitygroups_db.SecurityGroupDbMixin,
                              address_group_db.AddressGroupDbMixin):
    """Test plugin that implements necessary calls on create/delete port for
    associating ports with security groups.
    """

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["security-group"]

    def create_port(self, context, port):
        tenant_id = port['port']['tenant_id']
        default_sg = self._ensure_default_security_group(context, tenant_id)
        if not validators.is_attr_set(port['port'].get(ext_sg.SECURITYGROUPS)):
            port['port'][ext_sg.SECURITYGROUPS] = [default_sg]
        with db_api.CONTEXT_WRITER.using(context):
            sgs = self._get_security_groups_on_port(context, port)
            port = super(SecurityGroupTestPlugin, self).create_port(context,
                                                                    port)
            self._process_port_create_security_group(context, port,
                                                     sgs)
        return port

    def update_port(self, context, id, port):
        with db_api.CONTEXT_WRITER.using(context):
            if ext_sg.SECURITYGROUPS in port['port']:
                sgs = self._get_security_groups_on_port(context, port)
                port['port'][ext_sg.SECURITYGROUPS] = [
                    sg['id'] for sg in sgs] if sgs else None
                # delete the port binding and read it with the new rules
                self._delete_port_security_group_bindings(context, id)
                port['port']['id'] = id
                self._process_port_create_security_group(
                    context, port['port'], sgs)
            port = super(SecurityGroupTestPlugin, self).update_port(
                context, id, port)
        return port

    def create_network(self, context, network):
        self._ensure_default_security_group(context,
                                            network['network']['tenant_id'])
        return super(SecurityGroupTestPlugin, self).create_network(context,
                                                                   network)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        sorts = sorts or []
        neutron_lports = super(SecurityGroupTestPlugin, self).get_ports(
            context, filters, sorts=sorts, limit=limit, marker=marker,
            page_reverse=page_reverse)
        return neutron_lports


class SecurityGroupDBTestCase(SecurityGroupsTestCase,
                              test_address_group.AddressGroupTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        self._backup = copy.deepcopy(ext_sg.RESOURCE_ATTRIBUTE_MAP)
        self.addCleanup(self._restore)
        plugin = plugin or DB_PLUGIN_KLASS
        ext_mgr = ext_mgr or SecurityGroupTestExtensionManager()
        super(SecurityGroupDBTestCase,
              self).setUp(plugin=plugin, ext_mgr=ext_mgr)

    def _restore(self):
        ext_sg.RESOURCE_ATTRIBUTE_MAP = self._backup


class TestSecurityGroups(SecurityGroupDBTestCase):
    def test_create_security_group(self):
        name = 'webservers'
        description = 'my webservers'
        keys = [('name', name,), ('description', description)]
        with self.security_group(name, description) as security_group:
            for k, v, in keys:
                self.assertEqual(v, security_group['security_group'][k])

        # Verify that default egress rules have been created

        sg_rules = security_group['security_group']['security_group_rules']
        self.assertEqual(2, len(sg_rules))

        v4_rules = [r for r in sg_rules if r['ethertype'] == const.IPv4]
        self.assertEqual(1, len(v4_rules))
        v4_rule = v4_rules[0]
        expected = {'direction': 'egress',
                    'ethertype': const.IPv4,
                    'remote_group_id': None,
                    'remote_ip_prefix': None,
                    'protocol': None,
                    'port_range_max': None,
                    'port_range_min': None}
        self._assert_sg_rule_has_kvs(v4_rule, expected)

        v6_rules = [r for r in sg_rules if r['ethertype'] == const.IPv6]
        self.assertEqual(1, len(v6_rules))
        v6_rule = v6_rules[0]
        expected = {'direction': 'egress',
                    'ethertype': const.IPv6,
                    'remote_group_id': None,
                    'remote_ip_prefix': None,
                    'protocol': None,
                    'port_range_max': None,
                    'port_range_min': None}
        self._assert_sg_rule_has_kvs(v6_rule, expected)

    def test_create_security_group_bulk(self):
        rule1 = self._build_security_group("sg_1", "sec_grp_1")
        rule2 = self._build_security_group("sg_2", "sec_grp_2")
        rules = {'security_groups': [rule1['security_group'],
                                     rule2['security_group']]}
        res = self._create_security_group_response(self.fmt, rules)
        ret = self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
        self.assertEqual(2, len(ret['security_groups']))

    def test_skip_duplicate_default_sg_error(self):
        num_called = [0]
        original_func = self.plugin.create_security_group

        def side_effect(context, security_group, default_sg):
            # can't always raise, or create_security_group will hang
            self.assertTrue(default_sg)
            self.assertLess(num_called[0], 2)
            num_called[0] += 1
            ret = original_func(context, security_group, default_sg)
            if num_called[0] == 1:
                return ret
            # make another call to cause an exception.
            # NOTE(yamamoto): raising the exception by ourselves
            # doesn't update the session state appropriately.
            self.assertRaises(exc.DBDuplicateEntry,
                              original_func, context, security_group,
                              default_sg)

        with mock.patch.object(SecurityGroupTestPlugin,
                               'create_security_group',
                               side_effect=side_effect):
            self.plugin.create_network(
                context.get_admin_context(),
                {'network': {'name': 'foo',
                             'admin_state_up': True,
                             'shared': False,
                             'tenant_id': 'bar'}})

    def test_update_security_group(self):
        with self.security_group() as sg:
            data = {'security_group': {'name': 'new_name',
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_group']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(data['security_group']['name'],
                             res['security_group']['name'])
            self.assertEqual(data['security_group']['description'],
                             res['security_group']['description'])

    def test_update_security_group_name_to_default_fail(self):
        with self.security_group() as sg:
            data = {'security_group': {'name': 'default',
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_group']['id'])
            req.environ['neutron.context'] = context.Context('', 'somebody')
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_update_default_security_group_name_fail(self):
        with self.network():
            res = self.new_list_request('security-groups')
            sg = self.deserialize(self.fmt, res.get_response(self.ext_api))
            data = {'security_group': {'name': 'new_name',
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_groups'][0]['id'])
            req.environ['neutron.context'] = context.Context('', 'somebody')
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_update_default_security_group_with_description(self):
        with self.network():
            res = self.new_list_request('security-groups')
            sg = self.deserialize(self.fmt, res.get_response(self.ext_api))
            data = {'security_group': {'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_groups'][0]['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(data['security_group']['description'],
                             res['security_group']['description'])

    def test_update_security_group_with_max_name_length(self):
        with self.security_group() as sg:
            data = {'security_group': {'name': LONG_NAME_OK,
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_group']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(data['security_group']['name'],
                             res['security_group']['name'])
            self.assertEqual(data['security_group']['description'],
                             res['security_group']['description'])

    def test_update_security_group_with_too_long_name(self):
        with self.security_group() as sg:
            data = {'security_group': {'name': LONG_NAME_NG,
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_group']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_security_group_with_boolean_type_name(self):
        with self.security_group() as sg:
            data = {'security_group': {'name': True,
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_group']['id'])
            res = req.get_response(self.ext_api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_check_default_security_group_description(self):
        with self.network():
            res = self.new_list_request('security-groups')
            sg = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self.assertEqual('Default security group',
                             sg['security_groups'][0]['description'])

    def test_default_security_group(self):
        with self.network():
            res = self.new_list_request('security-groups')
            groups = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self.assertEqual(1, len(groups['security_groups']))

    def test_create_default_security_group_fail(self):
        name = 'default'
        description = 'my webservers'
        res = self._create_security_group(self.fmt, name, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_default_security_group_check_case_insensitive(self):
        name = 'DEFAULT'
        description = 'my webservers'
        res = self._create_security_group(self.fmt, name, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_with_max_name_length(self):
        description = 'my webservers'
        res = self._create_security_group(self.fmt, LONG_NAME_OK, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_with_too_long_name(self):
        description = 'my webservers'
        res = self._create_security_group(self.fmt, LONG_NAME_NG, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_with_boolean_type_name(self):
        description = 'my webservers'
        res = self._create_security_group(self.fmt, True, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_list_security_groups(self):
        with self.security_group(name='sg1', description='sg') as v1,\
                self.security_group(name='sg2', description='sg') as v2,\
                self.security_group(name='sg3', description='sg') as v3:
            security_groups = (v1, v2, v3)
            self._test_list_resources('security-group',
                                      security_groups,
                                      query_params='description=sg')

    def test_list_security_groups_with_sort(self):
        with self.security_group(name='sg1', description='sg') as sg1,\
                self.security_group(name='sg2', description='sg') as sg2,\
                self.security_group(name='sg3', description='sg') as sg3:
            self._test_list_with_sort('security-group',
                                      (sg3, sg2, sg1),
                                      [('name', 'desc')],
                                      query_params='description=sg')

    def test_list_security_groups_with_pagination(self):
        with self.security_group(name='sg1', description='sg') as sg1,\
                self.security_group(name='sg2', description='sg') as sg2,\
                self.security_group(name='sg3', description='sg') as sg3:
            self._test_list_with_pagination('security-group',
                                            (sg1, sg2, sg3),
                                            ('name', 'asc'), 2, 2,
                                            query_params='description=sg')

    def test_list_security_groups_with_pagination_reverse(self):
        with self.security_group(name='sg1', description='sg') as sg1,\
                self.security_group(name='sg2', description='sg') as sg2,\
                self.security_group(name='sg3', description='sg') as sg3:
            self._test_list_with_pagination_reverse(
                'security-group', (sg1, sg2, sg3), ('name', 'asc'), 2, 2,
                query_params='description=sg')

    def test_create_security_group_rule_ethertype_invalid_as_number(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            ethertype = 2
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', const.PROTO_NAME_TCP, '22',
                '22', None, None, ethertype=ethertype)
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_ethertype_invalid_for_protocol(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', const.PROTO_NAME_IPV6_FRAG)
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_invalid_ip_prefix(self):
        name = 'webservers'
        description = 'my webservers'
        for bad_prefix in ['bad_ip', 256, "2001:db8:a::123/129", '172.30./24']:
            with self.security_group(name, description) as sg:
                sg_id = sg['security_group']['id']
                remote_ip_prefix = bad_prefix
                rule = self._build_security_group_rule(
                    sg_id,
                    'ingress',
                    const.PROTO_NAME_TCP,
                    '22', '22',
                    remote_ip_prefix)
                res = self._create_security_group_rule(self.fmt, rule)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_invalid_ethertype_for_prefix(self):
        name = 'webservers'
        description = 'my webservers'
        test_addr = {'192.168.1.1/24': 'IPv6',
                     '2001:db8:1234::/48': 'IPv4',
                     '192.168.2.1/24': 'BadEthertype'}
        for remote_ip_prefix, ethertype in test_addr.items():
            with self.security_group(name, description) as sg:
                sg_id = sg['security_group']['id']
                rule = self._build_security_group_rule(
                    sg_id,
                    'ingress',
                    const.PROTO_NAME_TCP,
                    '22', '22',
                    remote_ip_prefix,
                    None,
                    ethertype=ethertype)
                res = self._create_security_group_rule(self.fmt, rule)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_with_unmasked_prefix(self):
        name = 'webservers'
        description = 'my webservers'
        addr = {'10.1.2.3': {'mask': '32', 'ethertype': 'IPv4'},
                'fe80::2677:3ff:fe7d:4c': {'mask': '128', 'ethertype': 'IPv6'}}
        for ip in addr:
            with self.security_group(name, description) as sg:
                sg_id = sg['security_group']['id']
                ethertype = addr[ip]['ethertype']
                remote_ip_prefix = ip
                rule = self._build_security_group_rule(
                    sg_id,
                    'ingress',
                    const.PROTO_NAME_TCP,
                    '22', '22',
                    remote_ip_prefix,
                    None,
                    ethertype=ethertype)
                res = self._create_security_group_rule(self.fmt, rule)
                self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
                res_sg = self.deserialize(self.fmt, res)
                prefix = res_sg['security_group_rule']['remote_ip_prefix']
                self.assertEqual('%s/%s' % (ip, addr[ip]['mask']), prefix)

    def test_create_security_group_rule_tcp_protocol_as_number(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = const.PROTO_NUM_TCP  # TCP
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol, '22', '22')
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_rule_protocol_as_number(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = 2
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol)
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_rule_protocol_as_number_with_port_bad(self):
        # When specifying ports, neither can be None
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = 6
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol, '70', None)
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_protocol_as_number_range(self):
        # This is a SG rule with a port range, but treated as a single
        # port since min/max are the same.
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = 6
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol, '70', '70')
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_rule_protocol_as_number_port_bad(self):
        # Only certain protocols support a SG rule with a port
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            protocol = 111
            rule = self._build_security_group_rule(
                security_group_id, 'ingress', protocol, '70', '70')
            res = self._create_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_case_insensitive(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = 'TCP'
            port_range_min = 22
            port_range_max = 22
            ethertype = 'ipV4'
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_ip_prefix=remote_ip_prefix,
                                          ethertype=ethertype) as rule:

                # the lower case value will be return
                self.assertEqual(protocol.lower(),
                                 rule['security_group_rule']['protocol'])
                self.assertEqual(const.IPv4,
                                 rule['security_group_rule']['ethertype'])

    def test_get_security_group(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            remote_group_id = sg['security_group']['id']
            res = self.new_show_request('security-groups', remote_group_id)
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = const.PROTO_NAME_TCP
            port_range_min = 22
            port_range_max = 22
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_ip_prefix=remote_ip_prefix):

                group = self.deserialize(
                    self.fmt, res.get_response(self.ext_api))
                sg_rule = group['security_group']['security_group_rules']
                self.assertEqual(remote_group_id,
                                 group['security_group']['id'])
                self.assertEqual(3, len(sg_rule))
                sg_rule = [r for r in sg_rule if r['direction'] == 'ingress']
                for k, v, in keys:
                    self.assertEqual(v, sg_rule[0][k])

    def test_get_security_group_empty_rules(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            remote_group_id = sg['security_group']['id']

            self._delete_default_security_group_egress_rules(
                remote_group_id)

            res = self.new_show_request('security-groups', remote_group_id)
            group = self.deserialize(
                self.fmt, res.get_response(self.ext_api))

            sg_rule = group['security_group']['security_group_rules']
            self.assertEqual(remote_group_id, group['security_group']['id'])
            self.assertEqual(0, len(sg_rule))

    def test_get_security_group_empty_rules_id_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            remote_group_id = sg['security_group']['id']

            self._delete_default_security_group_egress_rules(
                remote_group_id)

            res = self.new_show_request('security-groups', remote_group_id,
                                        fields=['id'])
            group = self.deserialize(
                self.fmt, res.get_response(self.ext_api))

            secgroup = group['security_group']
            self.assertFalse('security_group_rules' in secgroup)
            self.assertEqual(remote_group_id, group['security_group']['id'])

    # This test case checks that admins from a different tenant can add rules
    # as themselves. This is an odd behavior, with some weird GET semantics,
    # but this test is checking that we don't break that old behavior, at least
    # until we make a conscious choice to do so.
    def test_create_security_group_rules_admin_tenant(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            # Add a couple normal rules
            rule = self._build_security_group_rule(
                sg['security_group']['id'], "ingress", const.PROTO_NAME_TCP,
                port_range_min=22, port_range_max=22,
                remote_ip_prefix="10.0.0.0/24",
                ethertype=const.IPv4)
            self._make_security_group_rule(self.fmt, rule)

            rule = self._build_security_group_rule(
                sg['security_group']['id'], "ingress", const.PROTO_NAME_TCP,
                port_range_min=22, port_range_max=22,
                remote_ip_prefix="10.0.1.0/24",
                ethertype=const.IPv4)
            self._make_security_group_rule(self.fmt, rule)

            # Let's add a rule as admin, with a different tenant_id. The
            # results of this call are arguably a bug, but it is past behavior.
            rule = self._build_security_group_rule(
                sg['security_group']['id'], "ingress", const.PROTO_NAME_TCP,
                port_range_min=22, port_range_max=22,
                remote_ip_prefix="10.0.2.0/24",
                ethertype=const.IPv4,
                tenant_id='admin-tenant')
            self._make_security_group_rule(self.fmt, rule, admin_context=True)

            # Now, let's make sure all the rules are there, with their odd
            # tenant_id behavior.
            res = self.new_list_request('security-groups')
            sgs = self.deserialize(self.fmt, res.get_response(self.ext_api))
            for sg in sgs['security_groups']:
                if sg['name'] == "webservers":
                    rules = sg['security_group_rules']
                    self.assertEqual(5, len(rules))
                    self.assertNotEqual('admin-tenant', rules[3]['tenant_id'])
                    self.assertEqual('admin-tenant', rules[4]['tenant_id'])

    def test_get_security_group_on_port_from_wrong_tenant(self):
        plugin = directory.get_plugin()
        if not hasattr(plugin, '_get_security_groups_on_port'):
            self.skipTest("plugin doesn't use the mixin with this method")
        neutron_context = context.Context('user', 'tenant')
        res = self._create_security_group(self.fmt, 'webservers', 'webservers',
                                          tenant_id='bad_tenant')
        sg1 = self.deserialize(self.fmt, res)
        with testtools.ExpectedException(ext_sg.SecurityGroupNotFound):
            plugin._get_security_groups_on_port(
                neutron_context,
                {'port': {'security_groups': [sg1['security_group']['id']],
                          'tenant_id': 'tenant'}}
            )

    def test_get_security_group_on_port_with_admin_from_other_tenant(self):
        plugin = directory.get_plugin()
        if not hasattr(plugin, '_get_security_groups_on_port'):
            self.skipTest("plugin doesn't use the mixin with this method")
        neutron_context = context.get_admin_context()
        res = self._create_security_group(self.fmt, 'webservers', 'webservers',
                                          tenant_id='other_tenant')
        sg1 = self.deserialize(self.fmt, res)
        sgs = plugin._get_security_groups_on_port(
            neutron_context,
            {'port': {'security_groups': [sg1['security_group']['id']],
                      'tenant_id': 'tenant'}})
        sg1_id = sg1['security_group']['id']
        self.assertEqual(sg1_id, sgs[0].id)
        self.assertEqual('other_tenant', sgs[0].project_id)

    def test_delete_security_group(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            remote_group_id = sg['security_group']['id']
            self._delete('security-groups', remote_group_id,
                         webob.exc.HTTPNoContent.code)

    def test_delete_default_security_group_admin(self):
        with self.network():
            res = self.new_list_request('security-groups')
            sg = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self._delete('security-groups', sg['security_groups'][0]['id'],
                         webob.exc.HTTPNoContent.code)

    def test_delete_default_security_group_nonadmin(self):
        with self.network():
            res = self.new_list_request('security-groups')
            sg = self.deserialize(self.fmt, res.get_response(self.ext_api))
            neutron_context = context.Context(
                '', test_db_base_plugin_v2.TEST_TENANT_ID)
            self._delete('security-groups', sg['security_groups'][0]['id'],
                         webob.exc.HTTPConflict.code,
                         neutron_context=neutron_context)

    def test_security_group_list_creates_default_security_group(self):
        neutron_context = context.Context(
            '', test_db_base_plugin_v2.TEST_TENANT_ID)
        sg = self._list('security-groups',
                        neutron_context=neutron_context).get('security_groups')
        self.assertEqual(1, len(sg))

    def test_security_group_port_create_creates_default_security_group(self):
        res = self._create_network(self.fmt, 'net1', True,
                                   tenant_id='not_admin',
                                   set_context=True)
        net1 = self.deserialize(self.fmt, res)
        res = self._create_port(self.fmt, net1['network']['id'],
                                tenant_id='not_admin', set_context=True)
        sg = self._list('security-groups').get('security_groups')
        self.assertEqual(1, len(sg))

    def test_default_security_group_rules(self):
        with self.network():
            res = self.new_list_request('security-groups')
            groups = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self.assertEqual(1, len(groups['security_groups']))
            security_group_id = groups['security_groups'][0]['id']
            res = self.new_list_request('security-group-rules')
            rules = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self.assertEqual(4, len(rules['security_group_rules']))

            # Verify default rule for v4 egress
            sg_rules = rules['security_group_rules']
            rules = [
                r for r in sg_rules
                if r['direction'] == 'egress' and r['ethertype'] == const.IPv4
            ]
            self.assertEqual(1, len(rules))
            v4_egress = rules[0]

            expected = {'direction': 'egress',
                        'ethertype': const.IPv4,
                        'remote_group_id': None,
                        'remote_ip_prefix': None,
                        'protocol': None,
                        'port_range_max': None,
                        'port_range_min': None}
            self._assert_sg_rule_has_kvs(v4_egress, expected)

            # Verify default rule for v6 egress
            rules = [
                r for r in sg_rules
                if r['direction'] == 'egress' and r['ethertype'] == const.IPv6
            ]
            self.assertEqual(1, len(rules))
            v6_egress = rules[0]

            expected = {'direction': 'egress',
                        'ethertype': const.IPv6,
                        'remote_group_id': None,
                        'remote_ip_prefix': None,
                        'protocol': None,
                        'port_range_max': None,
                        'port_range_min': None}
            self._assert_sg_rule_has_kvs(v6_egress, expected)

            # Verify default rule for v4 ingress
            rules = [
                r for r in sg_rules
                if r['direction'] == 'ingress' and r['ethertype'] == const.IPv4
            ]
            self.assertEqual(1, len(rules))
            v4_ingress = rules[0]

            expected = {'direction': 'ingress',
                        'ethertype': const.IPv4,
                        'remote_group_id': security_group_id,
                        'remote_ip_prefix': None,
                        'protocol': None,
                        'port_range_max': None,
                        'port_range_min': None}
            self._assert_sg_rule_has_kvs(v4_ingress, expected)

            # Verify default rule for v6 ingress
            rules = [
                r for r in sg_rules
                if r['direction'] == 'ingress' and r['ethertype'] == const.IPv6
            ]
            self.assertEqual(1, len(rules))
            v6_ingress = rules[0]

            expected = {'direction': 'ingress',
                        'ethertype': const.IPv6,
                        'remote_group_id': security_group_id,
                        'remote_ip_prefix': None,
                        'protocol': None,
                        'port_range_max': None,
                        'port_range_min': None}
            self._assert_sg_rule_has_kvs(v6_ingress, expected)

    def test_create_security_group_rule_remote_ip_prefix(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = const.PROTO_NAME_TCP
            port_range_min = 22
            port_range_max = 22
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_ip_prefix=remote_ip_prefix
                                          ) as rule:
                for k, v, in keys:
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_group_id(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            with self.security_group(name, description) as sg2:
                security_group_id = sg['security_group']['id']
                direction = "ingress"
                remote_group_id = sg2['security_group']['id']
                protocol = const.PROTO_NAME_TCP
                port_range_min = 22
                port_range_max = 22
                keys = [('remote_group_id', remote_group_id),
                        ('security_group_id', security_group_id),
                        ('direction', direction),
                        ('protocol', protocol),
                        ('port_range_min', port_range_min),
                        ('port_range_max', port_range_max)]
                with self.security_group_rule(security_group_id,
                                              direction=direction,
                                              protocol=protocol,
                                              port_range_min=port_range_min,
                                              port_range_max=port_range_max,
                                              remote_group_id=remote_group_id
                                              ) as rule:
                    for k, v, in keys:
                        self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_remote_address_group_id(self):
        name = 'webservers'
        description = 'my webservers'
        ag = self._test_create_address_group(name='foo')
        ag_id = ag['address_group']['id']
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_address_group_id = ag_id
            protocol = const.PROTO_NAME_TCP
            port_range_min = 22
            port_range_max = 22
            keys = [('remote_address_group_id', remote_address_group_id),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_address_group_id=(
                                                  remote_address_group_id)
                                          ) as rule:
                for k, v, in keys:
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_delete_address_group_in_use(self):
        ag = self._test_create_address_group(name='foo')
        ag_id = ag['address_group']['id']
        with self.security_group() as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id,
                                          remote_address_group_id=ag_id):
                self._delete('address-groups', ag['address_group']['id'],
                             expected_code=webob.exc.HTTPConflict.code)

    def test_create_security_group_rule_multiple_remotes(self):
        name = 'webservers'
        description = 'my webservers'
        ag = self._test_create_address_group(name='foo')
        ag_id = ag['address_group']['id']
        with self.security_group(name, description) as sg:
            sg_id = sg['security_group']['id']
            for remote in [
                {'remote_ip_prefix': '10.0.0.0/8', 'remote_group_id': sg_id},
                {'remote_group_id': sg_id, 'remote_address_group_id': ag_id},
                {'remote_ip_prefix': '10.0.0.0/8',
                 'remote_address_group_id': ag_id},
                {'remote_ip_prefix': '10.0.0.0/8', 'remote_group_id': sg_id,
                 'remote_address_group_id': ag_id}
            ]:
                rule = self._build_security_group_rule(sg_id, "ingress",
                                                       const.PROTO_NAME_TCP,
                                                       **remote)
                res = self._create_security_group_rule(self.fmt, rule)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_port_range_min_max_limits(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            protocol = const.PROTO_NAME_TCP
            port_range_min = const.PORT_RANGE_MIN
            port_range_max = const.PORT_RANGE_MAX
            # The returned rule should have port range min/max as None
            keys = [('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', None),
                    ('port_range_max', None)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max
                                          ) as rule:
                for k, v, in keys:
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_icmp_with_type_and_code(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = const.PROTO_NAME_ICMP
            # port_range_min (ICMP type) is greater than port_range_max
            # (ICMP code) in order to confirm min <= max port check is
            # not called for ICMP.
            port_range_min = 8
            port_range_max = 5
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_ip_prefix=remote_ip_prefix
                                          ) as rule:
                for k, v, in keys:
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_icmp_with_type_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            remote_ip_prefix = "10.0.0.0/24"
            protocol = const.PROTO_NAME_ICMP
            # ICMP type
            port_range_min = 8
            # ICMP code
            port_range_max = None
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_ip_prefix=remote_ip_prefix
                                          ) as rule:
                for k, v, in keys:
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_icmpv6_with_type_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            ethertype = const.IPv6
            remote_ip_prefix = "2001::f401:56ff:fefe:d3dc/128"
            protocol = const.PROTO_NAME_IPV6_ICMP
            # ICMPV6 type
            port_range_min = const.ICMPV6_TYPE_RA
            # ICMPV6 code
            port_range_max = None
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('ethertype', ethertype),
                    ('protocol', protocol),
                    ('port_range_min', port_range_min),
                    ('port_range_max', port_range_max)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          port_range_min=port_range_min,
                                          port_range_max=port_range_max,
                                          remote_ip_prefix=remote_ip_prefix,
                                          ethertype=ethertype) as rule:
                for k, v, in keys:
                    self.assertEqual(v, rule['security_group_rule'][k])

    def _test_create_security_group_rule_legacy_protocol_name(self, protocol):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            ethertype = const.IPv6
            remote_ip_prefix = "2001::f401:56ff:fefe:d3dc/128"
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('ethertype', ethertype),
                    ('protocol', protocol)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          remote_ip_prefix=remote_ip_prefix,
                                          ethertype=ethertype) as rule:
                for k, v, in keys:
                    # IPv6 ICMP protocol will always be 'ipv6-icmp'
                    if k == 'protocol':
                        v = const.PROTO_NAME_IPV6_ICMP
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_ipv6_icmp_legacy_protocol_name(self):
        protocol = const.PROTO_NAME_ICMP
        self._test_create_security_group_rule_legacy_protocol_name(protocol)

    def test_create_security_group_rule_icmpv6_legacy_protocol_name(self):
        protocol = const.PROTO_NAME_IPV6_ICMP_LEGACY
        self._test_create_security_group_rule_legacy_protocol_name(protocol)

    def _test_create_security_group_rule_legacy_protocol_num(self, protocol):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            ethertype = const.IPv6
            remote_ip_prefix = "2001::f401:56ff:fefe:d3dc/128"
            keys = [('remote_ip_prefix', remote_ip_prefix),
                    ('security_group_id', security_group_id),
                    ('direction', direction),
                    ('ethertype', ethertype),
                    ('protocol', protocol)]
            with self.security_group_rule(security_group_id,
                                          direction=direction,
                                          protocol=protocol,
                                          remote_ip_prefix=remote_ip_prefix,
                                          ethertype=ethertype) as rule:
                for k, v, in keys:
                    # IPv6 ICMP protocol will always be '58'
                    if k == 'protocol':
                        v = str(const.PROTO_NUM_IPV6_ICMP)
                    self.assertEqual(v, rule['security_group_rule'][k])

    def test_create_security_group_rule_ipv6_icmp_legacy_protocol_num(self):
        protocol = const.PROTO_NUM_ICMP
        self._test_create_security_group_rule_legacy_protocol_num(protocol)

    def test_create_security_group_rule_ipv6_icmp_protocol_num(self):
        protocol = const.PROTO_NUM_IPV6_ICMP
        self._test_create_security_group_rule_legacy_protocol_num(protocol)

    def test_create_security_group_source_group_ip_and_ip_prefix(self):
        security_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = const.PROTO_NAME_TCP
        port_range_min = 22
        port_range_max = 22
        remote_group_id = "9cd70774-cc67-4a87-9b39-7d1db38eb087"
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix,
                                               remote_group_id)
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_bad_security_group_id(self):
        security_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = const.PROTO_NAME_TCP
        port_range_min = 22
        port_range_max = 22
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix)
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_security_group_rule_bad_tenant(self):
        with self.security_group() as sg:
            rule = {'security_group_rule':
                    {'security_group_id': sg['security_group']['id'],
                     'direction': 'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'port_range_min': '22',
                     'port_range_max': '22',
                     'tenant_id': "bad_tenant"}}

            res = self._create_security_group_rule(self.fmt, rule,
                                                   tenant_id='bad_tenant',
                                                   set_context=True)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_security_group_rule_bad_tenant_remote_group_id(self):
        with self.security_group() as sg:
            res = self._create_security_group(self.fmt, 'webservers',
                                              'webservers',
                                              tenant_id='bad_tenant')
            sg2 = self.deserialize(self.fmt, res)
            rule = {'security_group_rule':
                    {'security_group_id': sg2['security_group']['id'],
                     'direction': 'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'port_range_min': '22',
                     'port_range_max': '22',
                     'tenant_id': 'bad_tenant',
                     'remote_group_id': sg['security_group']['id']}}

            res = self._create_security_group_rule(self.fmt, rule,
                                                   tenant_id='bad_tenant',
                                                   set_context=True)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_security_group_rule_bad_tenant_security_group_rule(self):
        with self.security_group() as sg:
            res = self._create_security_group(self.fmt, 'webservers',
                                              'webservers',
                                              tenant_id='bad_tenant')
            self.deserialize(self.fmt, res)
            rule = {'security_group_rule':
                    {'security_group_id': sg['security_group']['id'],
                     'direction': 'ingress',
                     'protocol': const.PROTO_NAME_TCP,
                     'port_range_min': '22',
                     'port_range_max': '22',
                     'tenant_id': 'bad_tenant'}}

            res = self._create_security_group_rule(self.fmt, rule,
                                                   tenant_id='bad_tenant',
                                                   set_context=True)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_security_group_rule_bad_remote_group_id(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            remote_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
            direction = "ingress"
            protocol = const.PROTO_NAME_TCP
            port_range_min = 22
            port_range_max = 22
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_group_id=remote_group_id)
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_security_group_rule_bad_remote_address_group_id(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            remote_address_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
            direction = "ingress"
            protocol = const.PROTO_NAME_TCP
            port_range_min = 22
            port_range_max = 22
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_address_group_id=(
                                                   remote_address_group_id
                                               ))
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPNotFound.code, res.status_int)

    def test_create_security_group_rule_duplicate_rules(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id) as sgr:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22')
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
                self.assertIn(sgr['security_group_rule']['id'],
                              res.json['NeutronError']['message'])

    def test_create_security_group_rule_duplicate_rules_diff_desc(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id) as sgr:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22')
                rule['security_group_rule']['description'] = "description"
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
                self.assertIn(sgr['security_group_rule']['id'],
                              res.json['NeutronError']['message'])

    def test_create_security_group_rule_duplicate_rules_proto_name_num(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22')
                self._create_security_group_rule(self.fmt, rule)
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NUM_TCP, '22', '22')
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rule_duplicate_rules_proto_num_name(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NUM_UDP, '50', '100')
                self._create_security_group_rule(self.fmt, rule)
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_UDP, '50', '100')
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rule_min_port_greater_max(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                for protocol in [const.PROTO_NAME_TCP, const.PROTO_NAME_UDP,
                                 const.PROTO_NUM_TCP, const.PROTO_NUM_UDP]:
                    rule = self._build_security_group_rule(
                        sg['security_group']['id'],
                        'ingress', protocol, '50', '22')
                    res = self._create_security_group_rule(self.fmt, rule)
                    self.deserialize(self.fmt, res)
                    self.assertEqual(webob.exc.HTTPBadRequest.code,
                                     res.status_int)

    def test_create_security_group_rule_ports_but_no_protocol(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress', None, '22', '22')
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_port_range_min_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', None)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_port_range_max_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, None, '22')
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_icmp_type_too_big(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_ICMP, '256', None)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_icmp_code_too_big(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_ICMP, '8', '256')
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_icmp_with_code_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                for code in ['2', '0']:
                    rule = self._build_security_group_rule(
                        sg['security_group']['id'], 'ingress',
                        const.PROTO_NAME_ICMP, None, code)
                    res = self._create_security_group_rule(self.fmt, rule)
                    self.deserialize(self.fmt, res)
                    self.assertEqual(webob.exc.HTTPBadRequest.code,
                                     res.status_int)

    def test_list_ports_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'])
                req = self.new_list_request('ports')
                res = req.get_response(self.api)
                ports = self.deserialize(self.fmt, res)
                port = ports['ports'][0]
                self.assertEqual(1, len(port[ext_sg.SECURITYGROUPS]))
                self._delete('ports', port['id'])

    def test_list_security_group_rules(self):
        with self.security_group(name='sg') as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id,
                                          direction='egress',
                                          port_range_min=22,
                                          port_range_max=22) as sgr1,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=23,
                                             port_range_max=23) as sgr2,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=24,
                                             port_range_max=24) as sgr3:

                # Delete default rules as they would fail the following
                # assertion at the end.
                self._delete_default_security_group_egress_rules(
                    security_group_id)

                q = 'direction=egress&security_group_id=' + security_group_id
                self._test_list_resources('security-group-rule',
                                          [sgr1, sgr2, sgr3],
                                          query_params=q)

    def test_list_security_group_rules_with_sort(self):
        with self.security_group(name='sg') as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id,
                                          direction='egress',
                                          port_range_min=22,
                                          port_range_max=22) as sgr1,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=23,
                                             port_range_max=23) as sgr2,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=24,
                                             port_range_max=24) as sgr3:

                # Delete default rules as they would fail the following
                # assertion at the end.
                self._delete_default_security_group_egress_rules(
                    security_group_id)

                q = 'direction=egress&security_group_id=' + security_group_id
                self._test_list_with_sort('security-group-rule',
                                          (sgr3, sgr2, sgr1),
                                          [('port_range_max', 'desc')],
                                          query_params=q)

    def test_list_security_group_rules_with_pagination(self):
        with self.security_group(name='sg') as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id,
                                          direction='egress',
                                          port_range_min=22,
                                          port_range_max=22) as sgr1,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=23,
                                             port_range_max=23) as sgr2,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=24,
                                             port_range_max=24) as sgr3:

                # Delete default rules as they would fail the following
                # assertion at the end.
                self._delete_default_security_group_egress_rules(
                    security_group_id)

                q = 'direction=egress&security_group_id=' + security_group_id
                self._test_list_with_pagination(
                    'security-group-rule', (sgr3, sgr2, sgr1),
                    ('port_range_max', 'desc'), 2, 2,
                    query_params=q)

    def test_list_security_group_rules_with_pagination_reverse(self):
        with self.security_group(name='sg') as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id,
                                          direction='egress',
                                          port_range_min=22,
                                          port_range_max=22) as sgr1,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=23,
                                             port_range_max=23) as sgr2,\
                    self.security_group_rule(security_group_id,
                                             direction='egress',
                                             port_range_min=24,
                                             port_range_max=24) as sgr3:
                self._test_list_with_pagination_reverse(
                    'security-group-rule', (sgr3, sgr2, sgr1),
                    ('port_range_max', 'desc'), 2, 2,
                    query_params='direction=egress')

    def test_create_port_with_multiple_security_groups(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg1:
                    with self.security_group() as sg2:
                        res = self._create_port(
                            self.fmt, n['network']['id'],
                            security_groups=[sg1['security_group']['id'],
                                             sg2['security_group']['id']])
                        port = self.deserialize(self.fmt, res)
                        self.assertEqual(2, len(
                            port['port'][ext_sg.SECURITYGROUPS]))
                        self._delete('ports', port['port']['id'])

    def test_create_port_with_no_security_groups(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        security_groups=[])
                port = self.deserialize(self.fmt, res)
                self.assertEqual([], port['port'][ext_sg.SECURITYGROUPS])

    def test_update_port_with_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    res = self._create_port(self.fmt, n['network']['id'])
                    port = self.deserialize(self.fmt, res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     ext_sg.SECURITYGROUPS:
                                     [sg['security_group']['id']]}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(sg['security_group']['id'],
                                     res['port'][ext_sg.SECURITYGROUPS][0])

                    # Test update port without security group
                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name']}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(sg['security_group']['id'],
                                     res['port'][ext_sg.SECURITYGROUPS][0])

                    self._delete('ports', port['port']['id'])

    def test_update_port_with_multiple_security_groups(self):
        with self.network() as n:
            with self.subnet(n) as s:
                with self.port(s) as port:
                    with self.security_group() as sg1:
                        with self.security_group() as sg2:
                            data = {'port': {ext_sg.SECURITYGROUPS:
                                             [sg1['security_group']['id'],
                                              sg2['security_group']['id']]}}
                            req = self.new_update_request(
                                'ports', data, port['port']['id'])
                            port = self.deserialize(
                                self.fmt, req.get_response(self.api))
                            self.assertEqual(
                                2, len(port['port'][ext_sg.SECURITYGROUPS]))

    def test_update_port_remove_security_group_empty_list(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    res = self._create_port(self.fmt, n['network']['id'],
                                            security_groups=(
                                                [sg['security_group']['id']]))
                    port = self.deserialize(self.fmt, res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     'security_groups': []}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual([],
                                     res['port'].get(ext_sg.SECURITYGROUPS))
                    self._delete('ports', port['port']['id'])

    def test_update_port_remove_security_group_none(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    res = self._create_port(self.fmt, n['network']['id'],
                                            security_groups=(
                                                [sg['security_group']['id']]))
                    port = self.deserialize(self.fmt, res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     'security_groups': None}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual([],
                                     res['port'].get(ext_sg.SECURITYGROUPS))
                    self._delete('ports', port['port']['id'])

    def test_update_port_with_invalid_type_in_security_groups_param(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    res = self._create_port(self.fmt, n['network']['id'],
                                            security_groups=(
                                                [sg['security_group']['id']]))
                    port = self.deserialize(self.fmt, res)

                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name'],
                                     'security_groups': True}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(webob.exc.HTTPBadRequest.code,
                                     res.status_int)

    def test_create_port_with_bad_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        security_groups=['bad_id'])

                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_port_with_invalid_type_in_security_groups_param(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        security_groups=True)

                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_delete_security_group_port_in_use(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    res = self._create_port(self.fmt, n['network']['id'],
                                            security_groups=(
                                                [sg['security_group']['id']]))
                    port = self.deserialize(self.fmt, res)
                    self.assertEqual(sg['security_group']['id'],
                                     port['port'][ext_sg.SECURITYGROUPS][0])
                    # try to delete security group that's in use
                    self._delete('security-groups',
                                 sg['security_group']['id'],
                                 webob.exc.HTTPConflict.code)
                    # delete the blocking port
                    self._delete('ports', port['port']['id'])

    def test_create_security_group_rule_bulk_native(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "security_group_rule create")
        with self.security_group() as sg:
            rule1 = self._build_security_group_rule(sg['security_group']['id'],
                                                    'ingress',
                                                    const.PROTO_NAME_TCP, '22',
                                                    '22', '10.0.0.1/24')
            rule2 = self._build_security_group_rule(sg['security_group']['id'],
                                                    'ingress',
                                                    const.PROTO_NAME_TCP, '23',
                                                    '23', '10.0.0.1/24')
            rules = {'security_group_rules': [rule1['security_group_rule'],
                                              rule2['security_group_rule']]}
            res = self._create_security_group_rule(self.fmt, rules)
            ret = self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
            self.assertEqual(2, len(ret['security_group_rules']))

    def test_create_security_group_rule_bulk_emulated(self):
        real_has_attr = hasattr

        # ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('builtins.hasattr', new=fakehasattr):
            with self.security_group() as sg:
                rule1 = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22', '10.0.0.1/24')
                rule2 = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '23', '23', '10.0.0.1/24')
                rules = {'security_group_rules': [rule1['security_group_rule'],
                                                  rule2['security_group_rule']]
                         }
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_rule_allow_all_ipv4(self):
        with self.security_group() as sg:
            rule = {'security_group_id': sg['security_group']['id'],
                    'direction': 'ingress',
                    'ethertype': const.IPv4,
                    'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

            res = self._create_security_group_rule(
                self.fmt, {'security_group_rule': rule})
            rule = self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_rule_allow_all_ipv4_v6_bulk(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "security_group_rule create")
        with self.security_group() as sg:
            rule_v4 = {'security_group_id': sg['security_group']['id'],
                       'direction': 'ingress',
                       'ethertype': const.IPv4,
                       'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}
            rule_v6 = {'security_group_id': sg['security_group']['id'],
                       'direction': 'ingress',
                       'ethertype': const.IPv6,
                       'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

            rules = {'security_group_rules': [rule_v4, rule_v6]}
            res = self._create_security_group_rule(self.fmt, rules)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_security_group_rule_duplicate_rule_in_post(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "security_group_rule create")
        with self.security_group() as sg:
            rule = self._build_security_group_rule(sg['security_group']['id'],
                                                   'ingress',
                                                   const.PROTO_NAME_TCP, '22',
                                                   '22', '10.0.0.1/24')
            rules = {'security_group_rules': [rule['security_group_rule'],
                                              rule['security_group_rule']]}
            res = self._create_security_group_rule(self.fmt, rules)
            rule = self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rule_duplicate_rule_in_post_emulated(self):
        real_has_attr = hasattr

        # ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('builtins.hasattr', new=fakehasattr):
            with self.security_group() as sg:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22', '10.0.0.1/24')
                rules = {'security_group_rules': [rule['security_group_rule'],
                                                  rule['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                rule = self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rule_duplicate_rule_db(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "security_group_rule create")
        with self.security_group() as sg:
            rule = self._build_security_group_rule(sg['security_group']['id'],
                                                   'ingress',
                                                   const.PROTO_NAME_TCP, '22',
                                                   '22', '10.0.0.1/24')
            rules = {'security_group_rules': [rule]}
            self._create_security_group_rule(self.fmt, rules)
            res = self._create_security_group_rule(self.fmt, rules)
            rule = self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rule_duplicate_rule_db_emulated(self):
        real_has_attr = hasattr

        # ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('builtins.hasattr', new=fakehasattr):
            with self.security_group() as sg:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22', '10.0.0.1/24')
                rules = {'security_group_rules': [rule]}
                self._create_security_group_rule(self.fmt, rules)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_groups_native_quotas(self):
        quota = 1
        cfg.CONF.set_override('quota_security_group', quota, group='QUOTAS')
        name = 'quota_test'
        description = 'quota_test'
        res = self._create_security_group(self.fmt, name, description)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
        res = self._create_security_group(self.fmt, name, description)
        self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rules_native_quotas(self):
        name = 'quota_test'
        description = 'quota_test'
        with self.security_group(name, description) as sg:
            # avoid the number of default security group rules
            sgr = self._list('security-group-rules').get(
                'security_group_rules')
            quota = len(sgr) + 1
            cfg.CONF.set_override(
                'quota_security_group_rule', quota, group='QUOTAS')

            security_group_id = sg['security_group']['id']
            rule = self._build_security_group_rule(
                security_group_id, 'ingress',
                const.PROTO_NAME_TCP, '22', '22')
            res = self._create_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
            rule = self._build_security_group_rule(
                security_group_id, 'egress',
                const.PROTO_NAME_TCP, '22', '22')
            res = self._create_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_security_group_rule_different_security_group_ids(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "security_group_rule create")
        with self.security_group() as sg1:
            with self.security_group() as sg2:
                rule1 = self._build_security_group_rule(
                    sg1['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22', '10.0.0.1/24')
                rule2 = self._build_security_group_rule(
                    sg2['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '23', '23', '10.0.0.1/24')

                rules = {'security_group_rules': [rule1['security_group_rule'],
                                                  rule2['security_group_rule']]
                         }
                res = self._create_security_group_rule(self.fmt, rules)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_with_invalid_ethertype(self):
        security_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = const.PROTO_NAME_TCP
        port_range_min = 22
        port_range_max = 22
        remote_group_id = "9cd70774-cc67-4a87-9b39-7d1db38eb087"
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix,
                                               remote_group_id,
                                               ethertype='IPv5')
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_with_invalid_protocol(self):
        security_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = 'tcp/ip'
        port_range_min = 22
        port_range_max = 22
        remote_group_id = "9cd70774-cc67-4a87-9b39-7d1db38eb087"
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix,
                                               remote_group_id)
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_with_invalid_tcp_or_udp_protocol(self):
        security_group_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = 'tcp'
        port_range_min = 0
        port_range_max = 80
        remote_group_id = "9cd70774-cc67-4a87-9b39-7d1db38eb087"
        rule = self._build_security_group_rule(security_group_id, direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix,
                                               remote_group_id)
        res = self._create_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_port_with_non_uuid(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        security_groups=['not_valid'])

                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_security_group_rule_with_specific_id(self):
        neutron_context = context.Context(
            '', test_db_base_plugin_v2.TEST_TENANT_ID)
        specified_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        with self.security_group() as sg:
            rule = self._build_security_group_rule(
                sg['security_group']['id'], 'ingress', const.PROTO_NUM_TCP)
            rule['security_group_rule'].update({'id': specified_id,
                                                'port_range_min': None,
                                                'port_range_max': None,
                                                'remote_ip_prefix': None,
                                                'remote_group_id': None,
                                                'remote_address_group_id':
                                                    None})
            result = self.plugin.create_security_group_rule(
                neutron_context, rule)
            self.assertEqual(specified_id, result['id'])


class TestConvertIPPrefixToCIDR(base.BaseTestCase):

    def test_convert_bad_ip_prefix_to_cidr(self):
        for val in ['bad_ip', 256, "2001:db8:a::123/129"]:
            self.assertRaises(exceptions.InvalidCIDR,
                              ext_sg.convert_ip_prefix_to_cidr, val)
        self.assertIsNone(ext_sg.convert_ip_prefix_to_cidr(None))

    def test_convert_ip_prefix_no_netmask_to_cidr(self):
        addr = {'10.1.2.3': '32', 'fe80::2677:3ff:fe7d:4c': '128'}
        for k, v in addr.items():
            self.assertEqual('%s/%s' % (k, v),
                             ext_sg.convert_ip_prefix_to_cidr(k))

    def test_convert_ip_prefix_with_netmask_to_cidr(self):
        addresses = ['10.1.0.0/16', '10.1.2.3/32', '2001:db8:1234::/48']
        for addr in addresses:
            self.assertEqual(addr, ext_sg.convert_ip_prefix_to_cidr(addr))


class TestConvertProtocol(base.BaseTestCase):
    def test_convert_numeric_protocol(self):
        self.assertIsInstance(ext_sg.convert_protocol('2'), str)

    def test_convert_bad_protocol(self):
        for val in ['bad', '256', '-1']:
            self.assertRaises(ext_sg.SecurityGroupRuleInvalidProtocol,
                              ext_sg.convert_protocol, val)

    def test_convert_numeric_protocol_to_string(self):
        self.assertIsInstance(ext_sg.convert_protocol(2), str)


class TestConvertEtherType(base.BaseTestCase):
    def test_convert_unsupported_ethertype(self):
        for val in ['ip', 'ip4', 'ip6', '']:
            self.assertRaises(ext_sg.SecurityGroupRuleInvalidEtherType,
                              ext_sg.convert_ethertype_to_case_insensitive,
                              val)
