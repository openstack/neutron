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

import mock
import oslo_db.exception as exc
import six
import testtools
import webob.exc

from neutron.api.v2 import attributes as attr
from neutron.common import constants as const
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import db_base_plugin_v2
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.tests import base
from neutron.tests.unit.db import test_db_base_plugin_v2

DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_securitygroup.'
                   'SecurityGroupTestPlugin')


class SecurityGroupTestExtensionManager(object):

    def get_resources(self):
        # Add the resources to the global attribute map
        # This is done here as the setup process won't
        # initialize the main API router which extends
        # the global attribute map
        attr.RESOURCE_ATTRIBUTE_MAP.update(
            ext_sg.RESOURCE_ATTRIBUTE_MAP)
        return ext_sg.Securitygroup.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class SecurityGroupsTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def _create_security_group(self, fmt, name, description, **kwargs):

        data = {'security_group': {'name': name,
                                   'tenant_id': kwargs.get('tenant_id',
                                                           'test-tenant'),
                                   'description': description}}
        security_group_req = self.new_create_request('security-groups', data,
                                                     fmt)
        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            security_group_req.environ['neutron.context'] = (
                context.Context('', kwargs['tenant_id']))
        return security_group_req.get_response(self.ext_api)

    def _build_security_group_rule(self, security_group_id, direction, proto,
                                   port_range_min=None, port_range_max=None,
                                   remote_ip_prefix=None, remote_group_id=None,
                                   tenant_id='test-tenant',
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

        return data

    def _create_security_group_rule(self, fmt, rules, **kwargs):

        security_group_rule_req = self.new_create_request(
            'security-group-rules', rules, fmt)

        if (kwargs.get('set_context') and 'tenant_id' in kwargs):
            # create a specific auth context for this request
            security_group_rule_req.environ['neutron.context'] = (
                context.Context('', kwargs['tenant_id']))
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
                            fmt=None, ethertype=const.IPv4):
        if not fmt:
            fmt = self.fmt
        rule = self._build_security_group_rule(security_group_id,
                                               direction,
                                               protocol, port_range_min,
                                               port_range_max,
                                               remote_ip_prefix,
                                               remote_group_id,
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
                    not r['port_range_min'] and not r['protocol']
                    and not r['remote_ip_prefix']):
                self._delete('security-group-rules', r['id'])

    def _assert_sg_rule_has_kvs(self, security_group_rule, expected_kvs):
        """Asserts that the sg rule has expected key/value pairs passed
           in as expected_kvs dictionary
        """
        for k, v in six.iteritems(expected_kvs):
            self.assertEqual(security_group_rule[k], v)


class SecurityGroupTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                              securitygroups_db.SecurityGroupDbMixin):
    """Test plugin that implements necessary calls on create/delete port for
    associating ports with security groups.
    """

    __native_pagination_support = True
    __native_sorting_support = True

    supported_extension_aliases = ["security-group"]

    def create_port(self, context, port):
        tenant_id = self._get_tenant_id_for_create(context, port['port'])
        default_sg = self._ensure_default_security_group(context, tenant_id)
        if not attr.is_attr_set(port['port'].get(ext_sg.SECURITYGROUPS)):
            port['port'][ext_sg.SECURITYGROUPS] = [default_sg]
        session = context.session
        with session.begin(subtransactions=True):
            sgids = self._get_security_groups_on_port(context, port)
            port = super(SecurityGroupTestPlugin, self).create_port(context,
                                                                    port)
            self._process_port_create_security_group(context, port,
                                                     sgids)
        return port

    def update_port(self, context, id, port):
        session = context.session
        with session.begin(subtransactions=True):
            if ext_sg.SECURITYGROUPS in port['port']:
                port['port'][ext_sg.SECURITYGROUPS] = (
                    self._get_security_groups_on_port(context, port))
                # delete the port binding and read it with the new rules
                self._delete_port_security_group_bindings(context, id)
                port['port']['id'] = id
                self._process_port_create_security_group(
                    context, port['port'],
                    port['port'].get(ext_sg.SECURITYGROUPS))
            port = super(SecurityGroupTestPlugin, self).update_port(
                context, id, port)
        return port

    def create_network(self, context, network):
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        self._ensure_default_security_group(context, tenant_id)
        return super(SecurityGroupTestPlugin, self).create_network(context,
                                                                   network)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=[], limit=None, marker=None,
                  page_reverse=False):
        neutron_lports = super(SecurityGroupTestPlugin, self).get_ports(
            context, filters, sorts=sorts, limit=limit, marker=marker,
            page_reverse=page_reverse)
        return neutron_lports


class SecurityGroupDBTestCase(SecurityGroupsTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        plugin = plugin or DB_PLUGIN_KLASS
        ext_mgr = ext_mgr or SecurityGroupTestExtensionManager()
        super(SecurityGroupDBTestCase,
              self).setUp(plugin=plugin, ext_mgr=ext_mgr)


class TestSecurityGroups(SecurityGroupDBTestCase):
    def test_create_security_group(self):
        name = 'webservers'
        description = 'my webservers'
        keys = [('name', name,), ('description', description)]
        with self.security_group(name, description) as security_group:
            for k, v, in keys:
                self.assertEqual(security_group['security_group'][k], v)

        # Verify that default egress rules have been created

        sg_rules = security_group['security_group']['security_group_rules']
        self.assertEqual(len(sg_rules), 2)

        v4_rules = [r for r in sg_rules if r['ethertype'] == const.IPv4]
        self.assertEqual(len(v4_rules), 1)
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
        self.assertEqual(len(v6_rules), 1)
        v6_rule = v6_rules[0]
        expected = {'direction': 'egress',
                    'ethertype': const.IPv6,
                    'remote_group_id': None,
                    'remote_ip_prefix': None,
                    'protocol': None,
                    'port_range_max': None,
                    'port_range_min': None}
        self._assert_sg_rule_has_kvs(v6_rule, expected)

    def test_skip_duplicate_default_sg_error(self):
        num_called = [0]
        original_func = self.plugin.create_security_group

        def side_effect(context, security_group, default_sg):
            # can't always raise, or create_security_group will hang
            self.assertTrue(default_sg)
            self.assertTrue(num_called[0] < 2)
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
            self.assertEqual(res['security_group']['name'],
                             data['security_group']['name'])
            self.assertEqual(res['security_group']['description'],
                             data['security_group']['description'])

    def test_update_security_group_name_to_default_fail(self):
        with self.security_group() as sg:
            data = {'security_group': {'name': 'default',
                                       'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_group']['id'])
            req.environ['neutron.context'] = context.Context('', 'somebody')
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_update_default_security_group_with_description(self):
        with self.network():
            res = self.new_list_request('security-groups')
            sg = self.deserialize(self.fmt, res.get_response(self.ext_api))
            data = {'security_group': {'description': 'new_desc'}}
            req = self.new_update_request('security-groups',
                                          data,
                                          sg['security_groups'][0]['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['security_group']['description'],
                             data['security_group']['description'])

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
            self.assertEqual(len(groups['security_groups']), 1)

    def test_create_default_security_group_fail(self):
        name = 'default'
        description = 'my webservers'
        res = self._create_security_group(self.fmt, name, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_create_default_security_group_check_case_insensitive(self):
        name = 'DEFAULT'
        description = 'my webservers'
        res = self._create_security_group(self.fmt, name, description)
        self.deserialize(self.fmt, res)
        self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_create_security_group_rule_invalid_ethertype_for_prefix(self):
        name = 'webservers'
        description = 'my webservers'
        test_addr = {'192.168.1.1/24': 'IPv6',
                     '2001:db8:1234::/48': 'IPv4',
                     '192.168.2.1/24': 'BadEthertype'}
        for remote_ip_prefix, ethertype in six.iteritems(test_addr):
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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, 201)
                res_sg = self.deserialize(self.fmt, res)
                prefix = res_sg['security_group_rule']['remote_ip_prefix']
                self.assertEqual(prefix, '%s/%s' % (ip, addr[ip]['mask']))

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
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

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
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix,
                                          ethertype=ethertype) as rule:

                # the lower case value will be return
                self.assertEqual(rule['security_group_rule']['protocol'],
                                 protocol.lower())
                self.assertEqual(rule['security_group_rule']['ethertype'],
                                 const.IPv4)

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
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix):

                group = self.deserialize(
                    self.fmt, res.get_response(self.ext_api))
                sg_rule = group['security_group']['security_group_rules']
                self.assertEqual(group['security_group']['id'],
                                 remote_group_id)
                self.assertEqual(len(sg_rule), 3)
                sg_rule = [r for r in sg_rule if r['direction'] == 'ingress']
                for k, v, in keys:
                    self.assertEqual(sg_rule[0][k], v)

    def test_get_security_group_on_port_from_wrong_tenant(self):
        plugin = manager.NeutronManager.get_plugin()
        if not hasattr(plugin, '_get_security_groups_on_port'):
            self.skipTest("plugin doesn't use the mixin with this method")
        neutron_context = context.get_admin_context()
        res = self._create_security_group(self.fmt, 'webservers', 'webservers',
                                          tenant_id='bad_tenant')
        sg1 = self.deserialize(self.fmt, res)
        with testtools.ExpectedException(ext_sg.SecurityGroupNotFound):
            plugin._get_security_groups_on_port(
                neutron_context,
                {'port': {'security_groups': [sg1['security_group']['id']],
                          'tenant_id': 'tenant'}}
            )

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
            neutron_context = context.Context('', 'test-tenant')
            self._delete('security-groups', sg['security_groups'][0]['id'],
                         webob.exc.HTTPConflict.code,
                         neutron_context=neutron_context)

    def test_security_group_list_creates_default_security_group(self):
        neutron_context = context.Context('', 'test-tenant')
        sg = self._list('security-groups',
                        neutron_context=neutron_context).get('security_groups')
        self.assertEqual(len(sg), 1)

    def test_security_group_port_create_creates_default_security_group(self):
        res = self._create_network(self.fmt, 'net1', True,
                                   tenant_id='not_admin',
                                   set_context=True)
        net1 = self.deserialize(self.fmt, res)
        res = self._create_port(self.fmt, net1['network']['id'],
                                tenant_id='not_admin', set_context=True)
        sg = self._list('security-groups').get('security_groups')
        self.assertEqual(len(sg), 1)

    def test_default_security_group_rules(self):
        with self.network():
            res = self.new_list_request('security-groups')
            groups = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self.assertEqual(len(groups['security_groups']), 1)
            security_group_id = groups['security_groups'][0]['id']
            res = self.new_list_request('security-group-rules')
            rules = self.deserialize(self.fmt, res.get_response(self.ext_api))
            self.assertEqual(len(rules['security_group_rules']), 4)

            # Verify default rule for v4 egress
            sg_rules = rules['security_group_rules']
            rules = [
                r for r in sg_rules
                if r['direction'] == 'egress' and r['ethertype'] == const.IPv4
            ]
            self.assertEqual(len(rules), 1)
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
            self.assertEqual(len(rules), 1)
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
            self.assertEqual(len(rules), 1)
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
            self.assertEqual(len(rules), 1)
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
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

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
                with self.security_group_rule(security_group_id, direction,
                                              protocol, port_range_min,
                                              port_range_max,
                                              remote_group_id=remote_group_id
                                              ) as rule:
                    for k, v, in keys:
                        self.assertEqual(rule['security_group_rule'][k], v)

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
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

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
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

    def test_create_security_group_rule_icmpv6_with_type_only(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            direction = "ingress"
            ethertype = const.IPv6
            remote_ip_prefix = "2001::f401:56ff:fefe:d3dc/128"
            protocol = const.PROTO_NAME_ICMP_V6
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
            with self.security_group_rule(security_group_id, direction,
                                          protocol, port_range_min,
                                          port_range_max,
                                          remote_ip_prefix,
                                          None, None,
                                          ethertype) as rule:
                for k, v, in keys:
                    self.assertEqual(rule['security_group_rule'][k], v)

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
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

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
        self.assertEqual(res.status_int, webob.exc.HTTPNotFound.code)

    def test_create_security_group_rule_duplicate_rules(self):
        name = 'webservers'
        description = 'my webservers'
        with self.security_group(name, description) as sg:
            security_group_id = sg['security_group']['id']
            with self.security_group_rule(security_group_id):
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22')
                self._create_security_group_rule(self.fmt, rule)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

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
                    self.assertEqual(res.status_int,
                                     webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
                    self.assertEqual(res.status_int,
                                     webob.exc.HTTPBadRequest.code)

    def test_list_ports_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                self._create_port(self.fmt, n['network']['id'])
                req = self.new_list_request('ports')
                res = req.get_response(self.api)
                ports = self.deserialize(self.fmt, res)
                port = ports['ports'][0]
                self.assertEqual(len(port[ext_sg.SECURITYGROUPS]), 1)
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
                    self.assertEqual(res['port'][ext_sg.SECURITYGROUPS][0],
                                     sg['security_group']['id'])

                    # Test update port without security group
                    data = {'port': {'fixed_ips': port['port']['fixed_ips'],
                                     'name': port['port']['name']}}

                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(res['port'][ext_sg.SECURITYGROUPS][0],
                                     sg['security_group']['id'])

                    self._delete('ports', port['port']['id'])

    def test_update_port_with_multiple_security_groups(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg1:
                    with self.security_group() as sg2:
                        res = self._create_port(
                            self.fmt, n['network']['id'],
                            security_groups=[sg1['security_group']['id'],
                                             sg2['security_group']['id']])
                        port = self.deserialize(self.fmt, res)
                        self.assertEqual(len(
                            port['port'][ext_sg.SECURITYGROUPS]), 2)
                        self._delete('ports', port['port']['id'])

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
                    self.assertEqual(res['port'].get(ext_sg.SECURITYGROUPS),
                                     [])
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
                    self.assertEqual(res['port'].get(ext_sg.SECURITYGROUPS),
                                     [])
                    self._delete('ports', port['port']['id'])

    def test_create_port_with_bad_security_group(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        security_groups=['bad_id'])

                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_create_delete_security_group_port_in_use(self):
        with self.network() as n:
            with self.subnet(n):
                with self.security_group() as sg:
                    res = self._create_port(self.fmt, n['network']['id'],
                                            security_groups=(
                                                [sg['security_group']['id']]))
                    port = self.deserialize(self.fmt, res)
                    self.assertEqual(port['port'][ext_sg.SECURITYGROUPS][0],
                                     sg['security_group']['id'])
                    # try to delete security group that's in use
                    res = self._delete('security-groups',
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
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)
            self.assertEqual(2, len(ret['security_group_rules']))

    def test_create_security_group_rule_bulk_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('six.moves.builtins.hasattr',
                        new=fakehasattr):
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
                self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

    def test_create_security_group_rule_allow_all_ipv4(self):
        with self.security_group() as sg:
            rule = {'security_group_id': sg['security_group']['id'],
                    'direction': 'ingress',
                    'ethertype': 'IPv4',
                    'tenant_id': 'test-tenant'}

            res = self._create_security_group_rule(
                self.fmt, {'security_group_rule': rule})
            rule = self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

    def test_create_security_group_rule_allow_all_ipv4_v6_bulk(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk "
                          "security_group_rule create")
        with self.security_group() as sg:
            rule_v4 = {'security_group_id': sg['security_group']['id'],
                       'direction': 'ingress',
                       'ethertype': 'IPv4',
                       'tenant_id': 'test-tenant'}
            rule_v6 = {'security_group_id': sg['security_group']['id'],
                       'direction': 'ingress',
                       'ethertype': 'IPv6',
                       'tenant_id': 'test-tenant'}

            rules = {'security_group_rules': [rule_v4, rule_v6]}
            res = self._create_security_group_rule(self.fmt, rules)
            self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, webob.exc.HTTPCreated.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_create_security_group_rule_duplicate_rule_in_post_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('six.moves.builtins.hasattr',
                        new=fakehasattr):

            with self.security_group() as sg:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22', '10.0.0.1/24')
                rules = {'security_group_rules': [rule['security_group_rule'],
                                                  rule['security_group_rule']]}
                res = self._create_security_group_rule(self.fmt, rules)
                rule = self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

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
            self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

    def test_create_security_group_rule_duplicate_rule_db_emulated(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('six.moves.builtins.hasattr',
                        new=fakehasattr):
            with self.security_group() as sg:
                rule = self._build_security_group_rule(
                    sg['security_group']['id'], 'ingress',
                    const.PROTO_NAME_TCP, '22', '22', '10.0.0.1/24')
                rules = {'security_group_rules': [rule]}
                self._create_security_group_rule(self.fmt, rules)
                res = self._create_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPConflict.code)

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
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

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
        self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_create_port_with_non_uuid(self):
        with self.network() as n:
            with self.subnet(n):
                res = self._create_port(self.fmt, n['network']['id'],
                                        security_groups=['not_valid'])

                self.deserialize(self.fmt, res)
                self.assertEqual(res.status_int, webob.exc.HTTPBadRequest.code)

    def test_create_security_group_rule_with_specific_id(self):
        neutron_context = context.Context('', 'test-tenant')
        specified_id = "4cd70774-cc67-4a87-9b39-7d1db38eb087"
        with self.security_group() as sg:
            rule = self._build_security_group_rule(
                sg['security_group']['id'], 'ingress', const.PROTO_NUM_TCP)
            rule['security_group_rule'].update({'id': specified_id,
                                                'port_range_min': None,
                                                'port_range_max': None,
                                                'remote_ip_prefix': None,
                                                'remote_group_id': None})
            result = self.plugin.create_security_group_rule(
                neutron_context, rule)
            self.assertEqual(specified_id, result['id'])


class TestConvertIPPrefixToCIDR(base.BaseTestCase):

    def test_convert_bad_ip_prefix_to_cidr(self):
        for val in ['bad_ip', 256, "2001:db8:a::123/129"]:
            self.assertRaises(n_exc.InvalidCIDR,
                              ext_sg.convert_ip_prefix_to_cidr, val)
        self.assertIsNone(ext_sg.convert_ip_prefix_to_cidr(None))

    def test_convert_ip_prefix_no_netmask_to_cidr(self):
        addr = {'10.1.2.3': '32', 'fe80::2677:3ff:fe7d:4c': '128'}
        for k, v in six.iteritems(addr):
            self.assertEqual(ext_sg.convert_ip_prefix_to_cidr(k),
                             '%s/%s' % (k, v))

    def test_convert_ip_prefix_with_netmask_to_cidr(self):
        addresses = ['10.1.0.0/16', '10.1.2.3/32', '2001:db8:1234::/48']
        for addr in addresses:
            self.assertEqual(ext_sg.convert_ip_prefix_to_cidr(addr), addr)


class TestConvertProtocol(base.BaseTestCase):
    def test_convert_numeric_protocol(self):
        self.assertIsInstance(ext_sg.convert_protocol('2'), str)

    def test_convert_bad_protocol(self):
        for val in ['bad', '256', '-1']:
            self.assertRaises(ext_sg.SecurityGroupRuleInvalidProtocol,
                              ext_sg.convert_protocol, val)

    def test_convert_numeric_protocol_to_string(self):
        self.assertIsInstance(ext_sg.convert_protocol(2), str)
