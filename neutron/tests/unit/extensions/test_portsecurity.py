# Copyright (c) 2012 OpenStack Foundation.
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

import copy
from unittest import mock

from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api import validators
from neutron_lib.db import api as db_api
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import port_security as psec_exc
from neutron_lib.plugins import directory
from webob import exc

from neutron.common.ovn import utils as ovn_utils
from neutron.db import db_base_plugin_v2
from neutron.db import portsecurity_db
from neutron.db import securitygroups_db
from neutron.extensions import securitygroup as ext_sg
from neutron import quota
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_securitygroup

DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_portsecurity.'
                   'PortSecurityTestPlugin')


class PortSecurityTestCase(test_securitygroup.SecurityGroupsTestCase,
                           test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=None):
        self._backup = copy.deepcopy(ext_sg.RESOURCE_ATTRIBUTE_MAP)
        self.addCleanup(self._restore)
        ext_mgr = (
            test_securitygroup.SecurityGroupTestExtensionManager())
        super(PortSecurityTestCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr)

        # Check if a plugin supports security groups
        plugin_obj = directory.get_plugin()
        self._skip_security_group = ('security-group' not in
                                     plugin_obj.supported_extension_aliases)

    def _restore(self):
        ext_sg.RESOURCE_ATTRIBUTE_MAP = self._backup


class PortSecurityTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             securitygroups_db.SecurityGroupDbMixin,
                             portsecurity_db.PortSecurityDbMixin):

    """Test plugin that implements necessary calls on create/delete port for
    associating ports with security groups and port security.
    """

    supported_extension_aliases = ["security-group", psec.ALIAS]

    def create_network(self, context, network):
        with db_api.CONTEXT_WRITER.using(context):
            tenant_id = network['network'].get('tenant_id')
            self._ensure_default_security_group(context, tenant_id)
            neutron_db = super(PortSecurityTestPlugin, self).create_network(
                context, network)
            neutron_db.update(network['network'])
            self._process_network_port_security_create(
                context, network['network'], neutron_db)
        return neutron_db

    def update_network(self, context, id, network):
        with db_api.CONTEXT_WRITER.using(context):
            neutron_db = super(PortSecurityTestPlugin, self).update_network(
                context, id, network)
            if psec.PORTSECURITY in network['network']:
                self._process_network_port_security_update(
                    context, network['network'], neutron_db)
        return neutron_db

    def get_network(self, context, id, fields=None):
        with db_api.CONTEXT_READER.using(context):
            net = super(PortSecurityTestPlugin, self).get_network(
                context, id)
        return db_utils.resource_fields(net, fields)

    def create_port(self, context, port):
        p = port['port']
        neutron_db = super(PortSecurityTestPlugin, self).create_port(
            context, port)
        p.update(neutron_db)

        (port_security, has_ip) = self._determine_port_security_and_has_ip(
            context, p)
        p[psec.PORTSECURITY] = port_security
        self._process_port_port_security_create(context, p, neutron_db)

        if (validators.is_attr_set(p.get(ext_sg.SECURITYGROUPS)) and
                not (port_security and has_ip)):
            raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()

        # Port requires ip and port_security enabled for security group
        if has_ip and port_security:
            self._ensure_default_security_group_on_port(context, port)

        sgs = self._get_security_groups_on_port(context, port)
        p[ext_sg.SECURITYGROUPS] = [sg['id'] for sg in sgs] if sgs else None

        if (p.get(ext_sg.SECURITYGROUPS) and p[psec.PORTSECURITY]):
            with db_api.CONTEXT_WRITER.using(context):
                self._process_port_create_security_group(context, p, sgs)

        return port['port']

    def update_port(self, context, id, port):
        delete_security_groups = self._check_update_deletes_security_groups(
            port)
        has_security_groups = self._check_update_has_security_groups(port)
        with db_api.CONTEXT_WRITER.using(context):
            ret_port = super(PortSecurityTestPlugin, self).update_port(
                context, id, port)
            # copy values over - but not fixed_ips
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])

            # populate port_security setting
            if psec.PORTSECURITY not in ret_port:
                ret_port[psec.PORTSECURITY] = self._get_port_security_binding(
                    context, id)
            has_ip = self._ip_on_port(ret_port)
            # checks if security groups were updated adding/modifying
            # security groups, port security is set and port has ip
            if (has_security_groups and (not ret_port[psec.PORTSECURITY] or
                                         not has_ip)):
                raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()

            # Port security/IP was updated off. Need to check that no security
            # groups are on port.
            if ret_port[psec.PORTSECURITY] is not True or not has_ip:
                if has_security_groups:
                    raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()

                # get security groups on port
                filters = {'port_id': [id]}
                security_groups = (super(PortSecurityTestPlugin, self).
                                   _get_port_security_group_bindings(
                                       context, filters))
                if security_groups and not delete_security_groups:
                    raise psec_exc.PortSecurityPortHasSecurityGroup()

            if (delete_security_groups or has_security_groups):
                # delete the port binding and read it with the new rules.
                self._delete_port_security_group_bindings(context, id)
                sgs = self._get_security_groups_on_port(context, port)
                # process port create sec groups needs port id
                port['id'] = id
                self._process_port_create_security_group(context,
                                                         ret_port, sgs)

            if psec.PORTSECURITY in port['port']:
                self._process_port_port_security_update(
                    context, port['port'], ret_port)

        return ret_port


class PortSecurityDBTestCase(PortSecurityTestCase):
    def setUp(self, plugin=None, service_plugins=None):
        plugin = plugin or DB_PLUGIN_KLASS
        super(PortSecurityDBTestCase, self).setUp(plugin)


class TestPortSecurity(PortSecurityDBTestCase):

    def setUp(self, plugin=None, service_plugins=None):
        super().setUp(plugin)
        make_res = mock.patch.object(quota.QuotaEngine, 'make_reservation')
        commit_res = mock.patch.object(quota.QuotaEngine, 'commit_reservation')
        self.mock_quota_make_res = make_res.start()
        self.mock_quota_commit_res = commit_res.start()
        self.mock_vp_parents = mock.patch.object(
            ovn_utils, 'get_virtual_port_parents', return_value=None).start()

    def test_create_network_with_portsecurity_mac(self):
        res = self._create_network('json', 'net1', True)
        net = self.deserialize('json', res)
        self.assertTrue(net['network'][psec.PORTSECURITY])

    def test_create_network_with_portsecurity_false(self):
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        self.assertFalse(net['network'][psec.PORTSECURITY])

    def test_updating_network_port_security(self):
        res = self._create_network('json', 'net1', True,
                                   port_security_enabled='True')
        net = self.deserialize('json', res)
        self.assertTrue(net['network'][psec.PORTSECURITY])
        update_net = {'network': {psec.PORTSECURITY: False}}
        req = self.new_update_request('networks', update_net,
                                      net['network']['id'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertFalse(net['network'][psec.PORTSECURITY])
        req = self.new_show_request('networks', net['network']['id'])
        net = self.deserialize('json', req.get_response(self.api))
        self.assertFalse(net['network'][psec.PORTSECURITY])

    def test_create_port_default_true(self):
        with self.network() as net:
            res = self._create_port('json', net['network']['id'])
            port = self.deserialize('json', res)
            self.assertTrue(port['port'][psec.PORTSECURITY])
            self._delete('ports', port['port']['id'])

    def test_create_port_passing_true(self):
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=True)
        net = self.deserialize('json', res)
        res = self._create_port('json', net['network']['id'])
        port = self.deserialize('json', res)
        self.assertTrue(port['port'][psec.PORTSECURITY])
        self._delete('ports', port['port']['id'])

    def test_create_port_on_port_security_false_network(self):
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        res = self._create_port('json', net['network']['id'])
        port = self.deserialize('json', res)
        self.assertFalse(port['port'][psec.PORTSECURITY])
        self._delete('ports', port['port']['id'])

    def test_create_port_security_overrides_network_value(self):
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        res = self._create_port('json', net['network']['id'],
                                arg_list=('port_security_enabled',),
                                port_security_enabled=True)
        port = self.deserialize('json', res)
        self.assertTrue(port['port'][psec.PORTSECURITY])
        self._delete('ports', port['port']['id'])

    def test_create_port_fails_with_secgroup_and_port_security_false(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                security_group = self.deserialize(
                    'json',
                    self._create_security_group(self.fmt, 'asdf', 'asdf'))
                security_group_id = security_group['security_group']['id']
                res = self._create_port('json', net['network']['id'],
                                        arg_list=('security_groups',
                                                  'port_security_enabled'),
                                        security_groups=[security_group_id],
                                        port_security_enabled=False)
                self.assertEqual(400, res.status_int)

    def test_create_port_with_default_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'])
                port = self.deserialize('json', res)
                self.assertTrue(port['port'][psec.PORTSECURITY])
                self.assertEqual(1, len(port['port'][ext_sg.SECURITYGROUPS]))
                self._delete('ports', port['port']['id'])

    def test_create_port_with_security_group_and_net_sec_false(self):
        # This tests that port_security_enabled is true when creating
        # a port on a network that is marked as port_security_enabled=False
        # that has a subnet and security_groups are passed it.
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        self._create_subnet('json', net['network']['id'], '10.0.0.0/24')
        security_group = self.deserialize(
            'json', self._create_security_group(self.fmt, 'asdf', 'asdf'))
        security_group_id = security_group['security_group']['id']
        res = self._create_port('json', net['network']['id'],
                                arg_list=('security_groups',
                                    'port_security_enabled'),
                                port_security_enabled=True,
                                security_groups=[security_group_id])
        port = self.deserialize('json', res)
        self.assertTrue(port['port'][psec.PORTSECURITY])
        self.assertEqual(port['port']['security_groups'], [security_group_id])
        self._delete('ports', port['port']['id'])

    def test_create_port_with_admin_use_other_tenant_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   tenant_id='admin_tenant',
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        self._create_subnet('json', net['network']['id'], '10.0.0.0/24',
                            tenant_id='admin_tenant')
        security_group = self.deserialize(
            'json', self._create_security_group(self.fmt, 'asdf', 'asdf',
                                                tenant_id='other_tenant'))
        security_group_id = security_group['security_group']['id']
        res = self._create_port('json', net['network']['id'],
                                arg_list=('security_groups',
                                    'port_security_enabled'),
                                is_admin=True,
                                tenant_id='admin_tenant',
                                port_security_enabled=True,
                                security_groups=[security_group_id])
        port = self.deserialize('json', res)
        self.assertTrue(port['port'][psec.PORTSECURITY])
        self.assertEqual(port['port']['security_groups'], [security_group_id])
        self._delete('ports', port['port']['id'], tenant_id='admin_tenant')

    def test_create_port_with_no_admin_use_other_tenant_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   tenant_id='demo_tenant',
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        self._create_subnet('json', net['network']['id'], '10.0.0.0/24',
                            tenant_id='demo_tenant')
        security_group = self.deserialize(
            'json', self._create_security_group(self.fmt, 'asdf', 'asdf',
                                                tenant_id='other_tenant'))
        security_group_id = security_group['security_group']['id']
        res = self._create_port('json', net['network']['id'],
                                arg_list=('security_groups',
                                    'port_security_enabled'),
                                tenant_id='demo_tenant',
                                port_security_enabled=True,
                                security_groups=[security_group_id])
        self.assertEqual(404, res.status_int)

    def test_create_port_without_security_group_and_net_sec_false(self):
        res = self._create_network('json', 'net1', True,
                                   arg_list=('port_security_enabled',),
                                   port_security_enabled=False)
        net = self.deserialize('json', res)
        self._create_subnet('json', net['network']['id'], '10.0.0.0/24')
        res = self._create_port('json', net['network']['id'])
        port = self.deserialize('json', res)
        self.assertFalse(port['port'][psec.PORTSECURITY])
        self._delete('ports', port['port']['id'])

    def test_update_port_security_off_with_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'])
                port = self.deserialize('json', res)
                self.assertTrue(port['port'][psec.PORTSECURITY])

                update_port = {'port': {psec.PORTSECURITY: False}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(409, res.status_int)
                # remove security group on port
                update_port = {'port': {ext_sg.SECURITYGROUPS: None}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])

                self.deserialize('json', req.get_response(self.api))
                self._delete('ports', port['port']['id'])

    def test_update_port_with_admin_use_other_tenant_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'],
                                        is_admin=True,
                                        tenant_id='admin_tenant',)
                port = self.deserialize('json', res)
                self.assertTrue(port['port'][psec.PORTSECURITY])

                security_group = self.deserialize('json',
                    self._create_security_group(self.fmt, 'asdf', 'asdf',
                                                tenant_id='other_tenant'))
                security_group_id = security_group['security_group']['id']
                update_port = {'port':
                               {'security_groups': [security_group_id]}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'],
                                              tenant_id='admin_tenant',
                                              as_admin=True)
                port = self.deserialize('json', req.get_response(self.api))
                security_groups = port['port']['security_groups']
                self.assertIn(security_group_id, security_groups)
                self._delete('ports', port['port']['id'])

    def test_update_port_with_no_admin_use_other_tenant_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network(tenant_id='demo_tenant') as net:
            with self.subnet(network=net, tenant_id='demo_tenant'):
                res = self._create_port('json', net['network']['id'],
                                        tenant_id='demo_tenant',)
                port = self.deserialize('json', res)
                self.assertTrue(port['port'][psec.PORTSECURITY])

                security_group = self.deserialize('json',
                    self._create_security_group(self.fmt, 'asdf', 'asdf',
                                                tenant_id='other_tenant'))
                security_group_id = security_group['security_group']['id']
                update_port = {'port':
                               {'security_groups': [security_group_id]}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'],
                                              tenant_id='other_tenant')
                res = req.get_response(self.api)
                self.assertEqual(404, res.status_int)

    def test_update_port_remove_port_security_security_group(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'],
                                        arg_list=('port_security_enabled',),
                                        port_security_enabled=True)
                port = self.deserialize('json', res)
                self.assertTrue(port['port'][psec.PORTSECURITY])

                # remove security group on port
                update_port = {'port': {ext_sg.SECURITYGROUPS: None,
                                        psec.PORTSECURITY: False}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])
                port = self.deserialize('json', req.get_response(self.api))
                self.assertFalse(port['port'][psec.PORTSECURITY])
                self.assertEqual(0, len(port['port'][ext_sg.SECURITYGROUPS]))
                self._delete('ports', port['port']['id'])

    def test_update_port_remove_port_security_security_group_read(self):
        if self._skip_security_group:
            self.skipTest("Plugin does not support security groups")
        with self.network() as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'],
                                        arg_list=('port_security_enabled',),
                                        port_security_enabled=True)
                port = self.deserialize('json', res)
                self.assertTrue(port['port'][psec.PORTSECURITY])

                # remove security group on port
                update_port = {'port': {ext_sg.SECURITYGROUPS: None,
                                        psec.PORTSECURITY: False}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])
                self.deserialize('json', req.get_response(self.api))

                sg_id = port['port'][ext_sg.SECURITYGROUPS]
                update_port = {'port': {ext_sg.SECURITYGROUPS: [sg_id[0]],
                                        psec.PORTSECURITY: True}}

                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])

                port = self.deserialize('json', req.get_response(self.api))
                self.assertTrue(port['port'][psec.PORTSECURITY])
                self.assertEqual(1, len(port['port'][ext_sg.SECURITYGROUPS]))
                self._delete('ports', port['port']['id'])

    def test_create_port_security_off_shared_network(self):
        with self.network(as_admin=True, shared=True) as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'],
                                        arg_list=('port_security_enabled',),
                                        port_security_enabled=False,
                                        tenant_id='not_network_owner')
                self.deserialize('json', res)
                self.assertEqual(403, res.status_int)

    def test_update_port_security_off_shared_network(self):
        with self.network(as_admin=True, shared=True) as net:
            with self.subnet(network=net):
                res = self._create_port('json', net['network']['id'],
                                        tenant_id='not_network_owner')
                port = self.deserialize('json', res)
                # remove security group on port
                update_port = {'port': {ext_sg.SECURITYGROUPS: None,
                                        psec.PORTSECURITY: False}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'],
                                              tenant_id='not_network_owner')
                res = req.get_response(self.api)
                self.assertEqual(exc.HTTPForbidden.code, res.status_int)
