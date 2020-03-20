# Copyright (c) 2013 OpenStack Foundation.
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

from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api import validators
from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory
from oslo_config import cfg
from webob import exc as web_exc

from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import portsecurity_db
from neutron.extensions import securitygroup as secgroup
from neutron.tests.unit.db import test_db_base_plugin_v2


DB_PLUGIN_KLASS = ('neutron.tests.unit.db.test_allowedaddresspairs_db.'
                   'AllowedAddressPairTestPlugin')


class AllowedAddressPairTestCase(
        test_db_base_plugin_v2.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        super(AllowedAddressPairTestCase, self).setUp(plugin)

        # Check if a plugin supports security groups
        plugin_obj = directory.get_plugin()
        self._skip_port_security = ('port-security' not in
                                    plugin_obj.supported_extension_aliases)


class AllowedAddressPairTestPlugin(portsecurity_db.PortSecurityDbMixin,
                                   db_base_plugin_v2.NeutronDbPluginV2,
                                   addr_pair_db.AllowedAddressPairsMixin):

    """Test plugin that implements necessary calls on create/delete port for
    associating ports with port security and allowed address pairs.
    """

    supported_extension_aliases = [addr_apidef.ALIAS]

    def create_port(self, context, port):
        p = port['port']
        with db_api.CONTEXT_WRITER.using(context):
            neutron_db = super(AllowedAddressPairTestPlugin, self).create_port(
                context, port)
            p.update(neutron_db)
            if validators.is_attr_set(p.get(addr_apidef.ADDRESS_PAIRS)):
                self._process_create_allowed_address_pairs(
                    context, p,
                    p[addr_apidef.ADDRESS_PAIRS])
            else:
                p[addr_apidef.ADDRESS_PAIRS] = None

        return port['port']

    def update_port(self, context, id, port):
        delete_addr_pairs = self._check_update_deletes_allowed_address_pairs(
            port)
        has_addr_pairs = self._check_update_has_allowed_address_pairs(port)

        with db_api.CONTEXT_WRITER.using(context):
            ret_port = super(AllowedAddressPairTestPlugin, self).update_port(
                context, id, port)
            # copy values over - but not fixed_ips
            port['port'].pop('fixed_ips', None)
            ret_port.update(port['port'])

            if (delete_addr_pairs or has_addr_pairs):
                # delete address pairs and readd them
                self._delete_allowed_address_pairs(context, id)
                self._process_create_allowed_address_pairs(
                    context, ret_port,
                    ret_port[addr_apidef.ADDRESS_PAIRS])

        return ret_port


class AllowedAddressPairDBTestCase(AllowedAddressPairTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        plugin = plugin or DB_PLUGIN_KLASS
        super(AllowedAddressPairDBTestCase,
              self).setUp(plugin=plugin, ext_mgr=ext_mgr)


class TestAllowedAddressPairs(AllowedAddressPairDBTestCase):

    def test_create_port_allowed_address_pairs_bad_format(self):
        with self.network() as net:
            bad_values = [False, True, 1.1, 1, ['ip_address'],
                          ['mac_address']]
            for value in bad_values:
                self._create_port(
                    self.fmt, net['network']['id'],
                    expected_res_status=web_exc.HTTPBadRequest.code,
                    arg_list=(addr_apidef.ADDRESS_PAIRS,),
                    allowed_address_pairs=value)

    def test_create_port_allowed_address_pairs(self):
        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_apidef.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertEqual(port['port'][addr_apidef.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_create_port_security_true_allowed_address_pairs(self):
        if self._skip_port_security:
            self.skipTest("Plugin does not implement port-security extension")

        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_apidef.ADDRESS_PAIRS,),
                                    port_security_enabled=True,
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertTrue(port['port'][psec.PORTSECURITY])
            self.assertEqual(port['port'][addr_apidef.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_create_port_security_false_allowed_address_pairs(self):
        if self._skip_port_security:
            self.skipTest("Plugin does not implement port-security extension")

        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_apidef.ADDRESS_PAIRS,),
                                    port_security_enabled=False,
                                    allowed_address_pairs=address_pairs)
            self.deserialize(self.fmt, res)
            self.assertEqual(409, res.status_int)

            address_pairs = []
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_apidef.ADDRESS_PAIRS,),
                                    port_security_enabled=False,
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertFalse(port['port'][psec.PORTSECURITY])
            self.assertEqual(port['port'][addr_apidef.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_create_port_bad_mac(self):
        address_pairs = [{'mac_address': 'invalid_mac',
                          'ip_address': '10.0.0.1'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_port_bad_ip(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1222'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_missing_mac_field(self):
        address_pairs = [{'ip_address': '10.0.0.1'}]
        self._create_port_with_address_pairs(address_pairs, 201)

    def test_create_missing_ip_field(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_duplicate_mac_ip(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1'},
                         {'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_more_than_max_allowed_address_pair(self):
        cfg.CONF.set_default('max_allowed_address_pair', 3)
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1'},
                         {'mac_address': '00:00:00:00:00:02',
                          'ip_address': '10.0.0.2'},
                         {'mac_address': '00:00:00:00:00:03',
                          'ip_address': '10.0.0.3'},
                         {'mac_address': '00:00:00:00:00:04',
                          'ip_address': '10.0.0.4'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_equal_to_max_allowed_address_pair(self):
        cfg.CONF.set_default('max_allowed_address_pair', 3)
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1'},
                         {'mac_address': '00:00:00:00:00:02',
                          'ip_address': '10.0.0.2'},
                         {'mac_address': '00:00:00:00:00:03',
                          'ip_address': '10.0.0.3'}]
        self._create_port_with_address_pairs(address_pairs, 201)

    def test_create_overlap_with_fixed_ip(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.2'}]
        with self.network() as network:
            with self.subnet(network=network, cidr='10.0.0.0/24') as subnet:
                fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                              'ip_address': '10.0.0.2'}]
                res = self._create_port(self.fmt, network['network']['id'],
                                        arg_list=(addr_apidef.ADDRESS_PAIRS,
                                        'fixed_ips'),
                                        allowed_address_pairs=address_pairs,
                                        fixed_ips=fixed_ips)
                self.assertEqual(res.status_int, 201)
                port = self.deserialize(self.fmt, res)
                self._delete('ports', port['port']['id'])

    def test_create_port_extra_args(self):
        address_pairs = [{'mac_address': '00:00:00:00:00:01',
                          'ip_address': '10.0.0.1',
                          'icbb': 'agreed'}]
        self._create_port_with_address_pairs(address_pairs, 400)

    def test_create_port_with_unexpected_address_pairs_format(self):
        address_pairs = {'mac_address': '00:00:00:00:00:01',
                         'ip_address': '10.0.0.1'}
        self._create_port_with_address_pairs(address_pairs, 400)

    def _create_port_with_address_pairs(self, address_pairs, ret_code):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_apidef.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            self.assertEqual(res.status_int, ret_code)
            if ret_code == 201:
                self._delete('ports', port['port']['id'])

    def test_update_port_allowed_address_pairs_bad_format(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            bad_values = [False, True, 1.1, 1, ['ip_address'],
                          ['mac_address']]
            for value in bad_values:
                update_port = {'port': {addr_apidef.ADDRESS_PAIRS: value}}
                req = self.new_update_request('ports', update_port,
                                              port['port']['id'])
                res = req.get_response(self.api)
                self.assertEqual(400, res.status_int)

    def test_update_add_address_pairs(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            update_port = {'port': {addr_apidef.ADDRESS_PAIRS:
                                    address_pairs}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual(port['port'][addr_apidef.ADDRESS_PAIRS],
                             address_pairs)
            self._delete('ports', port['port']['id'])

    def test_update_add_address_pairs_with_unexpected_format(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            address_pairs = {'mac_address': '00:00:00:00:00:01',
                             'ip_address': '10.0.0.1'}
            update_port = {'port': {addr_apidef.ADDRESS_PAIRS:
                                    address_pairs}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(400, res.status_int)

    def test_create_address_gets_port_mac(self):
        with self.network() as net:
            address_pairs = [{'ip_address': '23.23.23.23'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=('port_security_enabled',
                                              addr_apidef.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)['port']
            port_addr_mac = port[addr_apidef.ADDRESS_PAIRS][0]['mac_address']
            self.assertEqual(port_addr_mac,
                             port['mac_address'])
            self._delete('ports', port['id'])

    def test_update_port_security_off_address_pairs(self):
        if self._skip_port_security:
            self.skipTest("Plugin does not implement port-security extension")
        with self.network() as net:
            with self.subnet(network=net) as subnet:
                address_pairs = [{'mac_address': '00:00:00:00:00:01',
                                  'ip_address': '10.0.0.1'}]
                # The port should not have any security-groups associated to it
                with self.port(subnet=subnet,
                               arg_list=(psec.PORTSECURITY,
                                         addr_apidef.ADDRESS_PAIRS,
                                         secgroup.SECURITYGROUPS),
                               port_security_enabled=True,
                               allowed_address_pairs=address_pairs,
                               security_groups=[]) as port:

                    update_port = {'port': {psec.PORTSECURITY: False}}
                    req = self.new_update_request('ports', update_port,
                                                  port['port']['id'])
                    res = req.get_response(self.api)
                    self.assertEqual(409, res.status_int)

    def test_update_with_none_and_own_mac_for_duplicate_ip(self):
        with self.network() as net:
            res = self._create_port(self.fmt, net['network']['id'])
            port = self.deserialize(self.fmt, res)
            mac_address = port['port']['mac_address']
            address_pairs = [{'ip_address': '10.0.0.1'},
                             {'mac_address': mac_address,
                              'ip_address': '10.0.0.1'}]
            update_port = {'port': {addr_apidef.ADDRESS_PAIRS:
                                    address_pairs}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(400, res.status_int)

    def test_create_port_remove_allowed_address_pairs_with_list(self):
        self._test_create_port_remove_allowed_address_pairs([])

    def test_create_port_remove_allowed_address_pairs_with_none(self):
        self._test_create_port_remove_allowed_address_pairs(None)

    def _test_create_port_remove_allowed_address_pairs(self, update_value):
        with self.network() as net:
            address_pairs = [{'mac_address': '00:00:00:00:00:01',
                              'ip_address': '10.0.0.1'}]
            res = self._create_port(self.fmt, net['network']['id'],
                                    arg_list=(addr_apidef.ADDRESS_PAIRS,),
                                    allowed_address_pairs=address_pairs)
            port = self.deserialize(self.fmt, res)
            update_port = {'port': {addr_apidef.ADDRESS_PAIRS: update_value}}
            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            port = self.deserialize(self.fmt, req.get_response(self.api))
            self.assertEqual([], port['port'][addr_apidef.ADDRESS_PAIRS])
            self._delete('ports', port['port']['id'])
