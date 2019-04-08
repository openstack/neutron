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

import copy

from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib import constants
import webob.exc

from neutron.db import db_base_plugin_v2
from neutron.db import extradhcpopt_db as edo_db
from neutron.tests.unit.db import test_db_base_plugin_v2


DB_PLUGIN_KLASS = (
    'neutron.tests.unit.extensions.test_extra_dhcp_opt.ExtraDhcpOptTestPlugin')


class ExtraDhcpOptTestPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                             edo_db.ExtraDhcpOptMixin):
    """Test plugin that implements necessary calls on create/delete port for
    associating ports with extra dhcp options.
    """

    supported_extension_aliases = [edo_ext.ALIAS]

    def create_port(self, context, port):
        with context.session.begin(subtransactions=True):
            edos = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            new_port = super(ExtraDhcpOptTestPlugin, self).create_port(
                context, port)
            self._process_port_create_extra_dhcp_opts(context, new_port, edos)
        return new_port

    def update_port(self, context, id, port):
        with context.session.begin(subtransactions=True):
            rtn_port = super(ExtraDhcpOptTestPlugin, self).update_port(
                context, id, port)
            self._update_extra_dhcp_opts_on_port(context, id, port, rtn_port)
        return rtn_port


class ExtraDhcpOptDBTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self, plugin=DB_PLUGIN_KLASS):
        super(ExtraDhcpOptDBTestCase, self).setUp(plugin=plugin)


class TestExtraDhcpOpt(ExtraDhcpOptDBTestCase):
    def _check_opts(self, expected, returned):
        self.assertEqual(len(expected), len(returned))
        for opt in returned:
            name = opt['opt_name']
            for exp in expected:
                if (name == exp['opt_name'] and
                    opt['ip_version'] == exp.get(
                        'ip_version', constants.IP_VERSION_4)):
                    val = exp['opt_value']
                    break
            self.assertEqual(val, opt['opt_value'])

    def test_create_port_with_extradhcpopts(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_create_port_with_none_extradhcpopts(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': None},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'}]
        expected = [{'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(expected,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_create_port_with_empty_router_extradhcpopts(self):
        opt_list = [{'opt_name': 'router',
                     'opt_value': ''},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_create_port_with_extradhcpopts_ipv4_opt_version(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0',
                     'ip_version': constants.IP_VERSION_4},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456',
                     'ip_version': constants.IP_VERSION_4},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123',
                     'ip_version': constants.IP_VERSION_4}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_create_port_with_extradhcpopts_ipv6_opt_version(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0',
                     'ip_version': constants.IP_VERSION_6},
                    {'opt_name': 'tftp-server',
                     'opt_value': '2001:192:168::1',
                     'ip_version': constants.IP_VERSION_6}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            self._check_opts(opt_list,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def _test_update_port_with_extradhcpopts(self, opt_list, upd_opts,
                                             expected_opts):
        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPOk.code, res.status_int)
            port = self.deserialize('json', res)
            self._check_opts(expected_opts,
                             port['port'][edo_ext.EXTRADHCPOPTS])

    def test_update_port_with_extradhcpopts_with_same(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        expected_opts = opt_list[:]
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_additional_extradhcpopt(self):
        opt_list = [{'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        expected_opts = copy.deepcopy(opt_list)
        expected_opts.append(upd_opts[0])
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_extradhcpopts(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'changeme.0'}]
        expected_opts = copy.deepcopy(opt_list)
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_extradhcpopt_delete(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': None}]
        expected_opts = []

        expected_opts = [opt for opt in opt_list
                         if opt['opt_name'] != 'bootfile-name']
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_without_extradhcpopt_delete(self):
        opt_list = []
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': None}]
        expected_opts = []
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_adding_extradhcpopts(self):
        opt_list = []
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        expected_opts = copy.deepcopy(upd_opts)
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_blank_string_extradhcpopt(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': 'bootfile-name', 'opt_value': '    '}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_port_with_blank_name_extradhcpopt(self):
        opt_list = [{'opt_name': 'bootfile-name', 'opt_value': 'pxelinux.0'},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123'},
                    {'opt_name': 'server-ip-address',
                     'opt_value': '123.123.123.456'}]
        upd_opts = [{'opt_name': '     ', 'opt_value': 'pxelinux.0'}]

        params = {edo_ext.EXTRADHCPOPTS: opt_list,
                  'arg_list': (edo_ext.EXTRADHCPOPTS,)}

        with self.port(**params) as port:
            update_port = {'port': {edo_ext.EXTRADHCPOPTS: upd_opts}}

            req = self.new_update_request('ports', update_port,
                                          port['port']['id'])
            res = req.get_response(self.api)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_update_port_with_blank_router_extradhcpopt(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0',
                     'ip_version': constants.IP_VERSION_4},
                    {'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123',
                     'ip_version': constants.IP_VERSION_4},
                    {'opt_name': 'router',
                     'opt_value': '123.123.123.1',
                     'ip_version': constants.IP_VERSION_4}]
        upd_opts = [{'opt_name': 'router',
                     'opt_value': '',
                     'ip_version': constants.IP_VERSION_4}]
        expected_opts = copy.deepcopy(opt_list)
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break

        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_extradhcpopts_ipv6_change_value(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0',
                     'ip_version': constants.IP_VERSION_6},
                    {'opt_name': 'tftp-server',
                     'opt_value': '2001:192:168::1',
                     'ip_version': constants.IP_VERSION_6}]
        upd_opts = [{'opt_name': 'tftp-server',
                     'opt_value': '2001:192:168::2',
                     'ip_version': constants.IP_VERSION_6}]
        expected_opts = copy.deepcopy(opt_list)
        for i in expected_opts:
            if i['opt_name'] == upd_opts[0]['opt_name']:
                i['opt_value'] = upd_opts[0]['opt_value']
                break
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)

    def test_update_port_with_extradhcpopts_add_another_ver_opt(self):
        opt_list = [{'opt_name': 'bootfile-name',
                     'opt_value': 'pxelinux.0',
                     'ip_version': constants.IP_VERSION_6},
                    {'opt_name': 'tftp-server',
                     'opt_value': '2001:192:168::1',
                     'ip_version': constants.IP_VERSION_6}]
        upd_opts = [{'opt_name': 'tftp-server',
                     'opt_value': '123.123.123.123',
                     'ip_version': constants.IP_VERSION_4}]
        expected_opts = copy.deepcopy(opt_list)
        expected_opts.extend(upd_opts)
        self._test_update_port_with_extradhcpopts(opt_list, upd_opts,
                                                  expected_opts)
