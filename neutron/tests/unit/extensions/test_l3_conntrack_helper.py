# Copyright 2021 Troila
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

from unittest import mock

from webob import exc

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_conntrack_helper as l3_ct
from oslo_utils import uuidutils

from neutron.extensions import l3
from neutron.extensions import l3_conntrack_helper
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.extensions import test_l3

_uuid = uuidutils.generate_uuid


class TestL3ConntrackHelperServicePlugin(test_l3.TestL3NatServicePlugin):
    supported_extension_aliases = [l3_apidef.ALIAS, l3_ct.ALIAS]


class ExtendL3ConntrackHelperExtensionManager(object):

    def get_resources(self):
        return (l3.L3.get_resources() +
                l3_conntrack_helper.L3_conntrack_helper.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class L3NConntrackHelperTestCase(test_l3.L3BaseForIntTests,
                                 test_l3.L3NatTestCaseMixin):
    tenant_id = _uuid()
    fmt = "json"

    def setUp(self):
        mock.patch('neutron.api.rpc.handlers.resources_rpc.'
                   'ResourcesPushRpcApi').start()
        svc_plugins = ('neutron.services.conntrack_helper.plugin.Plugin',
                       'neutron.tests.unit.extensions.'
                       'test_l3_conntrack_helper.'
                       'TestL3ConntrackHelperServicePlugin')
        plugin = ('neutron.tests.unit.extensions.test_l3.TestL3NatIntPlugin')
        ext_mgr = ExtendL3ConntrackHelperExtensionManager()
        super(L3NConntrackHelperTestCase, self).setUp(
              ext_mgr=ext_mgr, service_plugins=svc_plugins, plugin=plugin)
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def _create_router_conntrack_helper(self, fmt, router_id,
                                        protocol, port, helper):
        data = {'conntrack_helper': {
            "protocol": protocol,
            "port": port,
            "helper": helper}
        }
        router_ct_req = self.new_create_request(
            'routers', data,
            fmt or self.fmt, id=router_id,
            subresource='conntrack_helpers',
            as_admin=True)

        return router_ct_req.get_response(self.ext_api)

    def _update_router_conntrack_helper(self, fmt, router_id,
                                        conntrack_helper_id, **kwargs):
        conntrack_helper = {}
        for k, v in kwargs.items():
            conntrack_helper[k] = v
        data = {'conntrack_helper': conntrack_helper}

        router_ct_req = self.new_update_request(
            'routers', data, router_id,
            fmt or self.fmt, sub_id=conntrack_helper_id,
            subresource='conntrack_helpers', as_admin=True)
        return router_ct_req.get_response(self.ext_api)

    def test_create_ct_with_duplicate_entry(self):
        with self.router() as router:
            ct1 = self._create_router_conntrack_helper(
                self.fmt, router['router']['id'],
                "udp", 69, "tftp")
            self.assertEqual(exc.HTTPCreated.code, ct1.status_code)
            ct2 = self._create_router_conntrack_helper(
                self.fmt, router['router']['id'],
                "udp", 69, "tftp")
            self.assertEqual(exc.HTTPBadRequest.code, ct2.status_code)
            expect_msg = ("Bad conntrack_helper request: A duplicate "
                          "conntrack helper entry with same attributes "
                          "already exists, conflicting values are "
                          "{'router_id': '%s', 'protocol': 'udp', "
                          "'port': 69, 'helper': "
                          "'tftp'}.") % router['router']['id']
            self.assertEqual(
                expect_msg, ct2.json_body['NeutronError']['message'])

    def test_update_ct_with_duplicate_entry(self):
        with self.router() as router:
            ct1 = self._create_router_conntrack_helper(
                self.fmt, router['router']['id'],
                "udp", 69, "tftp")
            self.assertEqual(exc.HTTPCreated.code, ct1.status_code)
            ct2 = self._create_router_conntrack_helper(
                self.fmt, router['router']['id'],
                "udp", 68, "tftp")
            self.assertEqual(exc.HTTPCreated.code, ct2.status_code)
            result = self._update_router_conntrack_helper(
                self.fmt, router['router']['id'],
                ct1.json['conntrack_helper']['id'],
                **{'port': 68})
            self.assertEqual(exc.HTTPBadRequest.code, result.status_code)
            expect_msg = ("Bad conntrack_helper request: A duplicate "
                          "conntrack helper entry with same attributes "
                          "already exists, conflicting values are "
                          "{'router_id': '%s', 'protocol': 'udp', "
                          "'port': 68, 'helper': "
                          "'tftp'}.") % router['router']['id']
            self.assertEqual(
                expect_msg, result.json_body['NeutronError']['message'])
