# Copyright (c) 2019 Red Hat, Inc.
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

import mock

from neutron_lib.api.definitions import l3_conntrack_helper as apidef
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import l3 as lib_l3_exc
from neutron_lib.plugins import directory
from oslo_utils import uuidutils

from neutron.services.conntrack_helper.common import exceptions as cth_exc
from neutron.services.conntrack_helper import plugin as cth_plugin
from neutron.tests.functional import base as functional_base
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


INVALID_ID = uuidutils.generate_uuid()


class ConntrackHelperTestCase(ml2_test_base.ML2TestFramework,
                              functional_base.BaseLoggingTestCase):
    def setUp(self):
        super(ConntrackHelperTestCase, self).setUp()
        self.cth_plugin = cth_plugin.Plugin()
        directory.add_plugin("CONNTRACKHELPER", self.cth_plugin)
        self.router = self._create_router(distributed=True)
        self.conntack_helper = {
            apidef.RESOURCE_NAME:
                {apidef.PROTOCOL: 'udp',
                 apidef.PORT: 69,
                 apidef.HELPER: 'tftp'}
        }

    def test_create_conntrack_helper(self):
        res = self.cth_plugin.create_router_conntrack_helper(
            self.context, self.router['id'], self.conntack_helper)
        expected = {
            'id': mock.ANY,
            'protocol': 'udp',
            'port': 69,
            'helper': 'tftp',
            'router_id': self.router['id']
        }
        self.assertEqual(expected, res)

    def test_negative_duplicate_create_conntrack_helper(self):
        self.cth_plugin.create_router_conntrack_helper(
            self.context, self.router['id'], self.conntack_helper)

        self.assertRaises(lib_exc.BadRequest,
                          self.cth_plugin.create_router_conntrack_helper,
                          self.context, self.router['id'],
                          self.conntack_helper)

    def test_negative_create_conntrack_helper(self):
        self.assertRaises(lib_l3_exc.RouterNotFound,
                          self.cth_plugin.create_router_conntrack_helper,
                          self.context, INVALID_ID,
                          self.conntack_helper)

    def test_update_conntrack_helper(self):
        res = self.cth_plugin.create_router_conntrack_helper(
            self.context, self.router['id'], self.conntack_helper)
        new_conntack_helper = {
            apidef.RESOURCE_NAME:
                {apidef.PROTOCOL: 'udp',
                 apidef.PORT: 6969,
                 apidef.HELPER: 'tftp'}
        }
        update = self.cth_plugin.update_router_conntrack_helper(
            self.context, res['id'], self.router['id'], new_conntack_helper)
        expected = {
            'id': res['id'],
            'protocol': 'udp',
            'port': 6969,
            'helper': 'tftp',
            'router_id': self.router['id']
        }
        self.assertEqual(expected, update)

    def test_negative_update_conntrack_helper(self):
        self.assertRaises(cth_exc.ConntrackHelperNotFound,
                          self.cth_plugin.update_router_conntrack_helper,
                          self.context, INVALID_ID, self.router['id'], {})

    def test_negative_duplicate_update_conntrack_helper(self):
        self.cth_plugin.create_router_conntrack_helper(
            self.context, self.router['id'], self.conntack_helper)
        new_conntack_helper = {
            apidef.RESOURCE_NAME:
                {apidef.PROTOCOL: 'udp',
                 apidef.PORT: 6969,
                 apidef.HELPER: 'tftp'}
        }
        res = self.cth_plugin.create_router_conntrack_helper(
            self.context, self.router['id'], new_conntack_helper)

        new_conntack_helper[apidef.RESOURCE_NAME][apidef.PORT] = 69
        self.assertRaises(lib_exc.BadRequest,
                          self.cth_plugin.update_router_conntrack_helper,
                          self.context, res['id'], self.router['id'],
                          new_conntack_helper)

    def test_delete_conntrack_helper(self):
        res = self.cth_plugin.create_router_conntrack_helper(
            self.context, self.router['id'], self.conntack_helper)
        delete = self.cth_plugin.delete_router_conntrack_helper(
            self.context, res['id'], self.router['id'])
        self.assertIsNone(delete)

    def test_negative_delete_conntrack_helper(self):
        self.assertRaises(cth_exc.ConntrackHelperNotFound,
                          self.cth_plugin.delete_router_conntrack_helper,
                          self.context, INVALID_ID, self.router['id'])
