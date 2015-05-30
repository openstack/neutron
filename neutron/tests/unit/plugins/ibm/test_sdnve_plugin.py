# Copyright 2014 IBM Corp.
#
# All Rights Reserved.
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

from neutron.extensions import portbindings
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_l3 as test_l3

from neutron.plugins.ibm.common import constants


_plugin_name = ('neutron.plugins.ibm.'
                'sdnve_neutron_plugin.SdnvePluginV2')
HTTP_OK = 200


class MockClient(object):
    def sdnve_list(self, resource, **params):
        return (HTTP_OK, 'body')

    def sdnve_show(self, resource, specific, **params):
        return (HTTP_OK, 'body')

    def sdnve_create(self, resource, body):
        return (HTTP_OK, 'body')

    def sdnve_update(self, resource, specific, body=None):
        return (HTTP_OK, 'body')

    def sdnve_delete(self, resource, specific):
        return (HTTP_OK, 'body')

    def sdnve_get_tenant_byid(self, os_tenant_id):
        return (os_tenant_id, constants.TENANT_TYPE_OF)

    def sdnve_check_and_create_tenant(
        self, os_tenant_id, network_type=None):
        return os_tenant_id

    def sdnve_get_controller(self):
        return


class MockKeystoneClient(object):
    def __init__(self, **kwargs):
        pass

    def get_tenant_type(self, id):
        return constants.TENANT_TYPE_OF

    def get_tenant_name(self, id):
        return "tenant name"


class IBMPluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):
    def setUp(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.' 'KeystoneClient',
                        new=MockKeystoneClient),\
                mock.patch('neutron.plugins.ibm.sdnve_api.' 'Client',
                           new=MockClient):
            super(IBMPluginV2TestCase, self).setUp(plugin=_plugin_name)


class TestIBMBasicGet(test_plugin.TestBasicGet,
                      IBMPluginV2TestCase):
    pass


class TestIBMV2HTTPResponse(test_plugin.TestV2HTTPResponse,
                            IBMPluginV2TestCase):
    pass


class TestIBMNetworksV2(test_plugin.TestNetworksV2,
                        IBMPluginV2TestCase):
    pass


class TestIBMPortsV2(test_plugin.TestPortsV2,
                     IBMPluginV2TestCase):
    pass


class TestIBMSubnetsV2(test_plugin.TestSubnetsV2,
                       IBMPluginV2TestCase):
    pass


class TestIBMPortBinding(IBMPluginV2TestCase,
                         test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_OVS


class IBMPluginRouterTestCase(test_l3.L3NatDBIntTestCase):

    def setUp(self):
        with mock.patch('neutron.plugins.ibm.sdnve_api.' 'KeystoneClient',
                        new=MockKeystoneClient),\
                mock.patch('neutron.plugins.ibm.sdnve_api.' 'Client',
                           new=MockClient):
            super(IBMPluginRouterTestCase, self).setUp(plugin=_plugin_name)

    def test_floating_port_status_not_applicable(self):
        self.skipTest('Plugin changes floating port status')
