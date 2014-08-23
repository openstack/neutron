# Copyright 2014, Big Switch Networks
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

from neutron import manager
from neutron.tests.unit.bigswitch import test_base
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_security_groups_rpc as test_sg_rpc


class RestProxySecurityGroupsTestCase(test_sg.SecurityGroupDBTestCase,
                                      test_base.BigSwitchTestBase):
    plugin_str = ('%s.NeutronRestProxyV2' %
                  test_base.RESTPROXY_PKG_PATH)

    def setUp(self, plugin=None):
        test_sg_rpc.set_firewall_driver(test_sg_rpc.FIREWALL_HYBRID_DRIVER)
        self.setup_config_files()
        self.setup_patches()
        self._attribute_map_bk_ = {}
        super(RestProxySecurityGroupsTestCase, self).setUp(self.plugin_str)
        plugin = manager.NeutronManager.get_plugin()
        self.notifier = plugin.notifier
        self.rpc = plugin.endpoints[0]
        self.startHttpPatch()


class TestSecServerRpcCallBack(test_sg_rpc.SGServerRpcCallBackTestCase,
                               RestProxySecurityGroupsTestCase):
    pass


class TestSecurityGroupsMixin(test_sg.TestSecurityGroups,
                              test_sg_rpc.SGNotificationTestMixin,
                              RestProxySecurityGroupsTestCase):
    pass
