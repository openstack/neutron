# Copyright (c) 2015 Red Hat, Inc.
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

from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.tests.unit.plugins.ml2 import test_plugin


class ML2TestFramework(test_plugin.Ml2PluginV2TestCase):
    l3_plugin = ('neutron.services.l3_router.l3_router_plugin.'
                 'L3RouterPlugin')
    _mechanism_drivers = ['openvswitch']

    def get_additional_service_plugins(self):
        p = super(ML2TestFramework, self).get_additional_service_plugins()
        p.update({'flavors_plugin_name': 'neutron.services.flavors.'
                                         'flavors_plugin.FlavorsPlugin'})
        return p

    def setUp(self):
        super(ML2TestFramework, self).setUp()
        self.core_plugin = directory.get_plugin()
        self.l3_plugin = directory.get_plugin(constants.L3)

    def _create_router(self, distributed=False, ha=False, admin_state_up=True):
        return self.l3_plugin.create_router(
            self.context,
            {'router':
             {'name': 'router',
              'admin_state_up': admin_state_up,
              'tenant_id': self._tenant_id,
              'ha': ha,
              'distributed': distributed}})
