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

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import router_availability_zone
from neutron_lib import constants as lib_const
from neutron_lib.plugins import constants

from neutron.db.availability_zone import router as router_az_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.extensions import l3
from neutron.tests.unit.extensions import test_availability_zone as test_az
from neutron.tests.unit.extensions import test_l3


class AZL3ExtensionManager(test_az.AZExtensionManager):

    def get_resources(self):
        return (super(AZL3ExtensionManager, self).get_resources() +
                l3.L3.get_resources())


class AZRouterTestPlugin(l3_db.L3_NAT_db_mixin,
                         router_az_db.RouterAvailabilityZoneMixin,
                         l3_agentschedulers_db.AZL3AgentSchedulerDbMixin):
    supported_extension_aliases = [l3_apidef.ALIAS,
                                   lib_const.L3_AGENT_SCHEDULER_EXT_ALIAS,
                                   router_availability_zone.ALIAS]

    @classmethod
    def get_plugin_type(cls):
        return constants.L3

    def get_plugin_description(self):
        return "L3 Routing Service Plugin for testing"


class TestAZRouterCase(test_az.AZTestCommon, test_l3.L3NatTestCaseMixin):
    def setUp(self):
        plugin = ('neutron.tests.unit.extensions.'
                  'test_availability_zone.AZTestPlugin')
        l3_plugin = ('neutron.tests.unit.extensions.'
                     'test_router_availability_zone.AZRouterTestPlugin')
        service_plugins = {'l3_plugin_name': l3_plugin}

        ext_mgr = AZL3ExtensionManager()
        super(TestAZRouterCase, self).setUp(plugin=plugin, ext_mgr=ext_mgr,
                                            service_plugins=service_plugins)

    def test_create_router_with_az(self):
        self._register_azs()
        az_hints = ['nova2']
        with self.router(availability_zone_hints=az_hints) as router:
            res = self._show('routers', router['router']['id'])
            self.assertItemsEqual(az_hints,
                                  res['router']['availability_zone_hints'])

    def test_create_router_with_azs(self):
        self._register_azs()
        az_hints = ['nova2', 'nova3']
        with self.router(availability_zone_hints=az_hints) as router:
            res = self._show('routers', router['router']['id'])
            self.assertItemsEqual(az_hints,
                                  res['router']['availability_zone_hints'])

    def test_create_router_without_az(self):
        with self.router() as router:
            res = self._show('routers', router['router']['id'])
            self.assertEqual([], res['router']['availability_zone_hints'])

    def test_create_router_with_empty_az(self):
        with self.router(availability_zone_hints=[]) as router:
            res = self._show('routers', router['router']['id'])
            self.assertEqual([], res['router']['availability_zone_hints'])

    def test_create_router_with_none_existing_az(self):
        res = self._create_router(self.fmt, 'tenant_id',
                                  availability_zone_hints=['nova4'])
        self.assertEqual(404, res.status_int)
