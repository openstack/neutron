# Copyright 2024 Red Hat, Inc.
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

from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron.db import ovn_l3_hamode_db
from neutron.objects import router as router_obj
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.db import test_l3_dvr_db


class FakeOVNL3Plugin(test_l3_dvr_db.FakeL3Plugin,
                      ovn_l3_hamode_db.OVN_L3_HA_db_mixin):
    pass


class OVN_L3_HA_db_mixinTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self, **kwargs):
        super().setUp(plugin='ml2', **kwargs)
        self.core_plugin = directory.get_plugin()
        self.ctx = context.get_admin_context()
        self.mixin = FakeOVNL3Plugin()
        directory.add_plugin(plugin_constants.L3, self.mixin)

    def _create_router(self, router):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            return self.mixin._create_router_db(self.ctx, router, 'foo_tenant')

    def test_create_router(self):
        router_dict = {'name': 'foo_router', 'admin_state_up': True,
                       'distributed': False}
        router_db = self._create_router(router_dict)
        router = router_obj.Router.get_object(self.ctx, id=router_db.id)
        self.assertTrue(router.extra_attributes.ha)

    def test_create_no_ovn_router(self):
        router_dict = {'name': 'foo_router', 'admin_state_up': True,
                       'distributed': False, 'flavor_id': 'uuid'}
        router_db = self._create_router(router_dict)
        router = router_obj.Router.get_object(self.ctx, id=router_db.id)
        self.assertFalse(router.extra_attributes.ha)
