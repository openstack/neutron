# Copyright 2024 Red Hat, Inc.
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import context
from neutron_lib import exceptions as lib_exc

from neutron.services.l3_router.service_providers import driver_controller \
    as l3_driver_controller
from neutron.services.ovn_l3.service_providers import driver_controller
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class TestDriverController(testlib_api.SqlTestCase):

    def setUp(self):
        super(TestDriverController, self).setUp()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.fake_l3 = mock.Mock()
        self.dc = driver_controller.DriverController(self.fake_l3)
        self.fake_l3.l3_driver_controller = self.dc
        self.ctx = context.get_admin_context()

    def test__update_router_provider_ha_mandatory(self):
        test_dc = driver_controller.DriverController(self.fake_l3)
        with mock.patch.object(registry, "publish") as mock_cb:
            with mock.patch.object(test_dc, "get_provider_for_router"):
                with mock.patch.object(
                        l3_driver_controller,
                        "_ensure_driver_supports_request") as _ensure:
                    _ensure.side_effect = lib_exc.InvalidInput(
                        error_message='message')
                    self.assertRaises(
                        lib_exc.InvalidInput,
                        test_dc._update_router_provider,
                        None, None, None,
                        payload=events.DBEventPayload(
                            None, request_body={'ha': False,
                                                'distributed': True},
                            states=({'flavor_id': None},))
                    )
                    mock_cb.assert_not_called()
