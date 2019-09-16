# Copyright (c) 2016 Midokura SARL
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
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import context
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory

from neutron.db import extraroute_db
from neutron.tests.unit import testlib_api


class _Plugin(extraroute_db.ExtraRoute_dbonly_mixin):
    pass


class TestExtraRouteDb(testlib_api.SqlTestCase):
    def setUp(self):
        super(TestExtraRouteDb, self).setUp()
        self._plugin = _Plugin()
        directory.add_plugin(constants.CORE, self._plugin)

    def test_update(self):
        ctx = context.get_admin_context()
        create_request = {
            'router': {
                'name': 'my router',
                'tenant_id': 'my tenant',
                'admin_state_up': True,
            }
        }
        router = self._plugin.create_router(ctx, create_request)
        self.assertItemsEqual(router['routes'], [])
        router_id = router['id']
        routes = [
            {'destination': '10.0.0.0/24', 'nexthop': '1.1.1.4'},
            {'destination': '10.1.0.0/24', 'nexthop': '1.1.1.3'},
            {'destination': '10.2.0.0/24', 'nexthop': '1.1.1.2'},
        ]
        self._test_update_routes(ctx, router_id, router, routes)
        routes = [
            {'destination': '10.0.0.0/24', 'nexthop': '1.1.1.4'},
            {'destination': '10.2.0.0/24', 'nexthop': '1.1.1.2'},
            {'destination': '10.3.0.0/24', 'nexthop': '1.1.1.1'},
        ]
        self._test_update_routes(ctx, router_id, router, routes)

    def _test_update_routes(self, ctx, router_id, router, routes):
        router['routes'] = routes
        update_request = {
            'router': router,
        }
        with mock.patch.object(registry, "publish") as mock_cb:
            with mock.patch.object(self._plugin, '_validate_routes'):
                updated_router = self._plugin.update_router(ctx, router_id,
                                                            update_request)
            mock_cb.assert_called_with('router', events.PRECOMMIT_UPDATE,
                                       self._plugin, payload=mock.ANY)
        self.assertItemsEqual(updated_router['routes'], routes)
        got_router = self._plugin.get_router(ctx, router_id)
        self.assertItemsEqual(got_router['routes'], routes)

    def assertEqualRoutes(self, a, b):
        """Compare a list of routes without caring for the list order."""
        return self.assertSetEqual(
            set(frozenset(r.items()) for r in a),
            set(frozenset(r.items()) for r in b))

    def test_add_extra_routes(self):
        self.assertEqual(
            [],
            self._plugin._add_extra_routes([], []),
        )

        old = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        add = []
        self.assertEqual(old, self._plugin._add_extra_routes(old, add))

        old = []
        add = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        self.assertEqual(add, self._plugin._add_extra_routes(old, add))

        old = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        add = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        self.assertEqual(old, self._plugin._add_extra_routes(old, add))

        old = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        add = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.11"}]
        self.assertEqualRoutes(
            old + add, self._plugin._add_extra_routes(old, add))

    def test_remove_extra_routes(self):
        old = []
        remove = []
        self.assertEqual(old, self._plugin._remove_extra_routes(old, remove))

        old = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        remove = []
        self.assertEqual(old, self._plugin._remove_extra_routes(old, remove))

        old = []
        remove = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        self.assertEqual(old, self._plugin._remove_extra_routes(old, remove))

        old = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        remove = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.11"}]
        self.assertEqual(old, self._plugin._remove_extra_routes(old, remove))

        old = [{"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"}]
        remove = old
        self.assertEqual([], self._plugin._remove_extra_routes(old, remove))

        old = [
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
            {"destination": "10.0.11.0/24", "nexthop": "10.0.0.11"},
        ]
        remove = old[1:]
        self.assertEqual(
            old[:1], self._plugin._remove_extra_routes(old, remove))

        old = [
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.11"},
        ]
        remove = old[1:]
        self.assertEqual(
            old[:1], self._plugin._remove_extra_routes(old, remove))

        old = []
        remove = [
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
        ]
        self.assertEqual([], self._plugin._remove_extra_routes(old, remove))

        old = [
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
        ]
        remove = [
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
            {"destination": "10.0.10.0/24", "nexthop": "10.0.0.10"},
        ]
        self.assertEqual([], self._plugin._remove_extra_routes(old, remove))
