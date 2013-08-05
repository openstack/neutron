# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

import contextlib
import operator

from neutron.db import api as db
from neutron.plugins.ryu.common import config  # noqa
from neutron.plugins.ryu.db import api_v2 as db_api_v2
from neutron.tests.unit import test_db_plugin as test_plugin


class RyuDBTest(test_plugin.NeutronDbPluginV2TestCase):
    @staticmethod
    def _tunnel_key_sort(key_list):
        key_list.sort(key=operator.attrgetter('tunnel_key'))
        return [(key.network_id, key.tunnel_key) for key in key_list]

    def test_key_allocation(self):
        tunnel_key = db_api_v2.TunnelKey()
        session = db.get_session()
        with contextlib.nested(self.network('network-0'),
                               self.network('network-1')
                               ) as (network_0, network_1):
                network_id0 = network_0['network']['id']
                key0 = tunnel_key.allocate(session, network_id0)
                network_id1 = network_1['network']['id']
                key1 = tunnel_key.allocate(session, network_id1)
                key_list = tunnel_key.all_list()
                self.assertEqual(len(key_list), 2)

                expected_list = [(network_id0, key0), (network_id1, key1)]
                self.assertEqual(self._tunnel_key_sort(key_list),
                                 expected_list)

                tunnel_key.delete(session, network_id0)
                key_list = tunnel_key.all_list()
                self.assertEqual(self._tunnel_key_sort(key_list),
                                 [(network_id1, key1)])

                tunnel_key.delete(session, network_id1)
                self.assertEqual(tunnel_key.all_list(), [])
