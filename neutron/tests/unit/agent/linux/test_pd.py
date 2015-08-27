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

from neutron.agent.linux import pd
from neutron.tests import base as tests_base


class FakeRouter(object):
    def __init__(self, router_id):
        self.router_id = router_id


class TestPrefixDelegation(tests_base.DietTestCase):
    def test_remove_router(self):
        l3_agent = mock.Mock()
        router_id = 1
        l3_agent.pd.routers = {router_id: pd.get_router_entry(None)}
        pd.remove_router(None, None, l3_agent, router=FakeRouter(router_id))
        self.assertTrue(l3_agent.pd.delete_router_pd.called)
        self.assertEqual({}, l3_agent.pd.routers)
