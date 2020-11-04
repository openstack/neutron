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

from neutron.agent.l3 import dvr_edge_router
from neutron.agent.l3 import dvr_local_router
from neutron.agent.l3 import legacy_router
from neutron.agent.linux import pd
from neutron.tests import base as tests_base


class FakeRouter(object):
    def __init__(self, router_id):
        self.router_id = router_id


class TestPrefixDelegation(tests_base.DietTestCase):
    def test_remove_router(self):
        l3_agent = mock.Mock()
        router_id = 1
        l3_agent.pd.routers = {router_id:
                               pd.get_router_entry(None, True)}
        pd.remove_router(None, None, l3_agent, router=FakeRouter(router_id))
        self.assertTrue(l3_agent.pd.delete_router_pd.called)
        self.assertEqual({}, l3_agent.pd.routers)

    def _test_add_update_pd(self, l3_agent, router, ns_name):
        # add entry
        pd.add_router(None, None, l3_agent, router=router)
        pd_router = l3_agent.pd.routers.get(router.router_id)
        self.assertEqual(ns_name, pd_router.get('ns_name'))

        # clear namespace name, update entry
        pd_router['ns_name'] = None
        pd.update_router(None, None, l3_agent, router=router)
        pd_router = l3_agent.pd.routers.get(router.router_id)
        self.assertEqual(ns_name, pd_router.get('ns_name'))

    @mock.patch.object(dvr_edge_router.DvrEdgeRouter,
                       'load_used_fip_information')
    def test_add_update_dvr_edge_router(self, load_used_fip_info):
        l3_agent = mock.Mock()
        l3_agent.pd.routers = {}
        router_id = '1'
        ri = dvr_edge_router.DvrEdgeRouter(l3_agent,
                                           'host',
                                           router_id,
                                           mock.Mock(),
                                           mock.Mock(),
                                           mock.Mock())
        ns_name = ri.snat_namespace.name
        self._test_add_update_pd(l3_agent, ri, ns_name)

    @mock.patch.object(dvr_local_router.DvrLocalRouter,
                       'load_used_fip_information')
    def test_add_update_dvr_local_router(self, load_used_fip_info):
        l3_agent = mock.Mock()
        l3_agent.pd.routers = {}
        router_id = '1'
        ri = dvr_local_router.DvrLocalRouter(l3_agent,
                                             'host',
                                             router_id,
                                             mock.Mock(),
                                             mock.Mock(),
                                             mock.Mock())
        ns_name = ri.ns_name
        self._test_add_update_pd(l3_agent, ri, ns_name)

    def test_add_update_legacy_router(self):
        l3_agent = mock.Mock()
        l3_agent.pd.routers = {}
        router_id = '1'
        ri = legacy_router.LegacyRouter(l3_agent,
                                        router_id,
                                        mock.Mock(),
                                        mock.Mock(),
                                        mock.Mock())
        ns_name = ri.ns_name
        self._test_add_update_pd(l3_agent, ri, ns_name)

    def test_update_no_router_exception(self):
        l3_agent = mock.Mock()
        l3_agent.pd.routers = {}
        router = mock.Mock()
        router.router_id = '1'

        with mock.patch.object(pd.LOG, 'exception') as log:
            pd.update_router(None, None, l3_agent, router=router)
            self.assertTrue(log.called)

    def test_remove_stale_ri_ifname(self):
        pd_info_1 = mock.Mock()
        pd_info_1.ri_ifname = 'STALE'
        pd_info_2 = mock.Mock()
        pd_info_2.ri_ifname = 'NOT_STALE'
        router = {
            'subnets': {
                'FAKE_SUBNET_ID1': pd_info_1,
                'FAKE_SUBNET_ID2': pd_info_2}}

        class FakePD(pd.PrefixDelegation):
            def __init__(self, router):
                self.routers = {'FAKE_ROUTER_ID': router}

        fake_pd = FakePD(router)
        fake_pd._delete_pd = mock.Mock()
        fake_pd.remove_stale_ri_ifname('FAKE_ROUTER_ID', 'STALE')
        fake_pd._delete_pd.assert_called_with(router, pd_info_1)
        self.assertEqual(len(router['subnets'].keys()), 1)
