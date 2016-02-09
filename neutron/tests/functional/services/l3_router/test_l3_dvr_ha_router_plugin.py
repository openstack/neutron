# Copyright (c) 2016 Red Hat, Inc.
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

from neutron.common import constants
from neutron.common import topics
from neutron.extensions import external_net
from neutron.extensions import l3_ext_ha_mode
from neutron.extensions import portbindings
from neutron.tests.common import helpers
from neutron.tests.functional.services.l3_router import \
    test_l3_dvr_router_plugin

DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class L3DvrHATestCase(test_l3_dvr_router_plugin.L3DvrTestCase):
    def setUp(self):
        super(L3DvrHATestCase, self).setUp()
        self.l3_agent_2 = helpers.register_l3_agent(
            host="standby",
            agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)

    def _create_router(self, distributed=True, ha=True):
        return (super(L3DvrHATestCase, self).
                _create_router(distributed=distributed, ha=ha))

    def test_update_router_db_cvr_to_dvrha(self):
        router = self._create_router(distributed=False, ha=False)
        self.assertRaises(
            l3_ext_ha_mode.UpdateToDvrHamodeNotSupported,
            self.l3_plugin.update_router,
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': True}}
        )
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertFalse(router['distributed'])
        self.assertFalse(router['ha'])

    def test_update_router_db_dvrha_to_cvr(self):
        router = self._create_router(distributed=True, ha=True)
        self.assertRaises(
            l3_ext_ha_mode.DVRmodeUpdateOfDvrHaNotSupported,
            self.l3_plugin.update_router,
            self.context,
            router['id'],
            {'router': {'distributed': False, 'ha': False}}
        )
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertTrue(router['ha'])

    def test_update_router_db_dvrha_to_dvr(self):
        router = self._create_router(distributed=True, ha=True)
        self.l3_plugin.update_router(
            self.context, router['id'], {'router': {'admin_state_up': False}})
        self.assertRaises(
            l3_ext_ha_mode.HAmodeUpdateOfDvrHaNotSupported,
            self.l3_plugin.update_router,
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': False}}
        )
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertTrue(router['ha'])

    def test_update_router_db_dvrha_to_cvrha(self):
        router = self._create_router(distributed=True, ha=True)
        self.assertRaises(
            l3_ext_ha_mode.DVRmodeUpdateOfDvrHaNotSupported,
            self.l3_plugin.update_router,
            self.context,
            router['id'],
            {'router': {'distributed': False, 'ha': True}}
        )
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertTrue(router['ha'])

    def test_update_router_db_dvr_to_dvrha(self):
        router = self._create_router(distributed=True, ha=False)
        self.assertRaises(
            l3_ext_ha_mode.HAmodeUpdateOfDvrNotSupported,
            self.l3_plugin.update_router,
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': True}}
        )
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertFalse(router['ha'])

    def test_update_router_db_cvrha_to_dvrha(self):
        router = self._create_router(distributed=False, ha=True)
        self.assertRaises(
            l3_ext_ha_mode.DVRmodeUpdateOfHaNotSupported,
            self.l3_plugin.update_router,
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': True}}
        )
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertFalse(router['distributed'])
        self.assertTrue(router['ha'])

    def _assert_router_is_hosted_on_both_dvr_snat_agents(self, router):
        agents = self.l3_plugin.list_l3_agents_hosting_router(
            self.context, router['id'])
        self.assertEqual(2, len(agents['agents']))
        dvr_snat_agents = self.l3_plugin.get_ha_router_port_bindings(
            self.context, [router['id']])
        dvr_snat_agent_ids = [a.l3_agent_id for a in dvr_snat_agents]
        self.assertIn(self.l3_agent['id'], dvr_snat_agent_ids)
        self.assertIn(self.l3_agent_2['id'], dvr_snat_agent_ids)

    def test_router_notifications(self):
        """Check that notifications go to the right hosts in different
        conditions
        """
        # register l3 agents in dvr mode in addition to existing dvr_snat agent
        HOST1, HOST2, HOST3 = 'host1', 'host2', 'host3'
        for host in [HOST1, HOST2, HOST3]:
            helpers.register_l3_agent(
                host=host, agent_mode=constants.L3_AGENT_MODE_DVR)

        router = self._create_router(distributed=True, ha=True)
        arg_list = (portbindings.HOST_ID,)
        with self.subnet() as ext_subnet, \
                self.subnet(cidr='20.0.0.0/24') as subnet1, \
                self.subnet(cidr='30.0.0.0/24') as subnet2, \
                self.subnet(cidr='40.0.0.0/24') as subnet3, \
                self.port(subnet=subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST1}), \
                self.port(subnet=subnet2,
                          device_owner=constants.DEVICE_OWNER_DHCP,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST2}), \
                self.port(subnet=subnet3,
                          device_owner=constants.DEVICE_OWNER_NEUTRON_PREFIX,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST3}):
            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                         {'network': {external_net.EXTERNAL: True}})
            with mock.patch.object(self.l3_plugin.l3_rpc_notifier.client,
                                   'prepare') as mock_prepare:
                # add external gateway to router
                self.l3_plugin.update_router(
                    self.context, router['id'],
                    {'router': {
                        'external_gateway_info': {'network_id': ext_net_id}}})
                # router has no interfaces so notification goes
                # to only dvr_snat agents (self.l3_agent and self.l3_agent_2)
                self.assertEqual(2, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=self.l3_agent_2['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1')]
                mock_prepare.assert_has_calls(expected, any_order=True)

                mock_prepare.reset_mock()
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet1['subnet']['id']})
                self.assertEqual(3, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=self.l3_agent_2['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=HOST1,
                                      topic=topics.L3_AGENT,
                                      version='1.1')]
                mock_prepare.assert_has_calls(expected, any_order=True)

                mock_prepare.reset_mock()
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet2['subnet']['id']})
                self.assertEqual(4, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=self.l3_agent_2['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=HOST1,
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=HOST2,
                                      topic=topics.L3_AGENT,
                                      version='1.1')]
                mock_prepare.assert_has_calls(expected, any_order=True)

                mock_prepare.reset_mock()
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet3['subnet']['id']})
                # there are no dvr serviceable ports on HOST3, so notification
                # goes to the same hosts
                self.assertEqual(4, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=self.l3_agent_2['host'],
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=HOST1,
                                      topic=topics.L3_AGENT,
                                      version='1.1'),
                            mock.call(server=HOST2,
                                      topic=topics.L3_AGENT,
                                      version='1.1')]
                mock_prepare.assert_has_calls(expected, any_order=True)

    def test_router_is_not_removed_from_snat_agent_on_interface_removal(self):
        """Check that dvr router is not removed from dvr_snat l3 agents
        on router interface removal
        """
        router = self._create_router(distributed=True, ha=True)
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.subnet() as subnet, \
                self.network(**kwargs) as ext_net, \
                self.subnet(network=ext_net, cidr='20.0.0.0/24'):
            self.l3_plugin._update_router_gw_info(
                self.context, router['id'],
                {'network_id': ext_net['network']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})
            self._assert_router_is_hosted_on_both_dvr_snat_agents(router)
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                self.l3_plugin.remove_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet['subnet']['id']})
                self._assert_router_is_hosted_on_both_dvr_snat_agents(router)
                self.assertFalse(l3_notifier.router_removed_from_agent.called)

    def test_router_is_not_removed_from_snat_agent_on_dhcp_port_deletion(self):
        """Check that dvr router is not removed from l3 agent hosting
        SNAT for it on DHCP port removal
        """
        router = self._create_router(distributed=True, ha=True)
        kwargs = {'arg_list': (external_net.EXTERNAL,),
                  external_net.EXTERNAL: True}
        with self.network(**kwargs) as ext_net, \
                self.subnet(network=ext_net), \
                self.subnet(cidr='20.0.0.0/24') as subnet, \
                self.port(subnet=subnet,
                          device_owner=constants.DEVICE_OWNER_DHCP) as port:
            self.core_plugin.update_port(
                self.context, port['port']['id'],
                {'port': {'binding:host_id': self.l3_agent['host']}})
            self.l3_plugin._update_router_gw_info(
                self.context, router['id'],
                {'network_id': ext_net['network']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            # router should be scheduled to both dvr_snat l3 agents
            self._assert_router_is_hosted_on_both_dvr_snat_agents(router)

            notifier = self.l3_plugin.agent_notifiers[
                constants.AGENT_TYPE_L3]
            with mock.patch.object(
                    notifier, 'router_removed_from_agent',
                    side_effect=Exception("BOOOOOOM!")) as remove_mock:
                self._delete('ports', port['port']['id'])
                # now when port is deleted the router still has external
                # gateway and should still be scheduled to the snat agent
                remove_mock.assert_not_called()
                self._assert_router_is_hosted_on_both_dvr_snat_agents(router)

    def test_update_router_db_centralized_to_distributed(self):
        self.skipTest('Valid for DVR-only routers')

    def test__get_router_ids_for_agent(self):
        self.skipTest('Valid for DVR-only routers')

    def test_router_auto_scheduling(self):
        self.skipTest('Valid for DVR-only routers')
