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

from unittest import mock

from neutron_lib.agent import topics
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants

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

    def _create_router(self, distributed=True, ha=True, admin_state_up=True):
        return (super(L3DvrHATestCase, self).
                _create_router(distributed=distributed, ha=ha,
                               admin_state_up=admin_state_up))

    def test_update_router_db_cvr_to_dvrha(self):
        router = self._create_router(distributed=False, ha=False,
                                     admin_state_up=False)
        self.l3_plugin.update_router(
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': True}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertTrue(router['ha'])

    def test_update_router_db_dvrha_to_cvr(self):
        router = self._create_router(distributed=True, ha=True,
                                     admin_state_up=False)
        self.l3_plugin.update_router(
            self.context,
            router['id'],
            {'router': {'distributed': False, 'ha': False}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertFalse(router['distributed'])
        self.assertFalse(router['ha'])

    def test_update_router_db_dvrha_to_dvr(self):
        router = self._create_router(distributed=True, ha=True,
                                     admin_state_up=False)
        self.l3_plugin.update_router(
            self.context, router['id'], {'router': {'admin_state_up': False}})
        self.l3_plugin.update_router(
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': False}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertFalse(router['ha'])

    def test_update_router_db_dvrha_to_cvrha(self):
        router = self._create_router(distributed=True, ha=True,
                                     admin_state_up=False)
        self.l3_plugin.update_router(
            self.context,
            router['id'],
            {'router': {'distributed': False, 'ha': True}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertFalse(router['distributed'])
        self.assertTrue(router['ha'])

    def test_update_router_db_dvr_to_dvrha(self):
        router = self._create_router(distributed=True, ha=False,
                                     admin_state_up=False)
        self.l3_plugin.update_router(
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': True}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
        self.assertTrue(router['ha'])

    def test_update_router_db_cvrha_to_dvrha(self):
        router = self._create_router(distributed=False, ha=True,
                                     admin_state_up=False)
        self.l3_plugin.update_router(
            self.context,
            router['id'],
            {'router': {'distributed': True, 'ha': True}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])
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
                          is_admin=True,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST1}), \
                self.port(subnet=subnet2,
                          is_admin=True,
                          device_owner=constants.DEVICE_OWNER_DHCP,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST2}), \
                self.port(subnet=subnet3,
                          is_admin=True,
                          device_owner=constants.DEVICE_OWNER_NETWORK_PREFIX,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST3}):
            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                         {'network': {extnet_apidef.EXTERNAL: True}},
                         as_admin=True)
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
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.subnet() as subnet, \
                self.network(as_admin=True, **kwargs) as ext_net, \
                self.subnet(network=ext_net, cidr='20.0.0.0/24'):
            gw_info = {'network_id': ext_net['network']['id']}
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
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
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.network(as_admin=True, **kwargs) as ext_net, \
                self.subnet(network=ext_net), \
                self.subnet(cidr='20.0.0.0/24') as subnet, \
                self.port(subnet=subnet,
                          device_owner=constants.DEVICE_OWNER_DHCP) as port:
            self.core_plugin.update_port(
                self.context, port['port']['id'],
                {'port': {'binding:host_id': self.l3_agent['host']}})
            gw_info = {'network_id': ext_net['network']['id']}
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})
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

    def _get_ha_interface_list_for_router(self, router):
        return self.l3_plugin.get_ha_router_port_bindings(self.context,
                                                          [router['id']])

    def _delete_router(self, router):
        self.l3_plugin.delete_router(self.context, router['id'])

    def _check_dvr_ha_interfaces_presence(self, rtr, int_cnt):
        self.assertEqual(int_cnt,
                         len(self._get_ha_interface_list_for_router(rtr)))

    def _create_external_network(self):
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, 'ext_net', True, as_admin=True,
                                     **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.0.0.1', '10.0.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self._make_subnet(
            self.fmt, ext_net, '2001:db8::1', '2001:db8::/64',
            ip_version=constants.IP_VERSION_6, enable_dhcp=True)
        return ext_net

    def _set_external_gateway(self, router, ext_net):
        gw_info = {'network_id': ext_net['network']['id']}
        self.l3_plugin.update_router(
            self.context, router['id'],
            {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})

    def _clear_external_gateway(self, router):
        self.l3_plugin.update_router(
            self.context, router['id'],
            {'router': {l3_apidef.EXTERNAL_GW_INFO: {}}})

    def _remove_interface_from_router(self, router, subnet):
        self.l3_plugin.remove_router_interface(
            self.context, router['id'],
            {'subnet_id': subnet['subnet']['id']})

    def _check_snat_external_gateway_presence(self, ext_net, router, gw_count):
        ext_net_id = ext_net['network']['id']
        gw_port = (self.l3_plugin._core_plugin.
                   _get_router_gw_ports_by_network(self.context, ext_net_id))
        self.assertEqual(gw_count, len(gw_port))
        if gw_count > 1:
            self.assertEqual(router['id'], gw_port[0].device_id)

    def _check_snat_internal_gateways_presence(self, router, subnet, int_cnt):
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router['id']])
        if int_cnt == 0:
            self.assertEqual(0, len(snat_router_intfs))
        else:
            snat_interfaces = snat_router_intfs[router['id']]
            self.assertEqual(1, len(snat_interfaces))
            self.assertEqual(subnet['subnet']['id'],
                             snat_interfaces[0]['fixed_ips'][0]['subnet_id'])

    def _check_internal_subnet_interface_presence(self, router, subnet,
                                                  int_cnt):
        router_ints = self.l3_plugin._get_sync_interfaces(
            self.context, [router['id']],
            device_owners=constants.ROUTER_INTERFACE_OWNERS)
        self.assertEqual(int_cnt, len(router_ints))
        if int_cnt > 1:
            self.assertEqual(subnet['subnet']['id'],
                             router_ints[0]['fixed_ips'][0]['subnet_id'])

    def _add_internal_subnet_to_router(self, router):
        int_net = self._make_network(self.fmt, 'int_net', True)
        int_subnet = self._make_subnet(
            self.fmt, int_net, '10.1.0.1', '10.1.0.0/24', enable_dhcp=True)
        self.l3_plugin.add_router_interface(
            self.context, router['id'],
            {'subnet_id': int_subnet['subnet']['id']})
        return int_subnet

    def _create_dvrha_router(self):
        router = self._create_router(distributed=True, ha=True)
        self.assertTrue(router['distributed'])
        self.assertTrue(router['ha'])
        return router

    def test_dvr_ha_router_create_attach_internal_external_detach_delete(self):
        """DVRHA Attach internal subnet followed by attach external"""

        # create router
        router = self._create_dvrha_router()
        self._check_dvr_ha_interfaces_presence(router, 2)

        # add subnet interface to router
        int_subnet = self._add_internal_subnet_to_router(router)
        self._check_internal_subnet_interface_presence(router, int_subnet, 1)

        # set router external gateway
        ext_net = self._create_external_network()
        self._set_external_gateway(router, ext_net)
        self._check_dvr_ha_interfaces_presence(router, 2)
        self._check_snat_external_gateway_presence(ext_net, router, 1)
        self._check_internal_subnet_interface_presence(router, int_subnet, 1)
        self._check_snat_internal_gateways_presence(router, int_subnet, 1)

        # clear router external gateway
        self._clear_external_gateway(router)
        self._check_dvr_ha_interfaces_presence(router, 2)
        self._check_snat_external_gateway_presence(ext_net, router, 0)
        self._check_internal_subnet_interface_presence(router, int_subnet, 1)
        self._check_snat_internal_gateways_presence(router, int_subnet, 0)

        # remove subnet interface from router
        self._remove_interface_from_router(router, int_subnet)
        self._check_internal_subnet_interface_presence(router, int_subnet, 0)

        # delete router
        self._delete_router(router)
        self._check_dvr_ha_interfaces_presence(router, 0)

    def test_get_device_owner_centralized(self):
        self.skipTest('Valid for DVR-only routers')

    def test_update_router_db_centralized_to_distributed(self):
        self.skipTest('Valid for DVR-only routers')

    def test__get_router_ids_for_agent(self):
        self.skipTest('Valid for DVR-only routers')

    def test_router_auto_scheduling(self):
        self.skipTest('Valid for DVR-only routers')
