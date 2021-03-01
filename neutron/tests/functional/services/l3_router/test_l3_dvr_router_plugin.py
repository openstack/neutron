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

import mock
from neutron_lib.agent import topics
from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources

from neutron_lib import constants
from neutron_lib import context

from neutron.api.rpc.handlers import l3_rpc
from neutron.tests.common import helpers
from neutron.tests.functional import base as functional_base
from neutron.tests.unit.plugins.ml2 import base as ml2_test_base


DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'


class L3DvrTestCaseBase(ml2_test_base.ML2TestFramework,
                        functional_base.BaseLoggingTestCase):
    def setUp(self):
        super(L3DvrTestCaseBase, self).setUp()
        self.l3_agent = helpers.register_l3_agent(
            host="host0",
            agent_mode=constants.L3_AGENT_MODE_DVR_SNAT)
        # register OVS agents to avoid time wasted on committing
        # port binding failures on every port update
        helpers.register_ovs_agent(host='host1')
        helpers.register_ovs_agent(host='host2')

    def _create_router(self, distributed=True, ha=False, admin_state_up=True):
        return (super(L3DvrTestCaseBase, self).
                _create_router(distributed=distributed, ha=ha,
                               admin_state_up=admin_state_up))


class MultipleL3PluginTestCase(L3DvrTestCaseBase):

    def get_additional_service_plugins(self):
        p = super(MultipleL3PluginTestCase,
                  self).get_additional_service_plugins()
        p.update({'l3_plugin_name_1': self.l3_plugin,
                  'l3_plugin_name_2': self.l3_plugin})
        return p

    def test_create_router(self):
        router = self._create_router()
        self.assertEqual(
            constants.DEVICE_OWNER_DVR_INTERFACE,
            self.l3_plugin._get_device_owner(self.context, router))


class L3DvrTestCase(L3DvrTestCaseBase):
    def test_update_router_db_centralized_to_distributed(self):
        router = self._create_router(distributed=False)
        # router needs to be in admin state down in order to be upgraded to DVR
        self.l3_plugin.update_router(
            self.context, router['id'], {'router': {'admin_state_up': False}})
        self.assertFalse(router['distributed'])
        self.l3_plugin.update_router(
            self.context, router['id'], {'router': {'distributed': True}})
        router = self.l3_plugin.get_router(self.context, router['id'])
        self.assertTrue(router['distributed'])

    def test_get_device_owner_distributed_router_object(self):
        router = self._create_router()
        self.assertEqual(
            constants.DEVICE_OWNER_DVR_INTERFACE,
            self.l3_plugin._get_device_owner(self.context, router))

    def test_get_device_owner_distributed_router_id(self):
        router = self._create_router()
        self.assertEqual(
            constants.DEVICE_OWNER_DVR_INTERFACE,
            self.l3_plugin._get_device_owner(self.context, router['id']))

    def test_get_device_owner_centralized(self):
        router = self._create_router(distributed=False)
        self.assertEqual(
            constants.DEVICE_OWNER_ROUTER_INTF,
            self.l3_plugin._get_device_owner(self.context, router['id']))

    def test_get_agent_gw_ports_exist_for_network_no_port(self):
        self.assertIsNone(
            self.l3_plugin._get_agent_gw_ports_exist_for_network(
                self.context, 'network_id', 'host', 'agent_id'))

    def test_csnat_ports_are_created_and_deleted_based_on_router_subnet(self):
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        net1 = self._make_network(self.fmt, 'net1', True)
        subnet1 = self._make_subnet(
            self.fmt, net1, '10.1.0.1', '10.1.0.0/24', enable_dhcp=True)
        subnet2 = self._make_subnet(
            self.fmt, net1, '10.2.0.1', '10.2.0.0/24', enable_dhcp=True)
        ext_net = self._make_network(self.fmt, 'ext_net', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '20.0.0.1', '20.0.0.0/24', enable_dhcp=True)
        # Create first router and add an interface
        router1 = self._create_router()
        ext_net_id = ext_net['network']['id']
        net1_id = net1['network']['id']
        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router1['id'],
            {'network_id': ext_net_id})
        # Now add router interface (subnet1) from net1 to router
        self.l3_plugin.add_router_interface(
            self.context, router1['id'],
            {'subnet_id': subnet1['subnet']['id']})
        # Now add router interface (subnet2) from net1 to router
        self.l3_plugin.add_router_interface(
            self.context, router1['id'],
            {'subnet_id': subnet2['subnet']['id']})
        # Now check the valid snat interfaces passed to the agent
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router1['id']])
        self.assertEqual(2, len(snat_router_intfs[router1['id']]))
        # Also make sure that there are no csnat ports created and
        # left over.
        csnat_ports = self.core_plugin.get_ports(
            self.context, filters={
                'network_id': [net1_id],
                'device_owner': [constants.DEVICE_OWNER_ROUTER_SNAT]})
        self.assertEqual(2, len(csnat_ports))
        # Now remove router interface (subnet1) from net1 to router
        self.l3_plugin.remove_router_interface(
            self.context, router1['id'],
            {'subnet_id': subnet1['subnet']['id']})
        # Now remove router interface (subnet2) from net1 to router
        self.l3_plugin.remove_router_interface(
            self.context, router1['id'],
            {'subnet_id': subnet2['subnet']['id']})
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router1['id']])
        self.assertEqual(0, len(snat_router_intfs[router1['id']]))
        # Also make sure that there are no csnat ports created and
        # left over.
        csnat_ports = self.core_plugin.get_ports(
            self.context, filters={
                'network_id': [net1_id],
                'device_owner': [constants.DEVICE_OWNER_ROUTER_SNAT]})
        self.assertEqual(0, len(csnat_ports))

    def _test_remove_router_interface_leaves_snat_intact(self, by_subnet):
        with self.subnet() as subnet1, \
                self.subnet(cidr='20.0.0.0/24') as subnet2:
            kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                      extnet_apidef.EXTERNAL: True}
            with self.network(**kwargs) as ext_net, \
                    self.subnet(network=ext_net,
                                cidr='30.0.0.0/24'):
                router = self._create_router()
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet1['subnet']['id']})
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet2['subnet']['id']})
                gw_info = {'network_id': ext_net['network']['id']}
                self.l3_plugin.update_router(
                    self.context, router['id'],
                    {'router': {l3_apidef.EXTERNAL_GW_INFO: gw_info}})

                snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
                    self.context, [router['id']])
                self.assertEqual(
                    2, len(snat_router_intfs[router['id']]))

                if by_subnet:
                    self.l3_plugin.remove_router_interface(
                        self.context, router['id'],
                        {'subnet_id': subnet1['subnet']['id']})
                else:
                    port = self.core_plugin.get_ports(
                        self.context, filters={
                            'network_id': [subnet1['subnet']['network_id']],
                            'device_owner':
                                [constants.DEVICE_OWNER_DVR_INTERFACE]})[0]
                    self.l3_plugin.remove_router_interface(
                        self.context, router['id'],
                        {'port_id': port['id']})

                self.assertEqual(
                    1, len(self.l3_plugin._get_snat_sync_interfaces(
                        self.context, [router['id']])))

    def test_remove_router_interface_by_subnet_leaves_snat_intact(self):
        self._test_remove_router_interface_leaves_snat_intact(by_subnet=True)

    def test_remove_router_interface_by_port_leaves_snat_intact(self):
        self._test_remove_router_interface_leaves_snat_intact(
            by_subnet=False)

    def setup_create_agent_gw_port_for_network(self, network=None):
        if not network:
            network = self._make_network(self.fmt, '', True)
        network_id = network['network']['id']
        port = self.core_plugin.create_port(
            self.context,
            {'port': {'tenant_id': '',
                      'network_id': network_id,
                      'mac_address': constants.ATTR_NOT_SPECIFIED,
                      'fixed_ips': constants.ATTR_NOT_SPECIFIED,
                      'device_id': self.l3_agent['id'],
                      'device_owner': constants.DEVICE_OWNER_AGENT_GW,
                      portbindings.HOST_ID: '',
                      'admin_state_up': True,
                      'name': ''}})
        return network_id, port

    def test_get_agent_gw_port_for_network(self):
        network_id, port = (
            self.setup_create_agent_gw_port_for_network())

        self.assertEqual(
            port['id'],
            self.l3_plugin._get_agent_gw_ports_exist_for_network(
                self.context, network_id, None, self.l3_agent['id'])['id'])

    def test_delete_agent_gw_port_for_network(self):
        network_id, port = (
            self.setup_create_agent_gw_port_for_network())

        self.l3_plugin.delete_floatingip_agent_gateway_port(
            self.context, "", network_id)
        self.assertIsNone(
            self.l3_plugin._get_agent_gw_ports_exist_for_network(
                self.context, network_id, "", self.l3_agent['id']))

    def test_get_fip_agent_gw_ports(self):
        self.setup_create_agent_gw_port_for_network()

        self.assertEqual(
            1, len(self.l3_plugin._get_fip_agent_gw_ports(
                self.context, self.l3_agent['id'])))

    def test_process_routers(self):
        router = self._create_router()
        if not router.get('gw_port_id'):
            router['gw_port_id'] = 'fake_gw_id'
        self.l3_plugin._get_fip_agent_gw_ports = mock.Mock(
            return_value='fip_interface')
        self.l3_plugin._get_snat_sync_interfaces = mock.Mock(
            return_value={router['id']: 'snat_interface'})
        result = self.l3_plugin._process_routers(self.context, [router],
                                                 self.l3_agent)

        self.assertEqual(
            router['id'], result[router['id']]['id'])
        self.assertIn(constants.FLOATINGIP_AGENT_INTF_KEY,
                      result[router['id']])
        self.l3_plugin._get_fip_agent_gw_ports.assert_called_once_with(
            self.context, self.l3_agent['id'])
        self.l3_plugin._get_snat_sync_interfaces.assert_called_once_with(
            self.context, [router['id']])

    def test_agent_gw_port_delete_when_last_gateway_for_ext_net_removed(self):
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        net1 = self._make_network(self.fmt, 'net1', True)
        net2 = self._make_network(self.fmt, 'net2', True)
        subnet1 = self._make_subnet(
            self.fmt, net1, '10.1.0.1', '10.1.0.0/24', enable_dhcp=True)
        subnet2 = self._make_subnet(
            self.fmt, net2, '10.1.0.1', '10.1.0.0/24', enable_dhcp=True)
        ext_net = self._make_network(self.fmt, 'ext_net', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '20.0.0.1', '20.0.0.0/24', enable_dhcp=True)
        # Create first router and add an interface
        router1 = self._create_router()
        ext_net_id = ext_net['network']['id']
        self.l3_plugin.add_router_interface(
            self.context, router1['id'],
            {'subnet_id': subnet1['subnet']['id']})
        # Set gateway to first router
        self.l3_plugin._update_router_gw_info(
            self.context, router1['id'],
            {'network_id': ext_net_id})
        # Create second router and add an interface
        router2 = self._create_router()
        self.l3_plugin.add_router_interface(
            self.context, router2['id'],
            {'subnet_id': subnet2['subnet']['id']})
        # Set gateway to second router
        self.l3_plugin._update_router_gw_info(
            self.context, router2['id'],
            {'network_id': ext_net_id})
        # Create an agent gateway port for the external network
        net_id, agent_gw_port = (
            self.setup_create_agent_gw_port_for_network(network=ext_net))
        # Check for agent gateway ports
        self.assertIsNotNone(
            self.l3_plugin._get_agent_gw_ports_exist_for_network(
                self.context, ext_net_id, "", self.l3_agent['id']))
        self.l3_plugin._update_router_gw_info(
            self.context, router1['id'], {})
        # Check for agent gateway port after deleting one of the gw
        self.assertIsNotNone(
            self.l3_plugin._get_agent_gw_ports_exist_for_network(
                self.context, ext_net_id, "", self.l3_agent['id']))
        self.l3_plugin._update_router_gw_info(
            self.context, router2['id'], {})
        # Check for agent gateway port after deleting last gw
        self.assertIsNone(
            self.l3_plugin._get_agent_gw_ports_exist_for_network(
                self.context, ext_net_id, "", self.l3_agent['id']))

    def test_create_floating_ip_with_no_dvr_agents(self):
        self._test_create_floating_ip_agent_notification(
            test_agent_mode=None)

    def _test_create_floating_ip_agent_notification(
            self, dvr=True, test_agent_mode=constants.L3_AGENT_MODE_DVR):
        with self.subnet() as ext_subnet,\
                self.subnet(cidr='20.0.0.0/24') as int_subnet,\
                self.port(subnet=int_subnet,
                          device_owner=DEVICE_OWNER_COMPUTE) as int_port:
            self.core_plugin.update_port(
                self.context, int_port['port']['id'],
                {'port': {portbindings.HOST_ID: 'host1'}})
            # and create l3 agents on corresponding hosts
            if test_agent_mode is not None:
                helpers.register_l3_agent(host='host1',
                    agent_mode=test_agent_mode)

            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})

            router = self._create_router(distributed=dvr)
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {
                    'external_gateway_info': {'network_id': ext_net_id}}})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': int_subnet['subnet']['id']})
            if test_agent_mode is None:
                self.assertIsNone(
                    self.l3_plugin.create_fip_agent_gw_port_if_not_exists(
                        self.context, ext_net_id, 'host1'))
                return
            floating_ip = {'floating_network_id': ext_net_id,
                           'router_id': router['id'],
                           'port_id': int_port['port']['id'],
                           'tenant_id': int_port['port']['tenant_id'],
                           'dns_name': '', 'dns_domain': ''}
            with mock.patch.object(
                    self.l3_plugin, '_l3_rpc_notifier') as l3_notif:
                self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})
                if dvr:
                    if (test_agent_mode ==
                            constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
                        if router['ha']:
                            expected_calls = [
                                mock.call(self.context,
                                          [router['id']], 'host0'),
                                mock.call(self.context,
                                          [router['id']], 'standby')]
                            l3_notif.routers_updated_on_host.assert_has_calls(
                                expected_calls, any_order=True)
                            self.assertFalse(l3_notif.routers_updated.called)
                        if not router['ha']:
                            l3_notif.routers_updated_on_host.\
                                assert_called_once_with(
                                    self.context, [router['id']], 'host0')
                            self.assertFalse(l3_notif.routers_updated.called)
                    else:
                        l3_notif.routers_updated_on_host.\
                            assert_called_once_with(
                                self.context, [router['id']], 'host1')
                        self.assertFalse(l3_notif.routers_updated.called)
                else:
                    l3_notif.routers_updated.assert_called_once_with(
                        self.context, [router['id']], None)
                    self.assertFalse(
                        l3_notif.routers_updated_on_host.called)

    def test_create_floating_ip_agent_notification(self):
        self._test_create_floating_ip_agent_notification()

    def test_create_floating_ip_agent_notification_for_dvr_no_external_agent(
            self):
        agent_mode = constants.L3_AGENT_MODE_DVR_NO_EXTERNAL
        self._test_create_floating_ip_agent_notification(
            test_agent_mode=agent_mode)

    def test_create_floating_ip_agent_notification_non_dvr(self):
        self._test_create_floating_ip_agent_notification(dvr=False)

    def _test_update_floating_ip_agent_notification(
            self, dvr=True, test_agent_mode=constants.L3_AGENT_MODE_DVR):
        with self.subnet() as ext_subnet,\
                self.subnet(cidr='20.0.0.0/24') as int_subnet1,\
                self.subnet(cidr='30.0.0.0/24') as int_subnet2,\
                self.port(subnet=int_subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE) as int_port1,\
                self.port(subnet=int_subnet2,
                          device_owner=DEVICE_OWNER_COMPUTE) as int_port2:
            # locate internal ports on different hosts
            self.core_plugin.update_port(
                self.context, int_port1['port']['id'],
                {'port': {portbindings.HOST_ID: 'host1'}})
            self.core_plugin.update_port(
                self.context, int_port2['port']['id'],
                {'port': {portbindings.HOST_ID: 'host2'}})
            # and create l3 agents on corresponding hosts
            helpers.register_l3_agent(host='host1',
                agent_mode=test_agent_mode)
            helpers.register_l3_agent(host='host2',
                agent_mode=test_agent_mode)

            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})

            router1 = self._create_router(distributed=dvr)
            router2 = self._create_router(distributed=dvr)
            for router in (router1, router2):
                self.l3_plugin.update_router(
                    self.context, router['id'],
                    {'router': {
                        'external_gateway_info': {'network_id': ext_net_id}}})
            self.l3_plugin.add_router_interface(
                self.context, router1['id'],
                {'subnet_id': int_subnet1['subnet']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router2['id'],
                {'subnet_id': int_subnet2['subnet']['id']})

            floating_ip = {'floating_network_id': ext_net_id,
                           'router_id': router1['id'],
                           'port_id': int_port1['port']['id'],
                           'tenant_id': int_port1['port']['tenant_id'],
                           'dns_name': '', 'dns_domain': ''}
            floating_ip = self.l3_plugin.create_floatingip(
                self.context, {'floatingip': floating_ip})

            with mock.patch.object(
                    self.l3_plugin, '_l3_rpc_notifier') as l3_notif:
                updated_floating_ip = {'router_id': router2['id'],
                                       'port_id': int_port2['port']['id']}
                self.l3_plugin.update_floatingip(
                    self.context, floating_ip['id'],
                    {'floatingip': updated_floating_ip})
                if dvr:
                    if (test_agent_mode ==
                            constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
                        if router1['ha'] and router2['ha']:
                            self.assertEqual(
                                4,
                                l3_notif.routers_updated_on_host.call_count)
                            expected_calls = [
                                mock.call(self.context,
                                          [router1['id']], 'host0'),
                                mock.call(self.context,
                                          [router1['id']], 'standby'),
                                mock.call(self.context,
                                          [router2['id']], 'host0'),
                                mock.call(self.context,
                                          [router2['id']], 'standby')]
                            l3_notif.routers_updated_on_host.assert_has_calls(
                                expected_calls, any_order=True)
                            self.assertFalse(l3_notif.routers_updated.called)
                        else:
                            self.assertEqual(
                                2,
                                l3_notif.routers_updated_on_host.call_count)
                            expected_calls = [
                                mock.call(self.context,
                                          [router1['id']], 'host0'),
                                mock.call(self.context,
                                          [router2['id']], 'host0')]
                            l3_notif.routers_updated_on_host.assert_has_calls(
                                expected_calls)
                            self.assertFalse(l3_notif.routers_updated.called)
                    else:
                        self.assertEqual(
                            2, l3_notif.routers_updated_on_host.call_count)
                        expected_calls = [
                            mock.call(self.context, [router1['id']], 'host1'),
                            mock.call(self.context, [router2['id']], 'host2')]
                        l3_notif.routers_updated_on_host.assert_has_calls(
                            expected_calls)
                        self.assertFalse(l3_notif.routers_updated.called)
                else:
                    self.assertEqual(
                        2, l3_notif.routers_updated.call_count)
                    expected_calls = [
                        mock.call(self.context, [router1['id']], None),
                        mock.call(self.context, [router2['id']], None)]
                    l3_notif.routers_updated.assert_has_calls(
                        expected_calls)
                    self.assertFalse(l3_notif.routers_updated_on_host.called)

    def test_update_floating_ip_agent_notification(self):
        self._test_update_floating_ip_agent_notification()

    def test_update_floating_ip_agent_notification_with_dvr_no_external_agents(
            self):
        agent_mode = constants.L3_AGENT_MODE_DVR_NO_EXTERNAL
        self._test_update_floating_ip_agent_notification(
            test_agent_mode=agent_mode)

    def test_update_floating_ip_agent_notification_non_dvr(self):
        self._test_update_floating_ip_agent_notification(dvr=False)

    def test_delete_floating_ip_with_no_agents(self):
        self._test_delete_floating_ip_agent_notification(
            test_agent_mode=None)

    def _test_delete_floating_ip_agent_notification(
            self, dvr=True, test_agent_mode=constants.L3_AGENT_MODE_DVR):
        with self.subnet() as ext_subnet,\
                self.subnet(cidr='20.0.0.0/24') as int_subnet,\
                self.port(subnet=int_subnet,
                          device_owner=DEVICE_OWNER_COMPUTE) as int_port:
            self.core_plugin.update_port(
                self.context, int_port['port']['id'],
                {'port': {portbindings.HOST_ID: 'host1'}})
            # and create l3 agents on corresponding hosts
            helpers.register_l3_agent(host='host1',
                agent_mode=test_agent_mode)
            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})

            router = self._create_router(distributed=dvr)
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {
                    'external_gateway_info': {'network_id': ext_net_id}}})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': int_subnet['subnet']['id']})

            floating_ip = {'floating_network_id': ext_net_id,
                           'router_id': router['id'],
                           'port_id': int_port['port']['id'],
                           'tenant_id': int_port['port']['tenant_id'],
                           'dns_name': '', 'dns_domain': ''}
            floating_ip = self.l3_plugin.create_floatingip(
                self.context, {'floatingip': floating_ip})
            if test_agent_mode is None:
                with mock.patch.object(
                        self.l3_plugin, 'get_dvr_agent_on_host') as a_mock,\
                        mock.patch.object(self.l3_plugin,
                                          '_l3_rpc_notifier') as l3_notif:
                    a_mock.return_value = None
                    self.l3_plugin.delete_floatingip(
                        self.context, floating_ip['id'])
                    self.assertFalse(
                        l3_notif.routers_updated_on_host.called)
                    return
            with mock.patch.object(
                        self.l3_plugin, '_l3_rpc_notifier') as l3_notif:
                self.l3_plugin.delete_floatingip(
                    self.context, floating_ip['id'])
                if dvr:
                    if test_agent_mode == (
                            constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
                        if router['ha']:
                            expected_calls = [
                                mock.call(self.context,
                                          [router['id']], 'host0'),
                                mock.call(self.context,
                                          [router['id']], 'standby')]
                            l3_notif.routers_updated_on_host.assert_has_calls(
                                expected_calls, any_order=True)
                            self.assertFalse(l3_notif.routers_updated.called)
                        else:
                            l3_notif.routers_updated_on_host.\
                                assert_called_once_with(
                                    self.context, [router['id']], 'host0')
                            self.assertFalse(l3_notif.routers_updated.called)
                    if test_agent_mode == (
                            constants.L3_AGENT_MODE_DVR):
                        l3_notif.routers_updated_on_host.\
                            assert_called_once_with(
                                self.context, [router['id']], 'host1')
                        self.assertFalse(l3_notif.routers_updated.called)
                else:
                    l3_notif.routers_updated.assert_called_once_with(
                        self.context, [router['id']], None)
                    self.assertFalse(
                        l3_notif.routers_updated_on_host.called)

    def test_delete_floating_ip_agent_notification(self):
        self._test_delete_floating_ip_agent_notification()

    def test_delete_floating_ip_agent_notification_with_dvr_no_external_agents(
            self):
        agent_mode = constants.L3_AGENT_MODE_DVR_NO_EXTERNAL
        self._test_delete_floating_ip_agent_notification(
            test_agent_mode=agent_mode)

    def test_delete_floating_ip_agent_notification_non_dvr(self):
        self._test_delete_floating_ip_agent_notification(dvr=False)

    def test_router_with_ipv4_and_multiple_ipv6_on_same_network(self):
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.0.0.1', '10.0.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self._make_subnet(
            self.fmt, ext_net, '2001:db8::1', '2001:db8::/64',
            ip_version=constants.IP_VERSION_6, enable_dhcp=True)
        router1 = self._create_router()
        self.l3_plugin._update_router_gw_info(
            self.context, router1['id'],
            {'network_id': ext_net['network']['id']})
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router1['id']])
        self.assertEqual(0, len(snat_router_intfs[router1['id']]))
        private_net1 = self._make_network(self.fmt, 'net1', True)
        private_ipv6_subnet1 = self._make_subnet(self.fmt,
            private_net1, 'fd00::1',
            cidr='fd00::1/64', ip_version=constants.IP_VERSION_6,
            ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac')
        private_ipv6_subnet2 = self._make_subnet(self.fmt,
            private_net1, 'fd01::1',
            cidr='fd01::1/64', ip_version=constants.IP_VERSION_6,
            ipv6_ra_mode='slaac',
            ipv6_address_mode='slaac')
        # Add the first IPv6 subnet to the router
        self.l3_plugin.add_router_interface(
            self.context, router1['id'],
            {'subnet_id': private_ipv6_subnet1['subnet']['id']})
        # Check for the internal snat port interfaces
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router1['id']])
        self.assertEqual(1, len(snat_router_intfs[router1['id']]))
        # Add the second IPv6 subnet to the router
        self.l3_plugin.add_router_interface(
            self.context, router1['id'],
            {'subnet_id': private_ipv6_subnet2['subnet']['id']})
        # Check for the internal snat port interfaces
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router1['id']])
        snat_intf_list = snat_router_intfs[router1['id']]
        fixed_ips = snat_intf_list[0]['fixed_ips']
        self.assertEqual(1, len(snat_router_intfs[router1['id']]))
        self.assertEqual(2, len(fixed_ips))
        # Now delete the router interface and it should update the
        # SNAT port with the right fixed_ips instead of deleting it.
        self.l3_plugin.remove_router_interface(
            self.context, router1['id'],
            {'subnet_id': private_ipv6_subnet2['subnet']['id']})
        # Check for the internal snat port interfaces
        snat_router_intfs = self.l3_plugin._get_snat_sync_interfaces(
            self.context, [router1['id']])
        snat_intf_list = snat_router_intfs[router1['id']]
        fixed_ips = snat_intf_list[0]['fixed_ips']
        self.assertEqual(1, len(snat_router_intfs[router1['id']]))
        self.assertEqual(1, len(fixed_ips))

    def test_unbound_allowed_addr_pairs_fip_with_multiple_active_vms(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        HOST2 = 'host2'
        helpers.register_l3_agent(
            host=HOST2, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        test_allocation_pools = [{'start': '10.1.0.2',
                                  'end': '10.1.0.20'}]
        fixed_vrrp_ip = [{'ip_address': '10.1.0.201'}]
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])

        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            allocation_pools=test_allocation_pools,
            enable_dhcp=True)
        vrrp_port = self._make_port(
            self.fmt,
            private_net1['network']['id'],
            device_owner='',
            fixed_ips=fixed_vrrp_ip)
        allowed_address_pairs = [
            {'ip_address': '10.1.0.201',
             'mac_address': vrrp_port['port']['mac_address']}]
        with self.port(
                subnet=private_subnet1,
                device_owner=DEVICE_OWNER_COMPUTE) as int_port1,\
                self.port(
                    subnet=private_subnet1,
                    device_owner=DEVICE_OWNER_COMPUTE) as int_port2:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': private_subnet1['subnet']['id']})
            router_handle = (
                self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                    self.context, self.l3_agent['host'], [router['id']]))
            self.assertEqual(self.l3_agent['host'],
                             router_handle[0]['gw_port_host'])
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                vm_port1 = self.core_plugin.update_port(
                    self.context, int_port1['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})
                vm_port2 = self.core_plugin.update_port(
                    self.context, int_port2['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST2}})
                vrrp_port_db = self.core_plugin.get_port(
                    self.context, vrrp_port['port']['id'])
                # Make sure that the VRRP port is not bound to any host
                self.assertNotEqual(vrrp_port_db[portbindings.HOST_ID], HOST1)
                self.assertNotEqual(vrrp_port_db[portbindings.HOST_ID], HOST2)
                self.assertNotEqual(
                    vrrp_port_db[portbindings.HOST_ID], self.l3_agent['host'])
                # Now update both the VM ports with the allowed_address_pair ip
                self.core_plugin.update_port(
                     self.context, vm_port1['id'],
                     {'port': {
                         'allowed_address_pairs': allowed_address_pairs}})
                updated_vm_port1 = self.core_plugin.get_port(
                    self.context, vm_port1['id'])
                expected_allowed_address_pairs1 = updated_vm_port1.get(
                    'allowed_address_pairs')
                self.assertEqual(expected_allowed_address_pairs1,
                                 allowed_address_pairs)
                self.core_plugin.update_port(
                    self.context, vm_port2['id'],
                    {'port': {
                        'allowed_address_pairs': allowed_address_pairs}})
                updated_vm_port2 = self.core_plugin.get_port(
                    self.context, vm_port2['id'])
                expected_allowed_address_pairs2 = updated_vm_port2.get(
                    'allowed_address_pairs')
                self.assertEqual(expected_allowed_address_pairs2,
                                 allowed_address_pairs)
                # Now let us assign the floatingip to the vrrp port that is
                # unbound to any host.
                floating_ip = {'floating_network_id': ext_net['network']['id'],
                               'router_id': router['id'],
                               'port_id': vrrp_port['port']['id'],
                               'tenant_id': vrrp_port['port']['tenant_id']}
                floating_ip = self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})
                expected_routers_updated_calls = [
                    mock.call(self.context, mock.ANY, 'host0'),
                    mock.call(self.context, mock.ANY, HOST1),
                    mock.call(self.context, mock.ANY, HOST2)]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls, any_order=True)
                self.assertFalse(l3_notifier.routers_updated.called)
                router_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, self.l3_agent['host'], [router['id']]))
                floatingips = router_info[0][constants.FLOATINGIP_KEY]
                self.assertTrue(floatingips[0][constants.DVR_SNAT_BOUND])

    def test_dvr_process_floatingips_for_dvr_on_full_sync(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        # Schedule the router to the dvr_snat node
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])

        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            enable_dhcp=True)
        with self.port(
                subnet=private_subnet1,
                device_owner=DEVICE_OWNER_COMPUTE) as int_port1,\
                self.port(
                    subnet=private_subnet1) as int_port2:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': private_subnet1['subnet']['id']})
            router_handle = (
                self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                    self.context, self.l3_agent['host'], [router['id']]))
            self.assertEqual(self.l3_agent['host'],
                             router_handle[0]['gw_port_host'])
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                self.core_plugin.update_port(
                    self.context, int_port1['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})
                # Now let us assign the floatingip to the bound port
                # and unbound port.
                fip1 = {'floating_network_id': ext_net['network']['id'],
                        'router_id': router['id'],
                        'port_id': int_port1['port']['id'],
                        'tenant_id': int_port1['port']['tenant_id']}
                self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': fip1})
                expected_routers_updated_calls = [
                        mock.call(self.context, mock.ANY, HOST1)]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls)
                self.assertFalse(l3_notifier.routers_updated.called)
                fip2 = {'floating_network_id': ext_net['network']['id'],
                        'router_id': router['id'],
                        'port_id': int_port2['port']['id'],
                        'tenant_id': int_port2['port']['tenant_id']}
                self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': fip2})
                router_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, self.l3_agent['host'], [router['id']]))
                floatingips = router_info[0][constants.FLOATINGIP_KEY]
                self.assertEqual(1, len(floatingips))
                self.assertTrue(floatingips[0][constants.DVR_SNAT_BOUND])
                self.assertEqual(constants.FLOATING_IP_HOST_NEEDS_BINDING,
                                 floatingips[0]['host'])
                router1_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, HOST1, [router['id']]))
                floatingips = router1_info[0][constants.FLOATINGIP_KEY]
                self.assertEqual(1, len(floatingips))
                self.assertEqual(HOST1, floatingips[0]['host'])
                self.assertIsNone(floatingips[0]['dest_host'])

    def test_dvr_router_unbound_floating_ip_migrate_to_bound_host(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])

        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            enable_dhcp=True)
        with self.port(
                subnet=private_subnet1,
                device_owner=DEVICE_OWNER_COMPUTE) as int_port1:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': private_subnet1['subnet']['id']})
            router_handle = (
                self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                    self.context, self.l3_agent['host'], [router['id']]))
            self.assertEqual(self.l3_agent['host'],
                             router_handle[0]['gw_port_host'])
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                # Next we can try to associate the floatingip to the
                # VM port
                floating_ip = {'floating_network_id': ext_net['network']['id'],
                               'router_id': router['id'],
                               'port_id': int_port1['port']['id'],
                               'tenant_id': int_port1['port']['tenant_id']}
                floating_ip = self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})

                expected_routers_updated_calls = [
                        mock.call(self.context, mock.ANY, 'host0')]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls)
                self.assertFalse(l3_notifier.routers_updated.called)
                router_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, self.l3_agent['host'], [router['id']]))
                floatingips = router_info[0][constants.FLOATINGIP_KEY]
                self.assertTrue(floatingips[0][constants.DVR_SNAT_BOUND])
                # Now do the host binding to the fip port
                self.core_plugin.update_port(
                    self.context, int_port1['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})
                expected_routers_updated_calls = [
                        mock.call(self.context, mock.ANY, 'host0'),
                        mock.call(self.context, mock.ANY, HOST1)]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls)
                updated_router_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, HOST1, [router['id']]))
                floatingips = updated_router_info[0][constants.FLOATINGIP_KEY]
                self.assertFalse(floatingips[0].get(constants.DVR_SNAT_BOUND))
                self.assertEqual(HOST1, floatingips[0]['host'])

    def test_dvr_router_centralized_floating_ip(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR_NO_EXTERNAL)
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])

        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            enable_dhcp=True)
        with self.port(
                subnet=private_subnet1,
                device_owner=DEVICE_OWNER_COMPUTE) as int_port1:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': private_subnet1['subnet']['id']})
            router_handle = (
                self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                    self.context, self.l3_agent['host'], [router['id']]))
            self.assertEqual(self.l3_agent['host'],
                             router_handle[0]['gw_port_host'])
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                vm_port = self.core_plugin.update_port(
                    self.context, int_port1['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})
                self.assertEqual(
                    1, l3_notifier.routers_updated_on_host.call_count)
                # Next we can try to associate the floatingip to the
                # VM port
                floating_ip = {'floating_network_id': ext_net['network']['id'],
                               'router_id': router['id'],
                               'port_id': vm_port['id'],
                               'tenant_id': vm_port['tenant_id']}
                floating_ip = self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})

                expected_routers_updated_calls = [
                        mock.call(self.context, mock.ANY, HOST1),
                        mock.call(self.context, mock.ANY, 'host0')]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls)
                self.assertFalse(l3_notifier.routers_updated.called)
                router_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, self.l3_agent['host'], [router['id']]))
                floatingips = router_info[0][constants.FLOATINGIP_KEY]
                self.assertTrue(floatingips[0][constants.DVR_SNAT_BOUND])
                # Test case to make sure when an agent in this case
                # dvr_no_external restarts and does a full sync, we need
                # to make sure that the returned router_info has
                # DVR_SNAT_BOUND flag enabled, otherwise the floating IP
                # state would error out.
                router_sync_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, HOST1, [router['id']]))
                floatingips = router_sync_info[0][constants.FLOATINGIP_KEY]
                self.assertTrue(floatingips[0][constants.DVR_SNAT_BOUND])

    def test_allowed_addr_pairs_delayed_fip_and_update_arp_entry(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        HOST2 = 'host2'
        helpers.register_l3_agent(
            host=HOST2, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        test_allocation_pools = [{'start': '10.1.0.2',
                                  'end': '10.1.0.20'}]
        fixed_vrrp_ip = [{'ip_address': '10.1.0.201'}]
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])

        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            allocation_pools=test_allocation_pools,
            enable_dhcp=True)
        vrrp_port = self._make_port(
            self.fmt,
            private_net1['network']['id'],
            fixed_ips=fixed_vrrp_ip)
        allowed_address_pairs = [
            {'ip_address': '10.1.0.201',
             'mac_address': vrrp_port['port']['mac_address']}]
        with self.port(
                subnet=private_subnet1,
                device_owner=DEVICE_OWNER_COMPUTE) as int_port,\
                self.port(subnet=private_subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE) as int_port2:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': private_subnet1['subnet']['id']})
            router_handle = (
                self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                    self.context, self.l3_agent['host'], [router['id']]))
            self.assertEqual(self.l3_agent['host'],
                             router_handle[0]['gw_port_host'])
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                vm_port = self.core_plugin.update_port(
                    self.context, int_port['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})
                vm_port_mac = vm_port['mac_address']
                vm_port_fixed_ips = vm_port['fixed_ips']
                vm_port_subnet_id = vm_port_fixed_ips[0]['subnet_id']
                vm_arp_table = {
                    'ip_address': vm_port_fixed_ips[0]['ip_address'],
                    'mac_address': vm_port_mac,
                    'subnet_id': vm_port_subnet_id}
                vm_port2 = self.core_plugin.update_port(
                    self.context, int_port2['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST2}})
                # Now update the VM port with the allowed_address_pair
                self.core_plugin.update_port(
                     self.context, vm_port['id'],
                     {'port': {
                         'allowed_address_pairs': allowed_address_pairs}})
                self.core_plugin.update_port(
                     self.context, vm_port2['id'],
                     {'port': {
                         'allowed_address_pairs': allowed_address_pairs}})
                self.assertEqual(
                    2, l3_notifier.routers_updated_on_host.call_count)
                updated_vm_port1 = self.core_plugin.get_port(
                    self.context, vm_port['id'])
                updated_vm_port2 = self.core_plugin.get_port(
                    self.context, vm_port2['id'])
                expected_allowed_address_pairs = updated_vm_port1.get(
                    'allowed_address_pairs')
                self.assertEqual(expected_allowed_address_pairs,
                                 allowed_address_pairs)
                expected_allowed_address_pairs_2 = updated_vm_port2.get(
                    'allowed_address_pairs')
                self.assertEqual(expected_allowed_address_pairs_2,
                                 allowed_address_pairs)
                # Now the VRRP port is attached to the VM port. At this
                # point, the VRRP port should not have inherited the
                # port host bindings from the parent VM port.
                cur_vrrp_port_db = self.core_plugin.get_port(
                    self.context, vrrp_port['port']['id'])
                self.assertNotEqual(
                    cur_vrrp_port_db[portbindings.HOST_ID], HOST1)
                self.assertNotEqual(
                    cur_vrrp_port_db[portbindings.HOST_ID], HOST2)
                # Next we can try to associate the floatingip to the
                # VRRP port that is already attached to the VM port
                floating_ip = {'floating_network_id': ext_net['network']['id'],
                               'router_id': router['id'],
                               'port_id': vrrp_port['port']['id'],
                               'tenant_id': vrrp_port['port']['tenant_id']}
                floating_ip = self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})

                post_update_vrrp_port_db = self.core_plugin.get_port(
                    self.context, vrrp_port['port']['id'])
                vrrp_port_fixed_ips = post_update_vrrp_port_db['fixed_ips']
                vrrp_port_subnet_id = vrrp_port_fixed_ips[0]['subnet_id']
                vrrp_arp_table1 = {
                    'ip_address': vrrp_port_fixed_ips[0]['ip_address'],
                    'mac_address': vm_port_mac,
                    'subnet_id': vrrp_port_subnet_id}

                expected_calls = [
                        mock.call(self.context,
                                  router['id'], vm_arp_table),
                        mock.call(self.context,
                                  router['id'], vrrp_arp_table1)]
                l3_notifier.add_arp_entry.assert_has_calls(
                        expected_calls)
                expected_routers_updated_calls = [
                        mock.call(self.context, mock.ANY, HOST1),
                        mock.call(self.context, mock.ANY, HOST2),
                        mock.call(self.context, mock.ANY, 'host0')]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls, any_order=True)
                self.assertFalse(l3_notifier.routers_updated.called)
                router_info = (
                    self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                        self.context, self.l3_agent['host'], [router['id']]))
                floatingips = router_info[0][constants.FLOATINGIP_KEY]
                self.assertTrue(floatingips[0][constants.DVR_SNAT_BOUND])

    def test_dvr_gateway_host_binding_is_set(self):
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])
        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            enable_dhcp=True)
        self.l3_plugin.add_router_interface(
            self.context, router['id'],
            {'subnet_id': private_subnet1['subnet']['id']})
        # Check for the gw_port_host in the router dict to make
        # sure that the _build_routers_list in l3_dvr_db is called.
        router_handle = (
            self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                self.context, self.l3_agent['host'], [router['id']]))
        self.assertEqual(self.l3_agent['host'],
                         router_handle[0]['gw_port_host'])

    def test_allowed_address_pairs_update_arp_entry(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router(ha=False)
        private_net1 = self._make_network(self.fmt, 'net1', True)
        test_allocation_pools = [{'start': '10.1.0.2',
                                  'end': '10.1.0.20'}]
        fixed_vrrp_ip = [{'ip_address': '10.1.0.201'}]
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        ext_net = self._make_network(self.fmt, '', True, **kwargs)
        self._make_subnet(
            self.fmt, ext_net, '10.20.0.1', '10.20.0.0/24',
            ip_version=constants.IP_VERSION_4, enable_dhcp=True)
        self.l3_plugin.schedule_router(self.context,
                                       router['id'],
                                       candidates=[self.l3_agent])
        # Set gateway to router
        self.l3_plugin._update_router_gw_info(
            self.context, router['id'],
            {'network_id': ext_net['network']['id']})
        private_subnet1 = self._make_subnet(
            self.fmt,
            private_net1,
            '10.1.0.1',
            cidr='10.1.0.0/24',
            ip_version=constants.IP_VERSION_4,
            allocation_pools=test_allocation_pools,
            enable_dhcp=True)
        vrrp_port = self._make_port(
            self.fmt,
            private_net1['network']['id'],
            fixed_ips=fixed_vrrp_ip)
        allowed_address_pairs = [
            {'ip_address': '10.1.0.201',
             'mac_address': vrrp_port['port']['mac_address']}]
        with self.port(
                subnet=private_subnet1,
                device_owner=DEVICE_OWNER_COMPUTE) as int_port:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': private_subnet1['subnet']['id']})
            router_handle = (
                self.l3_plugin.list_active_sync_routers_on_active_l3_agent(
                    self.context, self.l3_agent['host'], [router['id']]))
            self.assertEqual(self.l3_agent['host'],
                             router_handle[0]['gw_port_host'])
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                vm_port = self.core_plugin.update_port(
                    self.context, int_port['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})
                vm_port_mac = vm_port['mac_address']
                vm_port_fixed_ips = vm_port['fixed_ips']
                vm_port_subnet_id = vm_port_fixed_ips[0]['subnet_id']
                vm_arp_table = {
                    'ip_address': vm_port_fixed_ips[0]['ip_address'],
                    'mac_address': vm_port_mac,
                    'subnet_id': vm_port_subnet_id}
                self.assertEqual(1, l3_notifier.add_arp_entry.call_count)
                floating_ip = {'floating_network_id': ext_net['network']['id'],
                               'router_id': router['id'],
                               'port_id': vrrp_port['port']['id'],
                               'tenant_id': vrrp_port['port']['tenant_id']}
                floating_ip = self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})
                vrrp_port_db = self.core_plugin.get_port(
                    self.context, vrrp_port['port']['id'])
                self.assertNotEqual(vrrp_port_db[portbindings.HOST_ID], HOST1)
                # Now update the VM port with the allowed_address_pair
                self.core_plugin.update_port(
                     self.context, vm_port['id'],
                     {'port': {
                         'allowed_address_pairs': allowed_address_pairs}})
                updated_vm_port = self.core_plugin.get_port(
                    self.context, vm_port['id'])
                expected_allowed_address_pairs = updated_vm_port.get(
                    'allowed_address_pairs')
                self.assertEqual(expected_allowed_address_pairs,
                                 allowed_address_pairs)
                cur_vrrp_port_db = self.core_plugin.get_port(
                    self.context, vrrp_port['port']['id'])
                vrrp_port_fixed_ips = cur_vrrp_port_db['fixed_ips']
                vrrp_port_subnet_id = vrrp_port_fixed_ips[0]['subnet_id']
                vrrp_arp_table1 = {
                    'ip_address': vrrp_port_fixed_ips[0]['ip_address'],
                    'mac_address': vm_port_mac,
                    'subnet_id': vrrp_port_subnet_id}

                expected_calls = [
                        mock.call(self.context,
                                  router['id'], vm_arp_table),
                        mock.call(self.context,
                                  router['id'], vrrp_arp_table1)]
                l3_notifier.add_arp_entry.assert_has_calls(
                        expected_calls)
                expected_routers_updated_calls = [
                        mock.call(self.context, mock.ANY, HOST1),
                        mock.call(self.context, mock.ANY, 'host0')]
                l3_notifier.routers_updated_on_host.assert_has_calls(
                        expected_routers_updated_calls)
                self.assertFalse(l3_notifier.routers_updated.called)

    def test_update_vm_port_host_router_update(self):
        # register l3 agents in dvr mode in addition to existing dvr_snat agent
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        HOST2 = 'host2'
        helpers.register_l3_agent(
            host=HOST2, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router()
        with self.subnet() as subnet:
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier,\
                    self.port(subnet=subnet,
                              device_owner=DEVICE_OWNER_COMPUTE) as port:
                self.l3_plugin.agent_notifiers[
                    constants.AGENT_TYPE_L3] = l3_notifier
                self.core_plugin.update_port(
                    self.context, port['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST1}})

                l3_notifier.routers_updated_on_host.assert_called_once_with(
                    self.context, {router['id']}, HOST1)
                self.assertFalse(l3_notifier.routers_updated.called)

                # updating port's host (instance migration)
                l3_notifier.reset_mock()
                self.core_plugin.update_port(
                    self.context, port['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST2}})

                l3_notifier.routers_updated_on_host.assert_called_once_with(
                    self.context, {router['id']}, HOST2)
                l3_notifier.router_removed_from_agent.assert_called_once_with(
                    mock.ANY, router['id'], HOST1)

    def test_dvr_router_manual_rescheduling_removes_router(self):
        router = self._create_router()
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.network(**kwargs) as ext_net,\
                self.subnet(network=ext_net),\
                self.subnet(cidr='20.0.0.0/24') as subnet,\
                self.port(subnet=subnet):
            self.l3_plugin._update_router_gw_info(
                self.context, router['id'],
                {'network_id': ext_net['network']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})
            self.l3_plugin.schedule_router(self.context,
                                           router['id'],
                                           candidates=[self.l3_agent])
            # Now the VM should be also scheduled on the node
            notifier = self.l3_plugin.agent_notifiers[
                constants.AGENT_TYPE_L3]
            with mock.patch.object(
                    notifier, 'router_removed_from_agent') as rtr_remove_mock:
                self.l3_plugin.remove_router_from_l3_agent(
                    self.context, self.l3_agent['id'], router['id'])
                rtr_remove_mock.assert_called_once_with(
                    self.context, router['id'], self.l3_agent['host'])

    def test_dvr_router_manual_rescheduling_updates_router(self):
        router = self._create_router()
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.network(**kwargs) as ext_net,\
                self.subnet(network=ext_net),\
                self.subnet(cidr='20.0.0.0/24') as subnet,\
                self.port(subnet=subnet,
                          device_owner=DEVICE_OWNER_COMPUTE) as port:
            self.core_plugin.update_port(
                self.context, port['port']['id'],
                {'port': {'binding:host_id': self.l3_agent['host']}})
            self.l3_plugin._update_router_gw_info(
                self.context, router['id'],
                {'network_id': ext_net['network']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})
            self.l3_plugin.schedule_router(self.context,
                                           router['id'],
                                           candidates=[self.l3_agent])
            # Now the VM should be also scheduled on the node
            notifier = self.l3_plugin.agent_notifiers[
                constants.AGENT_TYPE_L3]
            with mock.patch.object(
                    notifier, 'routers_updated_on_host') as rtr_update_mock:
                self.l3_plugin.remove_router_from_l3_agent(
                    self.context, self.l3_agent['id'], router['id'])
                rtr_update_mock.assert_called_once_with(
                    self.context, [router['id']], self.l3_agent['host'])

    def _test_router_remove_from_agent_on_vm_port_deletion(
            self, non_admin_port=False):
        # register l3 agent in dvr mode in addition to existing dvr_snat agent
        HOST = 'host1'
        non_admin_tenant = 'tenant1'
        helpers.register_l3_agent(
            host=HOST, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router()
        with self.network(shared=True) as net,\
                self.subnet(network=net) as subnet,\
                self.port(subnet=subnet,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          tenant_id=non_admin_tenant,
                          set_context=non_admin_port) as port:
            self.core_plugin.update_port(
                    self.context, port['port']['id'],
                    {'port': {portbindings.HOST_ID: HOST}})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            with mock.patch.object(self.l3_plugin.l3_rpc_notifier,
                                   'router_removed_from_agent') as remove_mock:
                ctx = context.Context(
                    '', non_admin_tenant) if non_admin_port else self.context
                self._delete('ports', port['port']['id'], neutron_context=ctx)
                remove_mock.assert_called_once_with(
                    mock.ANY, router['id'], HOST)

    def test_router_remove_from_agent_on_vm_port_deletion(self):
        self._test_router_remove_from_agent_on_vm_port_deletion()

    def test_admin_router_remove_from_agent_on_vm_port_deletion(self):
        self._test_router_remove_from_agent_on_vm_port_deletion(
            non_admin_port=True)

    def test_dvr_router_notifications_for_live_migration_with_fip(self):
        self._dvr_router_notifications_for_live_migration(
            with_floatingip=True)

    def test_dvr_router_notifications_for_live_migration_without_fip(self):
        self._dvr_router_notifications_for_live_migration()

    def _dvr_router_notifications_for_live_migration(
            self, with_floatingip=False):
        """Check the router notifications go to the right hosts
        with live migration without hostbinding on the port.
        """
        # register l3 agents in dvr mode in addition to existing dvr_snat agent
        HOST1, HOST2 = 'host1', 'host2'
        for host in [HOST1, HOST2]:
            helpers.register_l3_agent(
                host=host, agent_mode=constants.L3_AGENT_MODE_DVR)

        router = self._create_router()
        arg_list = (portbindings.HOST_ID,)
        with self.subnet() as ext_subnet,\
                self.subnet(cidr='20.0.0.0/24') as subnet1,\
                self.port(subnet=subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST1}) as vm_port:
            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})
            # add external gateway to router
            self.l3_plugin.update_router(
                self.context, router['id'],
                {'router': {
                    'external_gateway_info': {'network_id': ext_net_id}}})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet1['subnet']['id']})
            if with_floatingip:
                floating_ip = {'floating_network_id': ext_net_id,
                               'router_id': router['id'],
                               'port_id': vm_port['port']['id'],
                               'tenant_id': vm_port['port']['tenant_id'],
                               'dns_name': '', 'dns_domain': ''}
                floating_ip = self.l3_plugin.create_floatingip(
                    self.context, {'floatingip': floating_ip})

            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier,\
                    mock.patch.object(
                        self.l3_plugin,
                        'create_fip_agent_gw_port_if_not_exists'
                                     ) as fip_agent:
                live_migration_port_profile = {
                    'migrating_to': HOST2
                }
                # Update the VM Port with Migration porbinding Profile.
                # With this change, it should trigger a notification to
                # the Destination host to create a Router ahead of time
                # before the VM Port binding has changed to HOST2.
                updated_port = self.core_plugin.update_port(
                    self.context, vm_port['port']['id'],
                    {'port': {
                        portbindings.PROFILE: live_migration_port_profile}})
                # this will be called twice, once for port update, and once
                # for new binding
                l3_notifier.routers_updated_on_host.assert_any_call(
                    self.context, {router['id']}, HOST2)
                # Check the port-binding is still with the old HOST1, but
                # the router update notification has been sent to the new
                # host 'HOST2' based on the live migration profile change.
                self.assertEqual(updated_port[portbindings.HOST_ID], HOST1)
                self.assertNotEqual(updated_port[portbindings.HOST_ID], HOST2)
                if with_floatingip:
                    fip_agent.return_value = True
                    # Since we have already created the floatingip for the
                    # port, it should be creating the floatingip agent gw
                    # port for the new host if it does not exist.
                    fip_agent.assert_any_call(
                        mock.ANY, floating_ip['floating_network_id'], HOST2)

    def test_router_notifications(self):
        """Check that notifications go to the right hosts in different
        conditions
        """
        # register l3 agents in dvr mode in addition to existing dvr_snat agent
        HOST1, HOST2, HOST3 = 'host1', 'host2', 'host3'
        for host in [HOST1, HOST2, HOST3]:
            helpers.register_l3_agent(
                host=host, agent_mode=constants.L3_AGENT_MODE_DVR)

        router = self._create_router()
        arg_list = (portbindings.HOST_ID,)
        with self.subnet() as ext_subnet,\
                self.subnet(cidr='20.0.0.0/24') as subnet1,\
                self.subnet(cidr='30.0.0.0/24') as subnet2,\
                self.subnet(cidr='40.0.0.0/24') as subnet3,\
                self.port(subnet=subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST1}),\
                self.port(subnet=subnet2,
                          device_owner=constants.DEVICE_OWNER_DHCP,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST2}),\
                self.port(subnet=subnet3,
                          device_owner=constants.DEVICE_OWNER_NEUTRON_PREFIX,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST3}):
            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})

            with mock.patch.object(self.l3_plugin.l3_rpc_notifier.client,
                                   'prepare') as mock_prepare:
                # add external gateway to router
                self.l3_plugin.update_router(
                    self.context, router['id'],
                    {'router': {
                        'external_gateway_info': {'network_id': ext_net_id}}})
                # router has no interfaces so notification goes
                # to only dvr_snat agent
                mock_prepare.assert_called_once_with(
                    server=self.l3_agent['host'],
                    topic=topics.L3_AGENT,
                    version='1.1')

                mock_prepare.reset_mock()
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet1['subnet']['id']})
                self.assertEqual(2, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
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
                self.assertEqual(3, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
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
                self.assertEqual(3, mock_prepare.call_count)
                expected = [mock.call(server=self.l3_agent['host'],
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
        """Check that dvr router is not removed from l3 agent hosting
        SNAT for it on router interface removal
        """
        router = self._create_router()
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.subnet() as subnet,\
                self.network(**kwargs) as ext_net,\
                self.subnet(network=ext_net, cidr='20.0.0.0/24'):
            self.l3_plugin._update_router_gw_info(
                self.context, router['id'],
                {'network_id': ext_net['network']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            agents = self.l3_plugin.list_l3_agents_hosting_router(
                self.context, router['id'])
            self.assertEqual(1, len(agents['agents']))
            with mock.patch.object(self.l3_plugin,
                                   '_l3_rpc_notifier') as l3_notifier:
                self.l3_plugin.remove_router_interface(
                        self.context, router['id'],
                        {'subnet_id': subnet['subnet']['id']})
                agents = self.l3_plugin.list_l3_agents_hosting_router(
                    self.context, router['id'])
                self.assertEqual(1, len(agents['agents']))
                self.assertFalse(l3_notifier.router_removed_from_agent.called)

    def test_router_is_not_removed_from_snat_agent_on_dhcp_port_deletion(self):
        """Check that dvr router is not removed from l3 agent hosting
        SNAT for it on DHCP port removal
        """
        router = self._create_router()
        kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                  extnet_apidef.EXTERNAL: True}
        with self.network(**kwargs) as ext_net,\
                self.subnet(network=ext_net),\
                self.subnet(cidr='20.0.0.0/24') as subnet,\
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

            # router should be scheduled to the dvr_snat l3 agent
            agents = self.l3_plugin.list_l3_agents_hosting_router(
                self.context, router['id'])
            self.assertEqual(1, len(agents['agents']))
            self.assertEqual(self.l3_agent['id'], agents['agents'][0]['id'])

            notifier = self.l3_plugin.agent_notifiers[
                constants.AGENT_TYPE_L3]
            with mock.patch.object(
                    notifier, 'router_removed_from_agent') as remove_mock:
                self._delete('ports', port['port']['id'])
                # now when port is deleted the router still has external
                # gateway and should still be scheduled to the snat agent
                agents = self.l3_plugin.list_l3_agents_hosting_router(
                    self.context, router['id'])
                self.assertEqual(1, len(agents['agents']))
                self.assertEqual(self.l3_agent['id'],
                                 agents['agents'][0]['id'])
                self.assertFalse(remove_mock.called)

    def test__get_dvr_subnet_ids_on_host_query(self):
        with self.subnet(cidr='20.0.0.0/24') as subnet1,\
                self.subnet(cidr='30.0.0.0/24') as subnet2,\
                self.subnet(cidr='40.0.0.0/24') as subnet3,\
                self.port(subnet=subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE) as p1,\
                self.port(subnet=subnet2,
                          device_owner=constants.DEVICE_OWNER_DHCP) as p2,\
                self.port(subnet=subnet3,
                          device_owner=constants.DEVICE_OWNER_NEUTRON_PREFIX)\
                as p3,\
                self.port(subnet=subnet3,
                          device_owner=constants.DEVICE_OWNER_COMPUTE_PREFIX)\
                as p4:
            host = 'host1'

            subnet_ids = [item[0] for item in
                          self.l3_plugin._get_dvr_subnet_ids_on_host_query(
                              self.context, host)]
            self.assertEqual([], subnet_ids)

            self.core_plugin.update_port(
                self.context, p1['port']['id'],
                {'port': {portbindings.HOST_ID: host}})
            expected = {subnet1['subnet']['id']}
            subnet_ids = [item[0] for item in
                          self.l3_plugin._get_dvr_subnet_ids_on_host_query(
                              self.context, host)]
            self.assertEqual(expected, set(subnet_ids))

            self.core_plugin.update_port(
                self.context, p2['port']['id'],
                {'port': {portbindings.HOST_ID: host}})
            expected.add(subnet2['subnet']['id'])
            subnet_ids = [item[0] for item in
                          self.l3_plugin._get_dvr_subnet_ids_on_host_query(
                              self.context, host)]
            self.assertEqual(expected, set(subnet_ids))

            self.core_plugin.update_port(
                self.context, p3['port']['id'],
                {'port': {portbindings.HOST_ID: host}})
            # p3 is non dvr serviceable so no subnet3 expected
            subnet_ids = [item[0] for item in
                          self.l3_plugin._get_dvr_subnet_ids_on_host_query(
                              self.context, host)]
            self.assertEqual(expected, set(subnet_ids))

            other_host = 'other' + host
            self.core_plugin.update_port(
                self.context, p4['port']['id'],
                {'port': {portbindings.HOST_ID: other_host}})
            # p4 is on other host so no subnet3 expected
            subnet_ids = [item[0] for item in
                          self.l3_plugin._get_dvr_subnet_ids_on_host_query(
                              self.context, host)]
            self.assertEqual(expected, set(subnet_ids))

            self.core_plugin.update_port(
                self.context, p4['port']['id'],
                {'port': {portbindings.HOST_ID: host}})
            # finally p4 is on the right host so subnet3 is expected
            expected.add(subnet3['subnet']['id'])
            subnet_ids = [item[0] for item in
                          self.l3_plugin._get_dvr_subnet_ids_on_host_query(
                              self.context, host)]
            self.assertEqual(expected, set(subnet_ids))

    def test__get_dvr_router_ids_for_host(self):
        router1 = self._create_router()
        router2 = self._create_router()
        host = 'host1'
        arg_list = (portbindings.HOST_ID,)
        with self.subnet(cidr='20.0.0.0/24') as subnet1,\
                self.subnet(cidr='30.0.0.0/24') as subnet2,\
                self.port(subnet=subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: host}),\
                self.port(subnet=subnet2,
                          device_owner=constants.DEVICE_OWNER_DHCP,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: host}):

            router_ids = self.l3_plugin._get_dvr_router_ids_for_host(
                self.context, host)
            self.assertEqual([], router_ids)

            self.l3_plugin.add_router_interface(
                self.context, router1['id'],
                {'subnet_id': subnet1['subnet']['id']})
            router_ids = self.l3_plugin._get_dvr_router_ids_for_host(
                self.context, host)
            expected = {router1['id']}
            self.assertEqual(expected, set(router_ids))

            self.l3_plugin.add_router_interface(
                self.context, router2['id'],
                {'subnet_id': subnet2['subnet']['id']})
            router_ids = self.l3_plugin._get_dvr_router_ids_for_host(
                self.context, host)
            expected.add(router2['id'])
            self.assertEqual(expected, set(router_ids))

    def test__get_router_ids_for_agent(self):
        router1 = self._create_router()
        router2 = self._create_router()
        router3 = self._create_router()
        arg_list = (portbindings.HOST_ID,)
        host = self.l3_agent['host']
        with self.subnet() as ext_subnet,\
                self.subnet(cidr='20.0.0.0/24') as subnet1,\
                self.subnet(cidr='30.0.0.0/24') as subnet2,\
                self.port(subnet=subnet1,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: host}),\
                self.port(subnet=subnet2,
                          device_owner=constants.DEVICE_OWNER_DHCP,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: host}):
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [])
            self.assertEqual([], ids)
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router1['id'], router2['id']])
            self.assertEqual([], ids)

            self.l3_plugin.add_router_interface(
                self.context, router1['id'],
                {'subnet_id': subnet1['subnet']['id']})
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [])
            self.assertEqual([router1['id']], ids)
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router1['id']])
            self.assertEqual([router1['id']], ids)
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router1['id'], router2['id']])
            self.assertEqual([router1['id']], ids)
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router2['id']])
            self.assertEqual([], ids)

            self.l3_plugin.add_router_interface(
                self.context, router2['id'],
                {'subnet_id': subnet2['subnet']['id']})
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [])
            self.assertEqual({router1['id'], router2['id']}, set(ids))
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router1['id']])
            self.assertEqual([router1['id']], ids)
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router1['id'], router2['id']])
            self.assertEqual({router1['id'], router2['id']}, set(ids))
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router2['id']])
            self.assertEqual([router2['id']], ids)

            # make net external
            ext_net_id = ext_subnet['subnet']['network_id']
            self._update('networks', ext_net_id,
                     {'network': {extnet_apidef.EXTERNAL: True}})
            # add external gateway to router
            self.l3_plugin.update_router(
                self.context, router3['id'],
                {'router': {
                    'external_gateway_info': {'network_id': ext_net_id}}})
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [])
            self.assertEqual({router1['id'], router2['id'], router3['id']},
                             set(ids))
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router3['id']])
            self.assertEqual([router3['id']], ids)
            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, self.l3_agent, [router1['id'], router3['id']])
            self.assertEqual({router1['id'], router3['id']}, set(ids))

    def test__get_router_ids_for_agent_related_router(self):
        router1 = self._create_router()
        router2 = self._create_router()
        router3 = self._create_router()
        arg_list = (portbindings.HOST_ID,)
        dvr_l3_agent = helpers.register_l3_agent(
            host="host1", agent_mode=constants.L3_AGENT_MODE_DVR)
        host = dvr_l3_agent['host']
        with self.subnet() as wan_subnet,\
                self.subnet(cidr='20.0.0.0/24') as subnet1,\
                self.subnet(cidr='30.0.0.0/24') as subnet2,\
                self.subnet(cidr='40.0.0.0/24') as subnet3,\
                self.port(subnet=wan_subnet) as wan_port1,\
                self.port(subnet=wan_subnet) as wan_port2,\
                self.port(subnet=subnet1,
                          device_owner=constants.DEVICE_OWNER_DHCP,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: host}):

            self.l3_plugin.add_router_interface(
                self.context, router1['id'],
                {'subnet_id': subnet1['subnet']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router2['id'],
                {'subnet_id': subnet2['subnet']['id']})
            # Router3 is here just to be sure that it will not be returned as
            # is not related to the router1 and router2 in any way
            self.l3_plugin.add_router_interface(
                self.context, router3['id'],
                {'subnet_id': subnet3['subnet']['id']})

            self.l3_plugin.add_router_interface(
                self.context, router1['id'],
                {'port_id': wan_port1['port']['id']})
            self.l3_plugin.add_router_interface(
                self.context, router2['id'],
                {'port_id': wan_port2['port']['id']})

            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, dvr_l3_agent, [])
            self.assertEqual({router1['id'], router2['id']}, set(ids))

            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, dvr_l3_agent, [router2['id']])
            self.assertEqual({router1['id'], router2['id']}, set(ids))

            ids = self.l3_plugin._get_router_ids_for_agent(
                self.context, dvr_l3_agent, [router1['id']])
            self.assertEqual({router1['id'], router2['id']}, set(ids))

    def test_remove_router_interface(self):
        HOST1 = 'host1'
        helpers.register_l3_agent(
            host=HOST1, agent_mode=constants.L3_AGENT_MODE_DVR)
        router = self._create_router()
        arg_list = (portbindings.HOST_ID,)
        with self.subnet() as subnet,\
                self.port(subnet=subnet,
                          device_owner=DEVICE_OWNER_COMPUTE,
                          arg_list=arg_list,
                          **{portbindings.HOST_ID: HOST1}):
            l3_notifier = mock.Mock()
            self.l3_plugin.l3_rpc_notifier = l3_notifier
            self.l3_plugin.agent_notifiers[
                    constants.AGENT_TYPE_L3] = l3_notifier

            self.l3_plugin.add_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})
            self.l3_plugin.schedule_router(self.context, router['id'])

            self.l3_plugin.remove_router_interface(
                self.context, router['id'],
                {'subnet_id': subnet['subnet']['id']})

            l3_notifier.router_removed_from_agent.assert_called_once_with(
                mock.ANY, router['id'], HOST1)

    def test_router_auto_scheduling(self):
        router = self._create_router()
        agents = self.l3_plugin.list_l3_agents_hosting_router(
                self.context, router['id'])
        # router is not scheduled yet
        self.assertEqual([], agents['agents'])

        l3_rpc_handler = l3_rpc.L3RpcCallback()
        # router should be auto scheduled once l3 agent requests router ids
        l3_rpc_handler.get_router_ids(self.context, self.l3_agent['host'])
        agents = self.l3_plugin.list_l3_agents_hosting_router(
            self.context, router['id'])
        self.assertEqual(1, len(agents['agents']))
        self.assertEqual(self.l3_agent['id'], agents['agents'][0]['id'])

    def test_add_router_interface_by_subnet_notifications(self):
        notif_handler_before = mock.Mock()
        notif_handler_after = mock.Mock()
        registry.subscribe(notif_handler_before.callback,
                           resources.ROUTER_INTERFACE,
                           events.BEFORE_CREATE)
        registry.subscribe(notif_handler_after.callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        router = self._create_router()
        with self.network() as net, \
                self.subnet(network=net) as subnet:
            interface_info = {'subnet_id': subnet['subnet']['id']}
            self.l3_plugin.add_router_interface(
                    self.context, router['id'], interface_info)
            kwargs = {'context': self.context, 'router_id': router['id'],
                      'network_id': net['network']['id'],
                      'router_db': mock.ANY,
                      'port': mock.ANY,
                      'interface_info': interface_info}
            notif_handler_before.callback.assert_called_once_with(
                resources.ROUTER_INTERFACE, events.BEFORE_CREATE,
                mock.ANY, **kwargs)
            kwargs_after = {'cidrs': mock.ANY,
                            'context': mock.ANY,
                            'gateway_ips': mock.ANY,
                            'interface_info': mock.ANY,
                            'network_id': None,
                            'port': mock.ANY,
                            'new_interface': True,
                            'subnets': mock.ANY,
                            'port_id': mock.ANY,
                            'router_id': router['id']}
            notif_handler_after.callback.assert_called_once_with(
                resources.ROUTER_INTERFACE, events.AFTER_CREATE,
                mock.ANY, **kwargs_after)

    def test_add_router_interface_by_port_notifications(self):
        notif_handler_before = mock.Mock()
        notif_handler_after = mock.Mock()
        registry.subscribe(notif_handler_before.callback,
                           resources.ROUTER_INTERFACE,
                           events.BEFORE_CREATE)
        registry.subscribe(notif_handler_after.callback,
                           resources.ROUTER_INTERFACE,
                           events.AFTER_CREATE)
        router = self._create_router()
        with self.network() as net, \
                self.subnet(network=net) as subnet, \
                self.port(subnet=subnet) as port:
            interface_info = {'port_id': port['port']['id']}
            self.l3_plugin.add_router_interface(
                    self.context, router['id'], interface_info)
            kwargs = {'context': self.context, 'router_id': router['id'],
                      'network_id': net['network']['id'],
                      'router_db': mock.ANY,
                      'port': mock.ANY,
                      'interface_info': interface_info}
            notif_handler_before.callback.assert_called_once_with(
                resources.ROUTER_INTERFACE, events.BEFORE_CREATE,
                mock.ANY, **kwargs)
            kwargs_after = {'cidrs': mock.ANY,
                            'context': mock.ANY,
                            'gateway_ips': mock.ANY,
                            'interface_info': mock.ANY,
                            'network_id': None,
                            'port': mock.ANY,
                            'new_interface': True,
                            'subnets': mock.ANY,
                            'port_id': port['port']['id'],
                            'router_id': router['id']}
            notif_handler_after.callback.assert_called_once_with(
                resources.ROUTER_INTERFACE, events.AFTER_CREATE,
                mock.ANY, **kwargs_after)


class L3DvrTestCaseMigration(L3DvrTestCaseBase):
    def test_update_router_db_centralized_to_distributed_with_ports(self):
        with self.subnet() as subnet1:
            kwargs = {'arg_list': (extnet_apidef.EXTERNAL,),
                      extnet_apidef.EXTERNAL: True}
            with self.network(**kwargs) as ext_net, \
                    self.subnet(network=ext_net,
                                cidr='30.0.0.0/24'):
                router = self._create_router(distributed=False)
                self.l3_plugin.add_router_interface(
                    self.context, router['id'],
                    {'subnet_id': subnet1['subnet']['id']})
                self.l3_plugin._update_router_gw_info(
                    self.context, router['id'],
                    {'network_id': ext_net['network']['id']})
                self.assertEqual(
                    0, len(self.l3_plugin._get_snat_sync_interfaces(
                        self.context, [router['id']])))

                # router needs to be in admin state down in order to be
                # upgraded to DVR
                self.l3_plugin.update_router(
                    self.context, router['id'],
                    {'router': {'admin_state_up': False}})
                self.assertFalse(router['distributed'])
                self.l3_plugin.update_router(
                    self.context, router['id'],
                    {'router': {'distributed': True}})
                router = self.l3_plugin.get_router(self.context, router['id'])
                self.assertTrue(router['distributed'])
                self.assertEqual(
                    1, len(self.l3_plugin._get_snat_sync_interfaces(
                        self.context, [router['id']])))
