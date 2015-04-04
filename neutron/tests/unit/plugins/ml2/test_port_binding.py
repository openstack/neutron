# Copyright (c) 2013 OpenStack Foundation
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

from neutron import context
from neutron.extensions import portbindings
from neutron import manager
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2 import models as ml2_models
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin


PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class PortBindingTestCase(test_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = PLUGIN_NAME

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'test'],
                                     'ml2')
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['physnet1:1000:1099'],
                                     group='ml2_type_vlan')
        super(PortBindingTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        self.plugin = manager.NeutronManager.get_plugin()
        self.plugin.start_rpc_listeners()

    def _check_response(self, port, vif_type, has_port_filter, bound, status):
        self.assertEqual(port[portbindings.VIF_TYPE], vif_type)
        vif_details = port[portbindings.VIF_DETAILS]
        port_status = port['status']
        if bound:
            # TODO(rkukura): Replace with new VIF security details
            self.assertEqual(vif_details[portbindings.CAP_PORT_FILTER],
                             has_port_filter)
            self.assertEqual(port_status, status or 'DOWN')
        else:
            self.assertEqual(port_status, 'DOWN')

    def _test_port_binding(self, host, vif_type, has_port_filter, bound,
                           status=None, network_type='local'):
        mac_address = 'aa:aa:aa:aa:aa:aa'
        host_arg = {portbindings.HOST_ID: host,
                    'mac_address': mac_address}
        with self.port(name='name', arg_list=(portbindings.HOST_ID,),
                       **host_arg) as port:
            self._check_response(port['port'], vif_type, has_port_filter,
                                 bound, status)
            port_id = port['port']['id']
            neutron_context = context.get_admin_context()
            details = self.plugin.endpoints[0].get_device_details(
                neutron_context, agent_id="theAgentId", device=port_id)
            if bound:
                self.assertEqual(details['network_type'], network_type)
                self.assertEqual(mac_address, details['mac_address'])
            else:
                self.assertNotIn('network_type', details)
                self.assertNotIn('mac_address', details)

    def test_unbound(self):
        self._test_port_binding("",
                                portbindings.VIF_TYPE_UNBOUND,
                                False, False)

    def test_binding_failed(self):
        self._test_port_binding("host-fail",
                                portbindings.VIF_TYPE_BINDING_FAILED,
                                False, False)

    def test_binding_no_filter(self):
        self._test_port_binding("host-ovs-no_filter",
                                portbindings.VIF_TYPE_OVS,
                                False, True)

    def test_binding_filter(self):
        self._test_port_binding("host-bridge-filter",
                                portbindings.VIF_TYPE_BRIDGE,
                                True, True)

    def test_binding_status_active(self):
        self._test_port_binding("host-ovs-filter-active",
                                portbindings.VIF_TYPE_OVS,
                                True, True, 'ACTIVE')

    def test_update_port_binding_no_binding(self):
        ctx = context.get_admin_context()
        with self.port(name='name') as port:
            # emulating concurrent binding deletion
            (ctx.session.query(ml2_models.PortBinding).
             filter_by(port_id=port['port']['id']).delete())
            self.assertIsNone(
                self.plugin.get_bound_port_context(ctx, port['port']['id']))

    def test_hierarchical_binding(self):
        self._test_port_binding("host-hierarchical",
                                portbindings.VIF_TYPE_OVS,
                                False, True, network_type='vlan')

    def test_get_bound_port_context_cache_hit(self):
        ctx = context.get_admin_context()
        with self.port(name='name') as port:
            cached_network_id = port['port']['network_id']
            some_network = {'id': cached_network_id}
            cached_networks = {cached_network_id: some_network}
            self.plugin.get_network = mock.Mock(return_value=some_network)
            self.plugin.get_bound_port_context(ctx, port['port']['id'],
                                               cached_networks=cached_networks)
            self.assertFalse(self.plugin.get_network.called)

    def test_get_bound_port_context_cache_miss(self):
        ctx = context.get_admin_context()
        with self.port(name='name') as port:
            some_network = {'id': u'2ac23560-7638-44e2-9875-c1888b02af72'}
            self.plugin.get_network = mock.Mock(return_value=some_network)
            self.plugin.get_bound_port_context(ctx, port['port']['id'],
                                               cached_networks={})
            self.assertEqual(1, self.plugin.get_network.call_count)

    def _test_update_port_binding(self, host, new_host=None):
        with mock.patch.object(self.plugin,
                               '_notify_port_updated') as notify_mock:
            host_arg = {portbindings.HOST_ID: host}
            update_body = {'name': 'test_update'}
            if new_host is not None:
                update_body[portbindings.HOST_ID] = new_host
            with self.port(name='name', arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port:
                neutron_context = context.get_admin_context()
                updated_port = self._update('ports', port['port']['id'],
                                            {'port': update_body},
                                            neutron_context=neutron_context)
                port_data = updated_port['port']
                if new_host is not None:
                    self.assertEqual(port_data[portbindings.HOST_ID],
                                     new_host)
                else:
                    self.assertEqual(port_data[portbindings.HOST_ID], host)
                if new_host is not None and new_host != host:
                    notify_mock.assert_called_once_with(mock.ANY)
                else:
                    self.assertFalse(notify_mock.called)

    def test_update_with_new_host_binding_notifies_agent(self):
        self._test_update_port_binding('host-ovs-no_filter',
                                       'host-bridge-filter')

    def test_update_with_same_host_binding_does_not_notify(self):
        self._test_update_port_binding('host-ovs-no_filter',
                                       'host-ovs-no_filter')

    def test_update_without_binding_does_not_notify(self):
        self._test_update_port_binding('host-ovs-no_filter')

    def testt_update_from_empty_to_host_binding_notifies_agent(self):
        self._test_update_port_binding('', 'host-ovs-no_filter')

    def test_update_from_host_to_empty_binding_notifies_agent(self):
        self._test_update_port_binding('host-ovs-no_filter', '')
