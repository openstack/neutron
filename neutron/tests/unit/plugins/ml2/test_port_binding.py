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

from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import portbindings_extended as pbe_ext
from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils
from oslo_config import cfg
from oslo_serialization import jsonutils
import webob.exc

from neutron.conf.plugins.ml2 import config
from neutron.conf.plugins.ml2.drivers import driver_type
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import models as ml2_models
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.plugins.ml2.drivers import mechanism_test


class PortBindingTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        cfg.CONF.set_override('mechanism_drivers',
                              ['logger', 'test'],
                              'ml2')

        # NOTE(dasm): ml2_type_vlan requires to be registered before used.
        # This piece was refactored and removed from .config, so it causes
        # a problem, when tests are executed with pdb.
        # There is no problem when tests are running without debugger.
        driver_type.register_ml2_drivers_vlan_opts()
        cfg.CONF.set_override('network_vlan_ranges',
                              ['physnet1:1000:1099'],
                              group='ml2_type_vlan')
        super(PortBindingTestCase, self).setUp('ml2')
        self.port_create_status = 'DOWN'
        self.plugin = directory.get_plugin()
        self.plugin.start_rpc_listeners()

    def _check_response(self, port, vif_type, has_port_filter, bound, status):
        self.assertEqual(vif_type, port[portbindings.VIF_TYPE])
        vif_details = port[portbindings.VIF_DETAILS]
        port_status = port['status']
        if bound:
            # TODO(rkukura): Replace with new VIF security details
            self.assertEqual(has_port_filter,
                             vif_details[portbindings.CAP_PORT_FILTER])
            self.assertEqual(status or 'DOWN', port_status)
        else:
            self.assertEqual('DOWN', port_status)

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
                self.assertEqual(network_type, details['network_type'])
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
            with db_api.CONTEXT_WRITER.using(ctx):
                for item in (ctx.session.query(ml2_models.PortBinding).
                             filter_by(port_id=port['port']['id'])):
                    ctx.session.delete(item)
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
                    self.assertEqual(new_host,
                                     port_data[portbindings.HOST_ID])
                else:
                    self.assertEqual(host, port_data[portbindings.HOST_ID])
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

    def test_process_binding_port_host_id_changed(self):
        ctx = context.get_admin_context()
        plugin = directory.get_plugin()
        host_id = {portbindings.HOST_ID: 'host1'}
        with self.port(**host_id) as port:
            # Since the port is DOWN at first
            # It's necessary to make its status ACTIVE for this test
            plugin.update_port_status(ctx, port['port']['id'],
                const.PORT_STATUS_ACTIVE)

            attrs = port['port']
            attrs['status'] = const.PORT_STATUS_ACTIVE
            original_port = attrs.copy()
            attrs['binding:host_id'] = 'host2'
            updated_port = attrs.copy()
            network = {'id': attrs['network_id']}
            binding = ml2_models.PortBinding(
                port_id=original_port['id'],
                host=original_port['binding:host_id'],
                vnic_type=original_port['binding:vnic_type'],
                profile=jsonutils.dumps(original_port['binding:profile']),
                vif_type=original_port['binding:vif_type'],
                vif_details=original_port['binding:vif_details'])
            levels = []
            mech_context = driver_context.PortContext(
                plugin, ctx, updated_port, network, binding, levels,
                original_port=original_port)

            plugin._process_port_binding(mech_context, port['port'])
            self.assertEqual(const.PORT_STATUS_DOWN, updated_port['status'])
            port_dict = plugin.get_port(ctx, port['port']['id'])
            self.assertEqual(const.PORT_STATUS_DOWN, port_dict['status'])

    def test_distributed_binding(self):
        ctx = context.get_admin_context()
        with self.port(device_owner=const.DEVICE_OWNER_DVR_INTERFACE) as port:
            port_id = port['port']['id']

            # Verify port's VIF type and status.
            self.assertEqual(portbindings.VIF_TYPE_DISTRIBUTED,
                             port['port'][portbindings.VIF_TYPE])
            self.assertEqual('DOWN', port['port']['status'])

            # Update port to bind for a host.
            self.plugin.update_distributed_port_binding(ctx, port_id, {'port':
                {portbindings.HOST_ID: 'host-ovs-no_filter',
                 'device_id': 'router1'}})

            # Get port and verify VIF type and status unchanged.
            port = self._show('ports', port_id)
            self.assertEqual(portbindings.VIF_TYPE_DISTRIBUTED,
                             port['port'][portbindings.VIF_TYPE])
            self.assertEqual('DOWN', port['port']['status'])

            # Get and verify binding details for host
            details = self.plugin.endpoints[0].get_device_details(
                ctx, agent_id="theAgentId", device=port_id,
                host='host-ovs-no_filter')
            self.assertEqual('local', details['network_type'])

            # Get port and verify VIF type and changed status.
            port = self._show('ports', port_id)
            self.assertEqual(portbindings.VIF_TYPE_DISTRIBUTED,
                             port['port'][portbindings.VIF_TYPE])
            self.assertEqual('BUILD', port['port']['status'])

            # Mark device up.
            self.plugin.endpoints[0].update_device_up(
                ctx, agent_id="theAgentId", device=port_id,
                host='host-ovs-no_filter')

            # Get port and verify VIF type and changed status.
            port = self._show('ports', port_id)
            self.assertEqual(portbindings.VIF_TYPE_DISTRIBUTED,
                             port['port'][portbindings.VIF_TYPE])
            self.assertEqual('ACTIVE', port['port']['status'])

            # Mark device down.
            self.plugin.endpoints[0].update_device_down(
                ctx, agent_id="theAgentId", device=port_id,
                host='host-ovs-no_filter')

            # Get port and verify VIF type and changed status.
            port = self._show('ports', port_id)
            self.assertEqual(portbindings.VIF_TYPE_DISTRIBUTED,
                             port['port'][portbindings.VIF_TYPE])
            self.assertEqual('DOWN', port['port']['status'])

    def test_distributed_binding_multi_host_status(self):
        ctx = context.get_admin_context()
        with self.port(device_owner=const.DEVICE_OWNER_DVR_INTERFACE) as port:
            port_id = port['port']['id']

            # Update port to bind for 1st host.
            self.plugin.update_distributed_port_binding(ctx, port_id, {'port':
                {portbindings.HOST_ID: 'host-ovs-no_filter',
                 'device_id': 'router1'}})

            # Mark 1st device up.
            self.plugin.endpoints[0].update_device_up(
                ctx, agent_id="theAgentId", device=port_id,
                host='host-ovs-no_filter')

            # Get port and verify status is ACTIVE.
            port = self._show('ports', port_id)
            self.assertEqual('ACTIVE', port['port']['status'])

            # Update port to bind for a 2nd host.
            self.plugin.update_distributed_port_binding(ctx, port_id, {'port':
                {portbindings.HOST_ID: 'host-bridge-filter',
                 'device_id': 'router1'}})

            # Mark 2nd device up.
            self.plugin.endpoints[0].update_device_up(
                ctx, agent_id="the2ndAgentId", device=port_id,
                host='host-bridge-filter')

            # Get port and verify status unchanged.
            port = self._show('ports', port_id)
            self.assertEqual('ACTIVE', port['port']['status'])

            # Mark 1st device down.
            self.plugin.endpoints[0].update_device_down(
                ctx, agent_id="theAgentId", device=port_id,
                host='host-ovs-no_filter')

            # Get port and verify status unchanged.
            port = self._show('ports', port_id)
            self.assertEqual('ACTIVE', port['port']['status'])

            # Mark 2nd device down.
            self.plugin.endpoints[0].update_device_down(
                ctx, agent_id="the2ndAgentId", device=port_id,
                host='host-bridge-filter')

            # Get port and verify status is DOWN.
            port = self._show('ports', port_id)
            self.assertEqual('DOWN', port['port']['status'])

    def test_distributed_binding_update_unbound_host(self):
        ctx = context.get_admin_context()
        with self.port(device_owner=const.DEVICE_OWNER_DVR_INTERFACE) as port:
            port_id = port['port']['id']

            # Mark device up without first binding on host.
            self.plugin.endpoints[0].update_device_up(
                ctx, agent_id="theAgentId", device=port_id,
                host='host-ovs-no_filter')

            # Get port and verify status is still DOWN.
            port = self._show('ports', port_id)
            self.assertEqual('DOWN', port['port']['status'])


class ExtendedPortBindingTestCase(test_plugin.NeutronDbPluginV2TestCase):

    host = 'host-ovs-no_filter'

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.register_ml2_plugin_opts()
        cfg.CONF.set_override('mechanism_drivers',
                              ['logger', 'test'],
                              'ml2')

        driver_type.register_ml2_drivers_vlan_opts()
        cfg.CONF.set_override('network_vlan_ranges',
                              ['physnet1:1000:1099'],
                              group='ml2_type_vlan')
        super(ExtendedPortBindingTestCase, self).setUp('ml2')
        self.port_create_status = 'DOWN'
        self.plugin = directory.get_plugin()
        self.plugin.start_rpc_listeners()

    def _create_port_binding(self, fmt, port_id, host, tenant_id=None,
                             **kwargs):
        tenant_id = tenant_id or self._tenant_id
        data = {'binding': {'host': host, 'tenant_id': tenant_id}}
        if kwargs:
            data['binding'].update(kwargs)
        binding_resource = 'ports/%s/bindings' % port_id
        binding_req = self.new_create_request(binding_resource, data, fmt)
        return binding_req.get_response(self.api)

    def _make_port_binding(self, fmt, port_id, host, **kwargs):
        res = self._create_port_binding(fmt, port_id, host, **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    def _update_port_binding(self, fmt, port_id, host, **kwargs):
        data = {'binding': kwargs}
        binding_req = self.new_update_request('ports', data, port_id, fmt,
                                              subresource='bindings',
                                              sub_id=host)
        return binding_req.get_response(self.api)

    def _do_update_port_binding(self, fmt, port_id, host, **kwargs):
        res = self._update_port_binding(fmt, port_id, host, **kwargs)
        if res.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    def _activate_port_binding(self, port_id, host, raw_response=True):
        response = self._req('PUT', 'ports', id=port_id,
                             data={'port_id': port_id},
                             subresource='bindings', sub_id=host,
                             action='activate').get_response(self.api)
        return self._check_code_and_serialize(response, raw_response)

    def _check_code_and_serialize(self, response, raw_response):
        if raw_response:
            return response
        if response.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    def _list_port_bindings(self, port_id, params=None, raw_response=True):
        response = self._req(
            'GET', 'ports', fmt=self.fmt, id=port_id, subresource='bindings',
            params=params).get_response(self.api)
        return self._check_code_and_serialize(response, raw_response)

    def _show_port_binding(self, port_id, host, params=None,
                           raw_response=True):
        response = self._req(
            'GET', 'ports', fmt=self.fmt, id=port_id, subresource='bindings',
            sub_id=host, params=params).get_response(self.api)
        return self._check_code_and_serialize(response, raw_response)

    def _delete_port_binding(self, port_id, host):
        response = self._req(
            'DELETE', 'ports', fmt=self.fmt, id=port_id,
            subresource='bindings', sub_id=host).get_response(self.api)
        return response

    def _create_port_and_binding(self, **kwargs):
        device_owner = '%s%s' % (const.DEVICE_OWNER_COMPUTE_PREFIX, 'nova')
        with self.port(device_owner=device_owner) as port:
            port_id = port['port']['id']
            binding = self._make_port_binding(self.fmt, port_id, self.host,
                                              **kwargs)['binding']
            self._assert_bound_port_binding(binding)
            return port['port'], binding

    def _assert_bound_port_binding(self, binding):
        self.assertEqual(self.host, binding[pbe_ext.HOST])
        self.assertEqual(portbindings.VIF_TYPE_OVS,
                         binding[pbe_ext.VIF_TYPE])
        self.assertEqual({'port_filter': False},
                         binding[pbe_ext.VIF_DETAILS])

    def _assert_unbound_port_binding(self, binding):
        self.assertFalse(binding[pbe_ext.HOST])
        self.assertEqual(portbindings.VIF_TYPE_UNBOUND,
                         binding[pbe_ext.VIF_TYPE])
        self.assertEqual({}, binding[pbe_ext.VIF_DETAILS])
        self.assertEqual({}, binding[pbe_ext.PROFILE])

    def test_create_port_binding(self):
        profile = {'key1': 'value1'}
        kwargs = {pbe_ext.PROFILE: profile}
        port, binding = self._create_port_and_binding(**kwargs)
        self._assert_bound_port_binding(binding)
        self.assertEqual({"key1": "value1"}, binding[pbe_ext.PROFILE])

    def test_create_duplicate_port_binding(self):
        device_owner = '%s%s' % (const.DEVICE_OWNER_COMPUTE_PREFIX, 'nova')
        host_arg = {portbindings.HOST_ID: self.host}
        with self.port(device_owner=device_owner,
                       arg_list=(portbindings.HOST_ID,),
                       **host_arg) as port:
            response = self._create_port_binding(self.fmt, port['port']['id'],
                                                 self.host)
            self.assertEqual(webob.exc.HTTPConflict.code,
                             response.status_int)

    def test_create_port_binding_failure(self):
        device_owner = '%s%s' % (const.DEVICE_OWNER_COMPUTE_PREFIX, 'nova')
        with self.port(device_owner=device_owner) as port:
            port_id = port['port']['id']
            response = self._create_port_binding(self.fmt, port_id,
                                                 'host-fail')
            self.assertEqual(webob.exc.HTTPInternalServerError.code,
                             response.status_int)
            self.assertTrue(exceptions.PortBindingError.__name__ in
                            response.text)

    def test_create_port_binding_for_non_compute_owner(self):
        with self.port() as port:
            port_id = port['port']['id']
            response = self._create_port_binding(self.fmt, port_id,
                                                 'host-ovs-no_filter')
            self.assertEqual(webob.exc.HTTPBadRequest.code,
                             response.status_int)

    def test_update_port_binding(self):
        port, binding = self._create_port_and_binding()
        profile = {'key1': 'value1'}
        kwargs = {pbe_ext.PROFILE: profile}
        binding = self._do_update_port_binding(self.fmt, port['id'], self.host,
                                               **kwargs)['binding']
        self._assert_bound_port_binding(binding)
        self.assertEqual({"key1": "value1"}, binding[pbe_ext.PROFILE])

    def test_update_non_existing_binding(self):
        device_owner = '%s%s' % (const.DEVICE_OWNER_COMPUTE_PREFIX, 'nova')
        with self.port(device_owner=device_owner) as port:
            port_id = port['port']['id']
            profile = {'key1': 'value1'}
            kwargs = {pbe_ext.PROFILE: profile}
            response = self._update_port_binding(self.fmt, port_id, 'a_host',
                                                 **kwargs)
            self.assertEqual(webob.exc.HTTPNotFound.code, response.status_int)

    def test_update_port_binding_for_non_compute_owner(self):
        with self.port() as port:
            port_id = port['port']['id']
            profile = {'key1': 'value1'}
            kwargs = {pbe_ext.PROFILE: profile}
            response = self._update_port_binding(self.fmt, port_id, 'a_host',
                                                 **kwargs)
            self.assertEqual(webob.exc.HTTPBadRequest.code,
                             response.status_int)

    def test_update_port_binding_failure(self):
        class FakeBinding(object):
            vif_type = portbindings.VIF_TYPE_BINDING_FAILED

        class FakePortContext(object):
            _binding = FakeBinding()

        port, binding = self._create_port_and_binding()
        profile = {'key1': 'value1'}
        kwargs = {pbe_ext.PROFILE: profile}
        with mock.patch.object(
                self.plugin, '_bind_port_if_needed',
                return_value=FakePortContext()):
            response = self._update_port_binding(self.fmt, port['id'],
                                                 self.host, **kwargs)
            self.assertEqual(webob.exc.HTTPInternalServerError.code,
                             response.status_int)
            self.assertTrue(exceptions.PortBindingError.__name__ in
                            response.text)

    def test_activate_port_binding(self):
        port, new_binding = self._create_port_and_binding()
        with mock.patch.object(mechanism_test.TestMechanismDriver,
                '_check_port_context'):
            active_binding = self._activate_port_binding(
                port['id'], self.host, raw_response=False)
        self._assert_bound_port_binding(active_binding)
        updated_port = self._show('ports', port['id'])['port']
        self.assertEqual(new_binding[pbe_ext.HOST],
            updated_port[portbindings.HOST_ID])
        self.assertEqual(new_binding[pbe_ext.PROFILE],
                updated_port[portbindings.PROFILE])
        self.assertEqual(new_binding[pbe_ext.VNIC_TYPE],
                updated_port[portbindings.VNIC_TYPE])
        self.assertEqual(new_binding[pbe_ext.VIF_TYPE],
                updated_port[portbindings.VIF_TYPE])
        self.assertEqual(new_binding[pbe_ext.VIF_DETAILS],
                updated_port[portbindings.VIF_DETAILS])
        retrieved_bindings = self._list_port_bindings(
            port['id'], raw_response=False)['bindings']
        retrieved_active_binding = utils.get_port_binding_by_status_and_host(
            retrieved_bindings, const.ACTIVE)
        self._assert_bound_port_binding(retrieved_active_binding)
        retrieved_inactive_binding = utils.get_port_binding_by_status_and_host(
            retrieved_bindings, const.INACTIVE)
        self._assert_unbound_port_binding(retrieved_inactive_binding)

    def test_activate_port_binding_for_non_compute_owner(self):
        port, new_binding = self._create_port_and_binding()
        data = {'port': {'device_owner': ''}}
        self.new_update_request('ports', data, port['id'],
                                self.fmt).get_response(self.api)
        response = self._activate_port_binding(port['id'], self.host)
        self.assertEqual(webob.exc.HTTPBadRequest.code,
                         response.status_int)

    def test_activate_port_binding_already_active(self):
        port, new_binding = self._create_port_and_binding()
        with mock.patch.object(mechanism_test.TestMechanismDriver,
                '_check_port_context'):
            self._activate_port_binding(port['id'], self.host)
        response = self._activate_port_binding(port['id'], self.host)
        self.assertEqual(webob.exc.HTTPConflict.code,
                         response.status_int)

    def test_activate_port_binding_failure(self):
        port, new_binding = self._create_port_and_binding()
        with mock.patch.object(self.plugin, '_commit_port_binding',
                               return_value=(None, None, True,)) as p_mock:
            response = self._activate_port_binding(port['id'], self.host)
            self.assertEqual(webob.exc.HTTPInternalServerError.code,
                             response.status_int)
            self.assertTrue(exceptions.PortBindingError.__name__ in
                            response.text)
            self.assertEqual(ml2_plugin.MAX_BIND_TRIES, p_mock.call_count)

    def test_activate_port_binding_non_existing_binding(self):
        port, new_binding = self._create_port_and_binding()
        response = self._activate_port_binding(port['id'], 'other-host')
        self.assertEqual(webob.exc.HTTPNotFound.code, response.status_int)

    def test_list_port_bindings(self):
        port, new_binding = self._create_port_and_binding()
        retrieved_bindings = self._list_port_bindings(
            port['id'], raw_response=False)['bindings']
        self.assertEqual(2, len(retrieved_bindings))
        status = const.ACTIVE
        self._assert_unbound_port_binding(
            utils.get_port_binding_by_status_and_host(retrieved_bindings,
                                                      status))
        status = const.INACTIVE
        self._assert_bound_port_binding(
            utils.get_port_binding_by_status_and_host(retrieved_bindings,
                                                      status, host=self.host))

    def test_list_port_bindings_with_query_parameters(self):
        port, new_binding = self._create_port_and_binding()
        params = '%s=%s' % (pbe_ext.STATUS, const.INACTIVE)
        retrieved_bindings = self._list_port_bindings(
            port['id'], params=params, raw_response=False)['bindings']
        self.assertEqual(1, len(retrieved_bindings))
        self._assert_bound_port_binding(retrieved_bindings[0])

    def test_show_port_binding(self):
        port, new_binding = self._create_port_and_binding()
        retrieved_binding = self._show_port_binding(
            port['id'], self.host, raw_response=False)['binding']
        self._assert_bound_port_binding(retrieved_binding)

    def test_show_port_binding_with_fields(self):
        port, new_binding = self._create_port_and_binding()
        fields = 'fields=%s' % pbe_ext.HOST
        retrieved_binding = self._show_port_binding(
            port['id'], self.host, raw_response=False,
            params=fields)['binding']
        self.assertEqual(self.host, retrieved_binding[pbe_ext.HOST])
        for key in (pbe_ext.STATUS, pbe_ext.PROFILE, pbe_ext.VNIC_TYPE,
                    pbe_ext.VIF_TYPE, pbe_ext.VIF_DETAILS,):
            self.assertNotIn(key, retrieved_binding)

    def test_delete_port_binding(self):
        port, new_binding = self._create_port_and_binding()
        response = self._delete_port_binding(port['id'], self.host)
        self.assertEqual(webob.exc.HTTPNoContent.code, response.status_int)
        response = self._show_port_binding(port['id'], self.host)
        self.assertEqual(webob.exc.HTTPNotFound.code, response.status_int)

    def test_delete_non_existing_port_binding(self):
        port, new_binding = self._create_port_and_binding()
        response = self._delete_port_binding(port['id'], 'other-host')
        self.assertEqual(webob.exc.HTTPNotFound.code, response.status_int)

    def test_binding_fail_for_unknown_allocation(self):
        # The UUID is a random one - which of course is unknown to neutron
        # as a resource provider UUID.
        profile = {'allocation': 'ccccbb4c-2adf-11e9-91bc-db7063775d06'}
        kwargs = {pbe_ext.PROFILE: profile}
        device_owner = '%s%s' % (const.DEVICE_OWNER_COMPUTE_PREFIX, 'nova')

        with self.port(device_owner=device_owner) as port:
            port_id = port['port']['id']
            response = self._create_port_binding(
                self.fmt, port_id, self.host, **kwargs)

            self.assertEqual(webob.exc.HTTPInternalServerError.code,
                             response.status_int)
            self.assertTrue(exceptions.PortBindingError.__name__ in
                            response.text)
