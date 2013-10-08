# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import inspect
import logging
import mock

import webob.exc as wexc

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.common import exceptions as q_exc
from neutron import context
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import l3_db
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.manager import NeutronManager
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.common import config as cisco_config
from neutron.plugins.cisco.db import nexus_db_v2
from neutron.plugins.cisco.models import virt_phy_sw_v2
from neutron.plugins.openvswitch.common import config as ovs_config
from neutron.plugins.openvswitch import ovs_db_v2
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin
from neutron.tests.unit import test_extensions

LOG = logging.getLogger(__name__)
CORE_PLUGIN = 'neutron.plugins.cisco.network_plugin.PluginV2'
NEXUS_PLUGIN = 'neutron.plugins.cisco.nexus.cisco_nexus_plugin_v2.NexusPlugin'
NEXUS_DRIVER = ('neutron.plugins.cisco.nexus.'
                'cisco_nexus_network_driver_v2.CiscoNEXUSDriver')
PHYS_NET = 'physnet1'
BRIDGE_NAME = 'br-eth1'
VLAN_START = 1000
VLAN_END = 1100
COMP_HOST_NAME = 'testhost'
COMP_HOST_NAME_2 = 'testhost_2'
NEXUS_IP_ADDR = '1.1.1.1'
NEXUS_DEV_ID = 'NEXUS_SWITCH'
NEXUS_USERNAME = 'admin'
NEXUS_PASSWORD = 'mySecretPassword'
NEXUS_SSH_PORT = 22
NEXUS_INTERFACE = '1/1'
NEXUS_INTERFACE_2 = '1/2'
NEXUS_PORT_1 = 'ethernet:1/1'
NEXUS_PORT_2 = 'ethernet:1/2'
NETWORK_NAME = 'test_network'
CIDR_1 = '10.0.0.0/24'
CIDR_2 = '10.0.1.0/24'
DEVICE_ID_1 = '11111111-1111-1111-1111-111111111111'
DEVICE_ID_2 = '22222222-2222-2222-2222-222222222222'
DEVICE_OWNER = 'compute:None'


class CiscoNetworkPluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        """Configure for end-to-end neutron testing using a mock ncclient.

        This setup includes:
        - Configure the OVS plugin to use VLANs in the range of
          VLAN_START-VLAN_END.
        - Configure the Cisco plugin model to use the Nexus driver.
        - Configure the Nexus driver to use an imaginary switch
          at NEXUS_IP_ADDR.

        """
        # Configure the OVS and Cisco plugins
        phys_bridge = ':'.join([PHYS_NET, BRIDGE_NAME])
        phys_vlan_range = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        config = {
            ovs_config: {
                'OVS': {'bridge_mappings': phys_bridge,
                        'network_vlan_ranges': [phys_vlan_range],
                        'tenant_network_type': 'vlan'}
            },
            cisco_config: {
                'CISCO': {'nexus_driver': NEXUS_DRIVER},
                'CISCO_PLUGINS': {'nexus_plugin': NEXUS_PLUGIN},
            }
        }
        for module in config:
            for group in config[module]:
                for opt, val in config[module][group].items():
                    module.cfg.CONF.set_override(opt, val, group)
            self.addCleanup(module.cfg.CONF.reset)

        # Configure the Nexus switch dictionary
        # TODO(Henry): add tests for other devices
        nexus_config = {
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, 'username'): NEXUS_USERNAME,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, 'password'): NEXUS_PASSWORD,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, 'ssh_port'): NEXUS_SSH_PORT,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, COMP_HOST_NAME): NEXUS_INTERFACE,
            (NEXUS_DEV_ID, NEXUS_IP_ADDR, COMP_HOST_NAME_2): NEXUS_INTERFACE_2,
        }
        nexus_patch = mock.patch.dict(cisco_config.device_dictionary,
                                      nexus_config)
        nexus_patch.start()
        self.addCleanup(nexus_patch.stop)

        # Use a mock netconf client
        self.mock_ncclient = mock.Mock()
        ncclient_patch = mock.patch.dict('sys.modules',
                                         {'ncclient': self.mock_ncclient})
        ncclient_patch.start()
        self.addCleanup(ncclient_patch.stop)

        # Call the parent setUp, start the core plugin
        super(CiscoNetworkPluginV2TestCase, self).setUp(CORE_PLUGIN)
        self.port_create_status = 'DOWN'

    def _get_plugin_ref(self):
        plugin_obj = NeutronManager.get_plugin()
        if getattr(plugin_obj, "_master"):
            plugin_ref = plugin_obj
        else:
            plugin_ref = getattr(plugin_obj, "_model").\
                _plugins[const.VSWITCH_PLUGIN]

        return plugin_ref

    @contextlib.contextmanager
    def _patch_ncclient(self, attr, value):
        """Configure an attribute on the mock ncclient module.

        This method can be used to inject errors by setting a side effect
        or a return value for an ncclient method.

        :param attr: ncclient attribute (typically method) to be configured.
        :param value: Value to be configured on the attribute.

        """
        # Configure attribute.
        config = {attr: value}
        self.mock_ncclient.configure_mock(**config)
        # Continue testing
        yield
        # Unconfigure attribute
        config = {attr: None}
        self.mock_ncclient.configure_mock(**config)

    def _is_in_nexus_cfg(self, words):
        """Check if any config sent to Nexus contains all words in a list."""
        for call in (self.mock_ncclient.manager.connect.return_value.
                     edit_config.mock_calls):
            configlet = call[2]['config']
            if all(word in configlet for word in words):
                return True

    def _is_in_last_nexus_cfg(self, words):
        """Check if last config sent to Nexus contains all words in a list."""
        last_cfg = (self.mock_ncclient.manager.connect.return_value.
                    edit_config.mock_calls[-1][2]['config'])
        return all(word in last_cfg for word in words)


class TestCiscoBasicGet(CiscoNetworkPluginV2TestCase,
                        test_db_plugin.TestBasicGet):
    pass


class TestCiscoV2HTTPResponse(CiscoNetworkPluginV2TestCase,
                              test_db_plugin.TestV2HTTPResponse):
    pass


class TestCiscoPortsV2(CiscoNetworkPluginV2TestCase,
                       test_db_plugin.TestPortsV2,
                       test_bindings.PortBindingsHostTestCaseMixin):

    @contextlib.contextmanager
    def _create_port_res(self, name=NETWORK_NAME, cidr=CIDR_1,
                         do_delete=True, host_id=COMP_HOST_NAME):
        """Create a network, subnet, and port and yield the result.

        Create a network, subnet, and port, yield the result,
        then delete the port, subnet, and network.

        :param name: Name of network to be created
        :param cidr: cidr address of subnetwork to be created
        :param do_delete: If set to True, delete the port at the
                          end of testing
        :param host_id: Name of compute host to use for testing

        """
        ctx = context.get_admin_context()
        with self.network(name=name) as network:
            with self.subnet(network=network, cidr=cidr) as subnet:
                net_id = subnet['subnet']['network_id']
                args = (portbindings.HOST_ID, 'device_id', 'device_owner')
                port_dict = {portbindings.HOST_ID: host_id,
                             'device_id': DEVICE_ID_1,
                             'device_owner': DEVICE_OWNER}
                res = self._create_port(self.fmt, net_id, arg_list=args,
                                        context=ctx, **port_dict)
                port = self.deserialize(self.fmt, res)
                try:
                    yield res
                finally:
                    if do_delete:
                        self._delete('ports', port['port']['id'])

    def _assertExpectedHTTP(self, status, exc):
        """Confirm that an HTTP status corresponds to an expected exception.

        Confirm that an HTTP status which has been returned for an
        neutron API request matches the HTTP status corresponding
        to an expected exception.

        :param status: HTTP status
        :param exc: Expected exception

        """
        if exc in base.FAULT_MAP:
            expected_http = base.FAULT_MAP[exc].code
        else:
            expected_http = wexc.HTTPInternalServerError.code
        self.assertEqual(status, expected_http)

    def test_create_ports_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_ref = self._get_plugin_ref()
            orig = plugin_ref.create_port
            with mock.patch.object(plugin_ref,
                                   'create_port') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                with self.network() as net:
                    res = self._create_port_bulk(self.fmt, 2,
                                                 net['network']['id'],
                                                 'test',
                                                 True)
                    # Expect an internal server error as we injected a fault
                    self._validate_behavior_on_bulk_failure(
                        res,
                        'ports',
                        wexc.HTTPInternalServerError.code)

    def test_create_ports_bulk_native(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk port create")

    def test_create_ports_bulk_emulated(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk port create")

    def test_create_ports_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk port create")
        ctx = context.get_admin_context()
        with self.network() as net:
            plugin_ref = self._get_plugin_ref()
            orig = plugin_ref.create_port
            with mock.patch.object(plugin_ref,
                                   'create_port') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)

                patched_plugin.side_effect = side_effect
                res = self._create_port_bulk(self.fmt, 2,
                                             net['network']['id'],
                                             'test', True, context=ctx)
                # We expect an internal server error as we injected a fault
                self._validate_behavior_on_bulk_failure(
                    res,
                    'ports',
                    wexc.HTTPInternalServerError.code)

    def test_nexus_enable_vlan_cmd(self):
        """Verify the syntax of the command to enable a vlan on an intf."""
        # First vlan should be configured without 'add' keyword
        with self._create_port_res(name='net1', cidr=CIDR_1):
            self.assertTrue(self._is_in_last_nexus_cfg(['allowed', 'vlan']))
            self.assertFalse(self._is_in_last_nexus_cfg(['add']))
            # Second vlan should be configured with 'add' keyword
            with self._create_port_res(name='net2', cidr=CIDR_2):
                self.assertTrue(
                    self._is_in_last_nexus_cfg(['allowed', 'vlan', 'add']))

    def test_nexus_connect_fail(self):
        """Test failure to connect to a Nexus switch.

        While creating a network, subnet, and port, simulate a connection
        failure to a nexus switch. Confirm that the expected HTTP code
        is returned for the create port operation.

        """
        with self._patch_ncclient('manager.connect.side_effect',
                                  AttributeError):
            with self._create_port_res(do_delete=False) as res:
                self._assertExpectedHTTP(res.status_int,
                                         c_exc.NexusConnectFailed)

    def test_nexus_config_fail(self):
        """Test a Nexus switch configuration failure.

        While creating a network, subnet, and port, simulate a nexus
        switch configuration error. Confirm that the expected HTTP code
        is returned for the create port operation.

        """
        with self._patch_ncclient(
            'manager.connect.return_value.edit_config.side_effect',
            AttributeError):
            with self._create_port_res(do_delete=False) as res:
                self._assertExpectedHTTP(res.status_int,
                                         c_exc.NexusConfigFailed)

    def test_nexus_extended_vlan_range_failure(self):
        """Test that extended VLAN range config errors are ignored.

        Some versions of Nexus switch do not allow state changes for
        the extended VLAN range (1006-4094), but these errors can be
        ignored (default values are appropriate). Test that such errors
        are ignored by the Nexus plugin.

        """
        def mock_edit_config_a(target, config):
            if all(word in config for word in ['state', 'active']):
                raise Exception("Can't modify state for extended")

        with self._patch_ncclient(
            'manager.connect.return_value.edit_config.side_effect',
            mock_edit_config_a):
            with self._create_port_res() as res:
                self.assertEqual(res.status_int, wexc.HTTPCreated.code)

        def mock_edit_config_b(target, config):
            if all(word in config for word in ['no', 'shutdown']):
                raise Exception("Command is only allowed on VLAN")

        with self._patch_ncclient(
            'manager.connect.return_value.edit_config.side_effect',
            mock_edit_config_b):
            with self._create_port_res() as res:
                self.assertEqual(res.status_int, wexc.HTTPCreated.code)

    def test_nexus_vlan_config_rollback(self):
        """Test rollback following Nexus VLAN state config failure.

        Test that the Cisco Nexus plugin correctly deletes the VLAN
        on the Nexus switch when the 'state active' command fails (for
        a reason other than state configuration change is rejected
        for the extended VLAN range).

        """
        def mock_edit_config(target, config):
            if all(word in config for word in ['state', 'active']):
                raise ValueError
        with self._patch_ncclient(
            'manager.connect.return_value.edit_config.side_effect',
            mock_edit_config):
            with self._create_port_res(do_delete=False) as res:
                # Confirm that the last configuration sent to the Nexus
                # switch was deletion of the VLAN.
                self.assertTrue(
                    self._is_in_last_nexus_cfg(['<no>', '<vlan>'])
                )
                self._assertExpectedHTTP(res.status_int,
                                         c_exc.NexusConfigFailed)

    def test_get_seg_id_fail(self):
        """Test handling of a NetworkSegmentIDNotFound exception.

        Test the Cisco NetworkSegmentIDNotFound exception by simulating
        a return of None by the OVS DB get_network_binding method
        during port creation.

        """
        orig = ovs_db_v2.get_network_binding

        def _return_none_if_nexus_caller(self, *args, **kwargs):
            def _calling_func_name(offset=0):
                """Get name of the calling function 'offset' frames back."""
                return inspect.stack()[1 + offset][3]
            if (_calling_func_name(1) == '_get_segmentation_id' and
                _calling_func_name(2) == '_invoke_nexus_for_net_create'):
                return None
            else:
                return orig(self, *args, **kwargs)

        with mock.patch.object(ovs_db_v2, 'get_network_binding',
                               new=_return_none_if_nexus_caller):
            with self._create_port_res(do_delete=False) as res:
                self._assertExpectedHTTP(res.status_int,
                                         c_exc.NetworkSegmentIDNotFound)

    def test_nexus_host_non_configured(self):
        """Test handling of a NexusComputeHostNotConfigured exception.

        Test the Cisco NexusComputeHostNotConfigured exception by using
        a fictitious host name during port creation.

        """
        with self._create_port_res(do_delete=False,
                                   host_id='fakehost') as res:
            self._assertExpectedHTTP(res.status_int,
                                     c_exc.NexusComputeHostNotConfigured)

    def test_nexus_bind_fail_rollback(self):
        """Test for proper rollback following add Nexus DB binding failure.

        Test that the Cisco Nexus plugin correctly rolls back the vlan
        configuration on the Nexus switch when add_nexusport_binding fails
        within the plugin's create_port() method.

        """
        with mock.patch.object(nexus_db_v2, 'add_nexusport_binding',
                               side_effect=KeyError):
            with self._create_port_res(do_delete=False) as res:
                # Confirm that the last configuration sent to the Nexus
                # switch was a removal of vlan from the test interface.
                self.assertTrue(
                    self._is_in_last_nexus_cfg(['<vlan>', '<remove>'])
                )
                self._assertExpectedHTTP(res.status_int, KeyError)

    def test_model_update_port_rollback(self):
        """Test for proper rollback for Cisco model layer update port failure.

        Test that the vSwitch plugin port configuration is rolled back
        (restored) by the Cisco plugin model layer when there is a
        failure in the Nexus sub-plugin for an update port operation.

        The update port operation simulates a port attachment scenario:
        first a port is created with no instance (null device_id),
        and then a port update is requested with a non-null device_id
        to simulate the port attachment.

        """
        with self.port(fmt=self.fmt, device_id='',
                       device_owner=DEVICE_OWNER) as orig_port:

            inserted_exc = ValueError
            with mock.patch.object(
                virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                '_invoke_nexus_for_net_create',
                side_effect=inserted_exc):

                # Send an update port request including a non-null device ID
                data = {'port': {'device_id': DEVICE_ID_2,
                                 'device_owner': DEVICE_OWNER,
                                 portbindings.HOST_ID: COMP_HOST_NAME}}
                port_id = orig_port['port']['id']
                req = self.new_update_request('ports', data, port_id)
                res = req.get_response(self.api)

                # Sanity check failure result code
                self._assertExpectedHTTP(res.status_int, inserted_exc)

                # Check that the port still has the original device ID
                plugin = base_plugin.NeutronDbPluginV2()
                ctx = context.get_admin_context()
                db_port = plugin._get_port(ctx, port_id)
                self.assertEqual(db_port['device_id'],
                                 orig_port['port']['device_id'])

    def test_model_delete_port_rollback(self):
        """Test for proper rollback for OVS plugin delete port failure.

        Test that the nexus port configuration is rolled back (restored)
        by the Cisco model plugin when there is a failure in the OVS
        plugin for a delete port operation.

        """
        with self._create_port_res() as res:

            # After port is created, we should have one binding for this
            # vlan/nexus switch.
            port = self.deserialize(self.fmt, res)
            start_rows = nexus_db_v2.get_nexusvlan_binding(VLAN_START,
                                                           NEXUS_IP_ADDR)
            self.assertEqual(len(start_rows), 1)

            # Inject an exception in the OVS plugin delete_port
            # processing, and attempt a port deletion.
            inserted_exc = q_exc.Conflict
            expected_http = base.FAULT_MAP[inserted_exc].code
            with mock.patch.object(l3_db.L3_NAT_db_mixin,
                                   'disassociate_floatingips',
                                   side_effect=inserted_exc):
                self._delete('ports', port['port']['id'],
                             expected_code=expected_http)

            # Confirm that the Cisco model plugin has restored
            # the nexus configuration for this port after deletion failure.
            end_rows = nexus_db_v2.get_nexusvlan_binding(VLAN_START,
                                                         NEXUS_IP_ADDR)
            self.assertEqual(start_rows, end_rows)

    def test_nexus_delete_port_rollback(self):
        """Test for proper rollback for nexus plugin delete port failure.

        Test for rollback (i.e. restoration) of a VLAN entry in the
        nexus database whenever the nexus plugin fails to reconfigure the
        nexus switch during a delete_port operation.

        """
        with self._create_port_res() as res:

            port = self.deserialize(self.fmt, res)

            # Check that there is only one binding in the nexus database
            # for this VLAN/nexus switch.
            start_rows = nexus_db_v2.get_nexusvlan_binding(VLAN_START,
                                                           NEXUS_IP_ADDR)
            self.assertEqual(len(start_rows), 1)

            # Simulate a Nexus switch configuration error during
            # port deletion.
            with self._patch_ncclient(
                'manager.connect.return_value.edit_config.side_effect',
                AttributeError):
                self._delete('ports', port['port']['id'],
                             base.FAULT_MAP[c_exc.NexusConfigFailed].code)

            # Confirm that the binding has been restored (rolled back).
            end_rows = nexus_db_v2.get_nexusvlan_binding(VLAN_START,
                                                         NEXUS_IP_ADDR)
            self.assertEqual(start_rows, end_rows)

    def test_model_update_port_attach(self):
        """Test the model for update_port in attaching to an instance.

        Mock the routines that call into the plugin code, and make sure they
        are called with correct arguments.

        """
        with contextlib.nested(
                self.port(),
                mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                                  '_invoke_plugin_per_device'),
                mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                                  '_invoke_nexus_for_net_create')
        ) as (port, invoke_plugin_per_device, invoke_nexus_for_net_create):
            data = {'port': {portbindings.HOST_ID: COMP_HOST_NAME,
                    'device_id': DEVICE_ID_1,
                    'device_owner': DEVICE_OWNER}}

            req = self.new_update_request('ports', data, port['port']['id'])
            # Note, due to mocking out the two model routines, response won't
            # contain any useful data
            req.get_response(self.api)

            # Note that call_args_list is used instead of
            # assert_called_once_with which requires exact match of arguments.
            # This is because the mocked routines contain variable number of
            # arguments and/or dynamic objects.
            self.assertEqual(invoke_plugin_per_device.call_count, 1)
            self.assertEqual(
                invoke_plugin_per_device.call_args_list[0][0][0:2],
                (const.VSWITCH_PLUGIN, 'update_port'))
            self.assertEqual(invoke_nexus_for_net_create.call_count, 1)
            self.assertEqual(
                invoke_nexus_for_net_create.call_args_list[0][0][1:],
                (port['port']['tenant_id'], port['port']['network_id'],
                 data['port']['device_id'],
                 data['port'][portbindings.HOST_ID],))

    def test_model_update_port_migrate(self):
        """Test the model for update_port in migrating an instance.

        Mock the routines that call into the plugin code, and make sure they
        are called with correct arguments.

        """
        arg_list = (portbindings.HOST_ID,)
        data = {portbindings.HOST_ID: COMP_HOST_NAME,
                'device_id': DEVICE_ID_1,
                'device_owner': DEVICE_OWNER}

        with contextlib.nested(
                self.port(arg_list=arg_list, **data),
                mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                                  '_invoke_plugin_per_device'),
                mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                                  '_invoke_nexus_for_net_create')
        ) as (port, invoke_plugin_per_device, invoke_nexus_for_net_create):
            data = {'port': {portbindings.HOST_ID: COMP_HOST_NAME_2}}
            req = self.new_update_request('ports', data, port['port']['id'])
            # Note, due to mocking out the two model routines, response won't
            # contain any useful data
            req.get_response(self.api)

            # Note that call_args_list is used instead of
            # assert_called_once_with which requires exact match of arguments.
            # This is because the mocked routines contain variable number of
            # arguments and/or dynamic objects.
            self.assertEqual(invoke_plugin_per_device.call_count, 2)
            self.assertEqual(
                invoke_plugin_per_device.call_args_list[0][0][0:2],
                (const.VSWITCH_PLUGIN, 'update_port'))
            self.assertEqual(
                invoke_plugin_per_device.call_args_list[1][0][0:2],
                (const.NEXUS_PLUGIN, 'delete_port'))
            self.assertEqual(invoke_nexus_for_net_create.call_count, 1)
            self.assertEqual(
                invoke_nexus_for_net_create.call_args_list[0][0][1:],
                (port['port']['tenant_id'], port['port']['network_id'],
                 port['port']['device_id'],
                 data['port'][portbindings.HOST_ID],))

    def test_model_update_port_net_create_not_needed(self):
        """Test the model for update_port when no action is needed.

        Mock the routines that call into the plugin code, and make sure that
        VSWITCH plugin is called with correct arguments, while NEXUS plugin is
        not called at all.

        """
        arg_list = (portbindings.HOST_ID,)
        data = {portbindings.HOST_ID: COMP_HOST_NAME,
                'device_id': DEVICE_ID_1,
                'device_owner': DEVICE_OWNER}

        with contextlib.nested(
                self.port(arg_list=arg_list, **data),
                mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                                  '_invoke_plugin_per_device'),
                mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                                  '_invoke_nexus_for_net_create')
        ) as (port, invoke_plugin_per_device, invoke_nexus_for_net_create):
            data = {'port': {portbindings.HOST_ID: COMP_HOST_NAME,
                    'device_id': DEVICE_ID_1,
                    'device_owner': DEVICE_OWNER}}
            req = self.new_update_request('ports', data, port['port']['id'])
            # Note, due to mocking out the two model routines, response won't
            # contain any useful data
            req.get_response(self.api)

            # Note that call_args_list is used instead of
            # assert_called_once_with which requires exact match of arguments.
            # This is because the mocked routines contain variable number of
            # arguments and/or dynamic objects.
            self.assertEqual(invoke_plugin_per_device.call_count, 1)
            self.assertEqual(
                invoke_plugin_per_device.call_args_list[0][0][0:2],
                (const.VSWITCH_PLUGIN, 'update_port'))
            self.assertFalse(invoke_nexus_for_net_create.called)

    def verify_portbinding(self, host_id1, host_id2,
                           vlan, device_id, binding_port):
        """Verify a port binding entry in the DB is correct."""
        self.assertEqual(host_id1, host_id2)
        pb = nexus_db_v2.get_nexusvm_bindings(vlan, device_id)
        self.assertEqual(len(pb), 1)
        self.assertEqual(pb[0].port_id, binding_port)
        self.assertEqual(pb[0].switch_ip, NEXUS_IP_ADDR)

    def test_db_update_port_attach(self):
        """Test DB for update_port in attaching to an instance.

        Query DB for the port binding entry corresponding to the search key
        (vlan, device_id), and make sure that it's bound to correct switch port

        """
        with self.port() as port:
            data = {'port': {portbindings.HOST_ID: COMP_HOST_NAME,
                    'device_id': DEVICE_ID_1,
                    'device_owner': DEVICE_OWNER}}

            req = self.new_update_request('ports', data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            ctx = context.get_admin_context()
            net = self._show('networks', res['port']['network_id'],
                             neutron_context=ctx)['network']
            self.assertTrue(attributes.is_attr_set(
                            net.get(provider.SEGMENTATION_ID)))
            vlan = net[provider.SEGMENTATION_ID]
            self.assertEqual(vlan, VLAN_START)
            self.verify_portbinding(res['port'][portbindings.HOST_ID],
                                    data['port'][portbindings.HOST_ID],
                                    vlan,
                                    data['port']['device_id'],
                                    NEXUS_PORT_1)

    def test_db_update_port_migrate(self):
        """Test DB for update_port in migrating an instance.

        Query DB for the port binding entry corresponding to the search key
        (vlan, device_id), and make sure that it's bound to correct switch port
        before and after the migration.

        """
        arg_list = (portbindings.HOST_ID,)
        data = {portbindings.HOST_ID: COMP_HOST_NAME,
                'device_id': DEVICE_ID_1,
                'device_owner': DEVICE_OWNER}

        with self.port(arg_list=arg_list, **data) as port:
            ctx = context.get_admin_context()
            net = self._show('networks', port['port']['network_id'],
                             neutron_context=ctx)['network']
            self.assertTrue(attributes.is_attr_set(
                            net.get(provider.SEGMENTATION_ID)))
            vlan = net[provider.SEGMENTATION_ID]
            self.assertEqual(vlan, VLAN_START)
            self.verify_portbinding(port['port'][portbindings.HOST_ID],
                                    data[portbindings.HOST_ID],
                                    vlan,
                                    data['device_id'],
                                    NEXUS_PORT_1)

            new_data = {'port': {portbindings.HOST_ID: COMP_HOST_NAME_2}}
            req = self.new_update_request('ports',
                                          new_data, port['port']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.api))
            self.verify_portbinding(res['port'][portbindings.HOST_ID],
                                    new_data['port'][portbindings.HOST_ID],
                                    vlan,
                                    data['device_id'],
                                    NEXUS_PORT_2)


class TestCiscoNetworksV2(CiscoNetworkPluginV2TestCase,
                          test_db_plugin.TestNetworksV2):

    def test_create_networks_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        plugin_ref = self._get_plugin_ref()
        orig = plugin_ref.create_network
        #ensures the API choose the emulation code path
        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with mock.patch.object(plugin_ref,
                                   'create_network') as patched_plugin:
                def side_effect(*args, **kwargs):
                    return self._do_side_effect(patched_plugin, orig,
                                                *args, **kwargs)
                patched_plugin.side_effect = side_effect
                res = self._create_network_bulk(self.fmt, 2, 'test', True)
                LOG.debug("response is %s" % res)
                # We expect an internal server error as we injected a fault
                self._validate_behavior_on_bulk_failure(
                    res,
                    'networks',
                    wexc.HTTPInternalServerError.code)

    def test_create_networks_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk network create")
        plugin_ref = self._get_plugin_ref()
        orig = plugin_ref.create_network
        with mock.patch.object(plugin_ref,
                               'create_network') as patched_plugin:

            def side_effect(*args, **kwargs):
                return self._do_side_effect(patched_plugin, orig,
                                            *args, **kwargs)

            patched_plugin.side_effect = side_effect
            res = self._create_network_bulk(self.fmt, 2, 'test', True)
            # We expect an internal server error as we injected a fault
            self._validate_behavior_on_bulk_failure(
                res,
                'networks',
                wexc.HTTPInternalServerError.code)

    def test_create_provider_vlan_network(self):
        provider_attrs = {provider.NETWORK_TYPE: 'vlan',
                          provider.PHYSICAL_NETWORK: PHYS_NET,
                          provider.SEGMENTATION_ID: '1234'}
        arg_list = tuple(provider_attrs.keys())
        res = self._create_network(self.fmt, 'pvnet1', True,
                                   arg_list=arg_list, **provider_attrs)
        net = self.deserialize(self.fmt, res)
        expected = [('name', 'pvnet1'),
                    ('admin_state_up', True),
                    ('status', 'ACTIVE'),
                    ('shared', False),
                    (provider.NETWORK_TYPE, 'vlan'),
                    (provider.PHYSICAL_NETWORK, PHYS_NET),
                    (provider.SEGMENTATION_ID, 1234)]
        for k, v in expected:
            self.assertEqual(net['network'][k], v)


class TestCiscoSubnetsV2(CiscoNetworkPluginV2TestCase,
                         test_db_plugin.TestSubnetsV2):

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_ref = self._get_plugin_ref()
            orig = plugin_ref.create_subnet
            with mock.patch.object(plugin_ref,
                                   'create_subnet') as patched_plugin:

                def side_effect(*args, **kwargs):
                    self._do_side_effect(patched_plugin, orig,
                                         *args, **kwargs)

                patched_plugin.side_effect = side_effect
                with self.network() as net:
                    res = self._create_subnet_bulk(self.fmt, 2,
                                                   net['network']['id'],
                                                   'test')
                # We expect an internal server error as we injected a fault
                self._validate_behavior_on_bulk_failure(
                    res,
                    'subnets',
                    wexc.HTTPInternalServerError.code)

    def test_create_subnets_bulk_native_plugin_failure(self):
        if self._skip_native_bulk:
            self.skipTest("Plugin does not support native bulk subnet create")
        plugin_ref = self._get_plugin_ref()
        orig = plugin_ref.create_subnet
        with mock.patch.object(plugin_ref,
                               'create_subnet') as patched_plugin:
            def side_effect(*args, **kwargs):
                return self._do_side_effect(patched_plugin, orig,
                                            *args, **kwargs)

            patched_plugin.side_effect = side_effect
            with self.network() as net:
                res = self._create_subnet_bulk(self.fmt, 2,
                                               net['network']['id'],
                                               'test')

                # We expect an internal server error as we injected a fault
                self._validate_behavior_on_bulk_failure(
                    res,
                    'subnets',
                    wexc.HTTPInternalServerError.code)


class TestCiscoRouterInterfacesV2(CiscoNetworkPluginV2TestCase):

    def setUp(self):
        """Configure an API extension manager."""
        super(TestCiscoRouterInterfacesV2, self).setUp()
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    @contextlib.contextmanager
    def _router(self, subnet):
        """Create a virtual router, yield it for testing, then delete it."""
        data = {'router': {'tenant_id': 'test_tenant_id'}}
        router_req = self.new_create_request('routers', data, self.fmt)
        res = router_req.get_response(self.ext_api)
        router = self.deserialize(self.fmt, res)
        try:
            yield router
        finally:
            self._delete('routers', router['router']['id'])

    @contextlib.contextmanager
    def _router_interface(self, router, subnet):
        """Create a router interface, yield for testing, then delete it."""
        interface_data = {'subnet_id': subnet['subnet']['id']}
        req = self.new_action_request('routers', interface_data,
                                      router['router']['id'],
                                      'add_router_interface')
        req.get_response(self.ext_api)
        try:
            yield
        finally:
            req = self.new_action_request('routers', interface_data,
                                          router['router']['id'],
                                          'remove_router_interface')
            req.get_response(self.ext_api)

    def test_nexus_l3_enable_config(self):
        """Verify proper operation of the Nexus L3 enable configuration."""
        self.addCleanup(cisco_config.CONF.reset)
        with self.network() as network:
            with self.subnet(network=network) as subnet:
                with self._router(subnet) as router:
                    # With 'nexus_l3_enable' configured to True, confirm that
                    # a switched virtual interface (SVI) is created/deleted
                    # on the Nexus switch when a virtual router interface is
                    # created/deleted.
                    cisco_config.CONF.set_override('nexus_l3_enable',
                                                   True, 'CISCO')
                    with self._router_interface(router, subnet):
                        self.assertTrue(self._is_in_last_nexus_cfg(
                            ['interface', 'vlan', 'ip', 'address']))
                    self.assertTrue(self._is_in_nexus_cfg(
                        ['no', 'interface', 'vlan']))
                    self.assertTrue(self._is_in_last_nexus_cfg(
                        ['no', 'vlan']))

                    # With 'nexus_l3_enable' configured to False, confirm
                    # that no changes are made to the Nexus switch running
                    # configuration when a virtual router interface is
                    # created and then deleted.
                    cisco_config.CONF.set_override('nexus_l3_enable',
                                                   False, 'CISCO')
                    self.mock_ncclient.reset_mock()
                    self._router_interface(router, subnet)
                    self.assertFalse(self.mock_ncclient.manager.connect.
                                     return_value.edit_config.called)


class TestCiscoPortsV2XML(TestCiscoPortsV2):
    fmt = 'xml'


class TestCiscoNetworksV2XML(TestCiscoNetworksV2):
    fmt = 'xml'


class TestCiscoSubnetsV2XML(TestCiscoSubnetsV2):
    fmt = 'xml'


class TestCiscoRouterInterfacesV2XML(TestCiscoRouterInterfacesV2):
    fmt = 'xml'
