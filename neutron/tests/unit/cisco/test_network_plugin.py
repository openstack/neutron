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

from oslo.config import cfg
import webob.exc as wexc

from neutron.api.v2 import base
from neutron.common import exceptions as q_exc
from neutron import context
from neutron.db import db_base_plugin_v2 as base_plugin
from neutron.db import l3_db
from neutron.extensions import providernet as provider
from neutron.manager import NeutronManager
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_exceptions as c_exc
from neutron.plugins.cisco.common import config as cisco_config
from neutron.plugins.cisco.db import nexus_db_v2
from neutron.plugins.cisco.models import virt_phy_sw_v2
from neutron.plugins.openvswitch.common import config as ovs_config
from neutron.plugins.openvswitch import ovs_db_v2
from neutron.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)
NEXUS_PLUGIN = 'neutron.plugins.cisco.nexus.cisco_nexus_plugin_v2.NexusPlugin'


class CiscoNetworkPluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):

    _plugin_name = 'neutron.plugins.cisco.network_plugin.PluginV2'

    def setUp(self):
        # Use a mock netconf client
        self.mock_ncclient = mock.Mock()
        self.patch_obj = mock.patch.dict('sys.modules',
                                         {'ncclient': self.mock_ncclient})
        self.patch_obj.start()

        cisco_config.cfg.CONF.set_override('nexus_plugin', NEXUS_PLUGIN,
                                           'CISCO_PLUGINS')
        self.addCleanup(cisco_config.cfg.CONF.reset)

        super(CiscoNetworkPluginV2TestCase, self).setUp(self._plugin_name)
        self.port_create_status = 'DOWN'
        self.addCleanup(self.patch_obj.stop)

    def _get_plugin_ref(self):
        plugin_obj = NeutronManager.get_plugin()
        if getattr(plugin_obj, "_master"):
            plugin_ref = plugin_obj
        else:
            plugin_ref = getattr(plugin_obj, "_model").\
                _plugins[const.VSWITCH_PLUGIN]

        return plugin_ref


class TestCiscoBasicGet(CiscoNetworkPluginV2TestCase,
                        test_db_plugin.TestBasicGet):
    pass


class TestCiscoV2HTTPResponse(CiscoNetworkPluginV2TestCase,
                              test_db_plugin.TestV2HTTPResponse):

    pass


class TestCiscoPortsV2(CiscoNetworkPluginV2TestCase,
                       test_db_plugin.TestPortsV2):

    def setUp(self):
        """Configure for end-to-end neutron testing using a mock ncclient.

        This setup includes:
        - Configure the OVS plugin to use VLANs in the range of 1000-1100.
        - Configure the Cisco plugin model to use the real Nexus driver.
        - Configure the Nexus sub-plugin to use an imaginary switch
          at 1.1.1.1.

        """
        self.addCleanup(mock.patch.stopall)

        self.vlan_start = 1000
        self.vlan_end = 1100
        range_str = 'physnet1:%d:%d' % (self.vlan_start,
                                        self.vlan_end)
        nexus_driver = ('neutron.plugins.cisco.nexus.'
                        'cisco_nexus_network_driver_v2.CiscoNEXUSDriver')

        config = {
            ovs_config: {
                'OVS': {'bridge_mappings': 'physnet1:br-eth1',
                        'network_vlan_ranges': [range_str],
                        'tenant_network_type': 'vlan'}
            },
            cisco_config: {
                'CISCO': {'nexus_driver': nexus_driver},
                'CISCO_PLUGINS': {'nexus_plugin': NEXUS_PLUGIN},
            }
        }

        for module in config:
            for group in config[module]:
                for opt in config[module][group]:
                    module.cfg.CONF.set_override(opt,
                                                 config[module][group][opt],
                                                 group)
            self.addCleanup(module.cfg.CONF.reset)

        # TODO(Henry): add tests for other devices
        self.dev_id = 'NEXUS_SWITCH'
        self.switch_ip = '1.1.1.1'
        nexus_config = {
            (self.dev_id, self.switch_ip, 'username'): 'admin',
            (self.dev_id, self.switch_ip, 'password'): 'mySecretPassword',
            (self.dev_id, self.switch_ip, 'ssh_port'): 22,
            (self.dev_id, self.switch_ip, 'testhost'): '1/1',
        }
        mock.patch.dict(cisco_config.device_dictionary, nexus_config).start()

        patches = {
            '_should_call_create_net': True,
            '_get_instance_host': 'testhost'
        }
        for func in patches:
            mock_sw = mock.patch.object(
                virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                func).start()
            mock_sw.return_value = patches[func]

        super(TestCiscoPortsV2, self).setUp()

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

    @contextlib.contextmanager
    def _create_port_res(self, name='myname', cidr='1.0.0.0/24',
                         do_delete=True):
        """Create a network, subnet, and port and yield the result.

        Create a network, subnet, and port, yield the result,
        then delete the port, subnet, and network.

        :param name: Name of network to be created
        :param cidr: cidr address of subnetwork to be created
        :param do_delete: If set to True, delete the port at the
                          end of testing

        """
        with self.network(name=name) as network:
            with self.subnet(network=network, cidr=cidr) as subnet:
                net_id = subnet['subnet']['network_id']
                res = self._create_port(self.fmt, net_id,
                                        device_id='testdev',
                                        device_owner='testowner')
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

    def _is_in_last_nexus_cfg(self, words):
        last_cfg = (self.mock_ncclient.manager.connect().
                    edit_config.mock_calls[-1][2]['config'])
        return all(word in last_cfg for word in words)

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
                res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                             'test', True, context=ctx)
                # We expect an internal server error as we injected a fault
                self._validate_behavior_on_bulk_failure(
                    res,
                    'ports',
                    wexc.HTTPInternalServerError.code)

    def test_nexus_enable_vlan_cmd(self):
        """Verify the syntax of the command to enable a vlan on an intf."""
        # First vlan should be configured without 'add' keyword
        with self._create_port_res(name='net1', cidr='1.0.0.0/24'):
            self.assertTrue(self._is_in_last_nexus_cfg(['allowed', 'vlan']))
            self.assertFalse(self._is_in_last_nexus_cfg(['add']))
            # Second vlan should be configured with 'add' keyword
            with self._create_port_res(name='net2', cidr='1.0.1.0/24'):
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
            with self._create_port_res(name='myname') as res:
                self.assertEqual(res.status_int, wexc.HTTPCreated.code)

        def mock_edit_config_b(target, config):
            if all(word in config for word in ['no', 'shutdown']):
                raise Exception("Command is only allowed on VLAN")

        with self._patch_ncclient(
            'manager.connect.return_value.edit_config.side_effect',
            mock_edit_config_b):
            with self._create_port_res(name='myname') as res:
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
            with self._create_port_res(name='myname', do_delete=False) as res:
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
        with mock.patch.object(virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                               '_get_instance_host') as mock_get_instance:
            mock_get_instance.return_value = 'fictitious_host'
            with self._create_port_res(do_delete=False) as res:
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

        """
        with self.port(fmt=self.fmt) as orig_port:

            inserted_exc = ValueError
            with mock.patch.object(
                virt_phy_sw_v2.VirtualPhysicalSwitchModelV2,
                '_invoke_nexus_for_net_create',
                side_effect=inserted_exc):

                # Send an update port request with a new device ID
                device_id = "00fff4d0-e4a8-4a3a-8906-4c4cdafb59f1"
                if orig_port['port']['device_id'] == device_id:
                    device_id = "600df00d-e4a8-4a3a-8906-feed600df00d"
                data = {'port': {'device_id': device_id}}
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
            start_rows = nexus_db_v2.get_nexusvlan_binding(self.vlan_start,
                                                           self.switch_ip)
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
            end_rows = nexus_db_v2.get_nexusvlan_binding(self.vlan_start,
                                                         self.switch_ip)
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
            start_rows = nexus_db_v2.get_nexusvlan_binding(self.vlan_start,
                                                           self.switch_ip)
            self.assertEqual(len(start_rows), 1)

            # Simulate a Nexus switch configuration error during
            # port deletion.
            with self._patch_ncclient(
                'manager.connect.return_value.edit_config.side_effect',
                AttributeError):
                self._delete('ports', port['port']['id'],
                             base.FAULT_MAP[c_exc.NexusConfigFailed].code)

            # Confirm that the binding has been restored (rolled back).
            end_rows = nexus_db_v2.get_nexusvlan_binding(self.vlan_start,
                                                         self.switch_ip)
            self.assertEqual(start_rows, end_rows)


class TestCiscoNetworksV2(CiscoNetworkPluginV2TestCase,
                          test_db_plugin.TestNetworksV2):

    def setUp(self):
        self.physnet = 'testphys1'
        self.vlan_range = '100:199'
        phys_vrange = ':'.join([self.physnet, self.vlan_range])
        cfg.CONF.set_override('tenant_network_type', 'vlan', 'OVS')
        cfg.CONF.set_override('network_vlan_ranges', [phys_vrange], 'OVS')
        self.addCleanup(cfg.CONF.reset)

        super(TestCiscoNetworksV2, self).setUp()

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
                          provider.PHYSICAL_NETWORK: self.physnet,
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
                    (provider.PHYSICAL_NETWORK, self.physnet),
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


class TestCiscoPortsV2XML(TestCiscoPortsV2):
    fmt = 'xml'


class TestCiscoNetworksV2XML(TestCiscoNetworksV2):
    fmt = 'xml'


class TestCiscoSubnetsV2XML(TestCiscoSubnetsV2):
    fmt = 'xml'
