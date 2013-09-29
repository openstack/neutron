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
import mock

import webob.exc as wexc

from neutron.api.v2 import base
from neutron.common import constants as n_const
from neutron import context
from neutron.extensions import portbindings
from neutron.manager import NeutronManager
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import config as ml2_config
from neutron.plugins.ml2.drivers.cisco import config as cisco_config
from neutron.plugins.ml2.drivers.cisco import exceptions as c_exc
from neutron.plugins.ml2.drivers.cisco import mech_cisco_nexus
from neutron.plugins.ml2.drivers.cisco import nexus_db_v2
from neutron.plugins.ml2.drivers.cisco import nexus_network_driver
from neutron.plugins.ml2.drivers import type_vlan as vlan_config
from neutron.tests.unit import test_db_plugin

LOG = logging.getLogger(__name__)
ML2_PLUGIN = 'neutron.plugins.ml2.plugin.Ml2Plugin'
PHYS_NET = 'physnet1'
COMP_HOST_NAME = 'testhost'
VLAN_START = 1000
VLAN_END = 1100
NEXUS_IP_ADDR = '1.1.1.1'
CIDR_1 = '10.0.0.0/24'
CIDR_2 = '10.0.1.0/24'
DEVICE_ID_1 = '11111111-1111-1111-1111-111111111111'
DEVICE_ID_2 = '22222222-2222-2222-2222-222222222222'


class CiscoML2MechanismTestCase(test_db_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        """Configure for end-to-end neutron testing using a mock ncclient.

        This setup includes:
        - Configure the ML2 plugin to use VLANs in the range of 1000-1100.
        - Configure the Cisco mechanism driver to use an imaginary switch
          at NEXUS_IP_ADDR.
        - Create a mock NETCONF client (ncclient) for the Cisco mechanism
          driver

        """
        self.addCleanup(mock.patch.stopall)

        # Configure the ML2 mechanism drivers and network types
        ml2_opts = {
            'mechanism_drivers': ['cisco_nexus'],
            'tenant_network_types': ['vlan'],
        }
        for opt, val in ml2_opts.items():
                ml2_config.cfg.CONF.set_override(opt, val, 'ml2')
        self.addCleanup(ml2_config.cfg.CONF.reset)

        # Configure the ML2 VLAN parameters
        phys_vrange = ':'.join([PHYS_NET, str(VLAN_START), str(VLAN_END)])
        vlan_config.cfg.CONF.set_override('network_vlan_ranges',
                                          [phys_vrange],
                                          'ml2_type_vlan')
        self.addCleanup(vlan_config.cfg.CONF.reset)

        # Configure the Cisco Nexus mechanism driver
        nexus_config = {
            (NEXUS_IP_ADDR, 'username'): 'admin',
            (NEXUS_IP_ADDR, 'password'): 'mySecretPassword',
            (NEXUS_IP_ADDR, 'ssh_port'): 22,
            (NEXUS_IP_ADDR, COMP_HOST_NAME): '1/1'}
        nexus_patch = mock.patch.dict(
            cisco_config.ML2MechCiscoConfig.nexus_dict,
            nexus_config)
        nexus_patch.start()
        self.addCleanup(nexus_patch.stop)

        # The NETCONF client module is not included in the DevStack
        # distribution, so mock this module for unit testing.
        self.mock_ncclient = mock.Mock()
        mock.patch.object(nexus_network_driver.CiscoNexusDriver,
                          '_import_ncclient',
                          return_value=self.mock_ncclient).start()

        # Mock port values for 'status' and 'binding:segmenation_id'
        mock_status = mock.patch.object(
            mech_cisco_nexus.CiscoNexusMechanismDriver,
            '_is_status_active').start()
        mock_status.return_value = n_const.PORT_STATUS_ACTIVE

        def _mock_get_vlanid(context):
            port = context.current
            if port['device_id'] == DEVICE_ID_1:
                return VLAN_START
            else:
                return VLAN_START + 1

        mock_vlanid = mock.patch.object(
            mech_cisco_nexus.CiscoNexusMechanismDriver,
            '_get_vlanid').start()
        mock_vlanid.side_effect = _mock_get_vlanid

        super(CiscoML2MechanismTestCase, self).setUp(ML2_PLUGIN)

        self.port_create_status = 'DOWN'

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

    def _is_in_last_nexus_cfg(self, words):
        """Confirm last config sent to Nexus contains specified keywords."""
        last_cfg = (self.mock_ncclient.connect.return_value.
                    edit_config.mock_calls[-1][2]['config'])
        return all(word in last_cfg for word in words)


class TestCiscoBasicGet(CiscoML2MechanismTestCase,
                        test_db_plugin.TestBasicGet):

    pass


class TestCiscoV2HTTPResponse(CiscoML2MechanismTestCase,
                              test_db_plugin.TestV2HTTPResponse):

    pass


class TestCiscoPortsV2(CiscoML2MechanismTestCase,
                       test_db_plugin.TestPortsV2):

    @contextlib.contextmanager
    def _create_resources(self, name='myname', cidr=CIDR_1,
                          device_id=DEVICE_ID_1,
                          host_id=COMP_HOST_NAME,
                          expected_exception=None):
        """Create network, subnet, and port resources for test cases.

        Create a network, subnet, port and then update port, yield the result,
        then delete the port, subnet, and network.

        :param name: Name of network to be created.
        :param cidr: cidr address of subnetwork to be created.
        :param device_id: Device ID to use for port to be created/updated.
        :param host_id: Host ID to use for port create/update.
        :param expected_exception: Expected HTTP code.

        """
        ctx = context.get_admin_context()
        with self.network(name=name) as network:
            with self.subnet(network=network, cidr=cidr) as subnet:
                net_id = subnet['subnet']['network_id']
                args = (portbindings.HOST_ID, 'device_id', 'device_owner',
                        'admin_state_up')
                port_dict = {portbindings.HOST_ID: host_id,
                             'device_id': device_id,
                             'device_owner': 'compute:none',
                             'admin_state_up': True}

                res = self._create_port(self.fmt, net_id, arg_list=args,
                                        context=ctx, **port_dict)
                port = self.deserialize(self.fmt, res)

                expected_exception = self._expectedHTTP(expected_exception)
                data = {'port': port_dict}
                self._update('ports', port['port']['id'], data,
                             expected_code=expected_exception,
                             neutron_context=ctx)

                try:
                    yield port
                finally:
                    self._delete('ports', port['port']['id'])

    def _expectedHTTP(self, exc):
        """Map a Cisco exception to the HTTP status equivalent.

        :param exc: Expected Cisco exception

        """
        if exc == None:
            expected_http = wexc.HTTPOk.code
        elif exc in base.FAULT_MAP:
            expected_http = base.FAULT_MAP[exc].code
        else:
            expected_http = wexc.HTTPInternalServerError.code

        return expected_http

    def test_create_ports_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API chooses the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_obj = NeutronManager.get_plugin()
            orig = plugin_obj.create_port
            with mock.patch.object(plugin_obj,
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
            plugin_obj = NeutronManager.get_plugin()
            orig = plugin_obj.create_port
            with mock.patch.object(plugin_obj,
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
        """Verify the syntax of the command to enable a vlan on an intf.

        Confirm that for the first VLAN configured on a Nexus interface,
        the command string sent to the switch does not contain the
        keyword 'add'.

        Confirm that for the second VLAN configured on a Nexus interface,
        the command staring sent to the switch contains the keyword 'add'.

        """
        with self._create_resources(name='net1', cidr=CIDR_1):
            self.assertTrue(self._is_in_last_nexus_cfg(['allowed', 'vlan']))
            self.assertFalse(self._is_in_last_nexus_cfg(['add']))
            with self._create_resources(name='net2', device_id=DEVICE_ID_2,
                                        cidr=CIDR_2):
                self.assertTrue(
                    self._is_in_last_nexus_cfg(['allowed', 'vlan', 'add']))

    def test_nexus_connect_fail(self):
        """Test failure to connect to a Nexus switch.

        While creating a network, subnet, and port, simulate a connection
        failure to a nexus switch. Confirm that the expected HTTP code
        is returned for the create port operation.

        """
        with self._patch_ncclient('connect.side_effect',
                                  AttributeError):
            self._create_resources(expected_exception=c_exc.NexusConnectFailed)

    def test_nexus_config_fail(self):
        """Test a Nexus switch configuration failure.

        While creating a network, subnet, and port, simulate a nexus
        switch configuration error. Confirm that the expected HTTP code
        is returned for the create port operation.

        """
        with self._patch_ncclient(
            'connect.return_value.edit_config.side_effect',
            AttributeError):
            self._create_resources(expected_exception=c_exc.NexusConfigFailed)

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
            'connect.return_value.edit_config.side_effect',
            mock_edit_config_a):
            self._create_resources(name='myname')

        def mock_edit_config_b(target, config):
            if all(word in config for word in ['no', 'shutdown']):
                raise Exception("Command is only allowed on VLAN")

        with self._patch_ncclient(
            'connect.return_value.edit_config.side_effect',
            mock_edit_config_b):
            self._create_resources(name='myname')

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
            'connect.return_value.edit_config.side_effect',
            mock_edit_config):
            with self._create_resources(
                    name='myname',
                    expected_exception=c_exc.NexusConfigFailed):
                # Confirm that the last configuration sent to the Nexus
                # switch was deletion of the VLAN.
                self.assertTrue(self._is_in_last_nexus_cfg(['<no>', '<vlan>']))

    def test_nexus_host_not_configured(self):
        """Test handling of a NexusComputeHostNotConfigured exception.

        Test the Cisco NexusComputeHostNotConfigured exception by using
        a fictitious host name during port creation.

        """
        self._create_resources(
            host_id='fake_host',
            expected_exception=c_exc.NexusComputeHostNotConfigured)

    def test_nexus_bind_fail_rollback(self):
        """Test for proper rollback following add Nexus DB binding failure.

        Test that the Cisco Nexus plugin correctly rolls back the vlan
        configuration on the Nexus switch when add_nexusport_binding fails
        within the plugin's create_port() method.

        """
        with mock.patch.object(nexus_db_v2,
                               'add_nexusport_binding',
                               side_effect=KeyError):
            with self._create_resources(expected_exception=KeyError):
                # Confirm that the last configuration sent to the Nexus
                # switch was a removal of vlan from the test interface.
                self.assertTrue(
                    self._is_in_last_nexus_cfg(['<vlan>', '<remove>'])
                )

    def test_nexus_delete_port_rollback(self):
        """Test for proper rollback for nexus plugin delete port failure.

        Test for rollback (i.e. restoration) of a VLAN entry in the
        nexus database whenever the nexus plugin fails to reconfigure the
        nexus switch during a delete_port operation.

        """
        with self._create_resources() as port:
            # Check that there is only one binding in the nexus database
            # for this VLAN/nexus switch.
            start_rows = nexus_db_v2.get_nexusvlan_binding(VLAN_START,
                                                           NEXUS_IP_ADDR)
            self.assertEqual(len(start_rows), 1)

            # Simulate a Nexus switch configuration error during
            # port deletion.
            with self._patch_ncclient(
                'connect.return_value.edit_config.side_effect',
                AttributeError):
                self._delete('ports', port['port']['id'],
                             wexc.HTTPInternalServerError.code)

            # Confirm that the binding has been restored (rolled back).
            end_rows = nexus_db_v2.get_nexusvlan_binding(VLAN_START,
                                                         NEXUS_IP_ADDR)
            self.assertEqual(start_rows, end_rows)


class TestCiscoNetworksV2(CiscoML2MechanismTestCase,
                          test_db_plugin.TestNetworksV2):

    def test_create_networks_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        plugin_obj = NeutronManager.get_plugin()
        orig = plugin_obj.create_network
        #ensures the API choose the emulation code path
        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with mock.patch.object(plugin_obj,
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
        plugin_obj = NeutronManager.get_plugin()
        orig = plugin_obj.create_network
        with mock.patch.object(plugin_obj,
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


class TestCiscoSubnetsV2(CiscoML2MechanismTestCase,
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
            plugin_obj = NeutronManager.get_plugin()
            orig = plugin_obj.create_subnet
            with mock.patch.object(plugin_obj,
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
        plugin_obj = NeutronManager.get_plugin()
        orig = plugin_obj.create_subnet
        with mock.patch.object(plugin_obj,
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
