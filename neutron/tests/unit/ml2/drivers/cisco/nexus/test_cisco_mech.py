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
from neutron import context
from neutron.extensions import portbindings
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers.cisco.nexus import config as cisco_config
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as c_exc
from neutron.plugins.ml2.drivers.cisco.nexus import mech_cisco_nexus
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_network_driver
from neutron.tests.unit.ml2 import test_ml2_plugin


LOG = logging.getLogger(__name__)
PHYS_NET = 'physnet1'
COMP_HOST_NAME = 'testhost'
COMP_HOST_NAME_2 = 'testhost_2'
VLAN_START = 1000
VLAN_END = 1100
NEXUS_IP_ADDR = '1.1.1.1'
NETWORK_NAME = 'test_network'
NETWORK_NAME_2 = 'test_network_2'
NEXUS_INTERFACE = '1/1'
NEXUS_INTERFACE_2 = '1/2'
CIDR_1 = '10.0.0.0/24'
CIDR_2 = '10.0.1.0/24'
DEVICE_ID_1 = '11111111-1111-1111-1111-111111111111'
DEVICE_ID_2 = '22222222-2222-2222-2222-222222222222'
DEVICE_OWNER = 'compute:None'
BOUND_SEGMENT1 = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                  api.PHYSICAL_NETWORK: PHYS_NET,
                  api.SEGMENTATION_ID: VLAN_START}
BOUND_SEGMENT2 = {api.NETWORK_TYPE: p_const.TYPE_VLAN,
                  api.PHYSICAL_NETWORK: PHYS_NET,
                  api.SEGMENTATION_ID: VLAN_START + 1}


class CiscoML2MechanismTestCase(test_ml2_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['cisco_nexus']

    def setUp(self):
        """Configure for end-to-end neutron testing using a mock ncclient.

        This setup includes:
        - Configure the ML2 plugin to use VLANs in the range of 1000-1100.
        - Configure the Cisco mechanism driver to use an imaginary switch
          at NEXUS_IP_ADDR.
        - Create a mock NETCONF client (ncclient) for the Cisco mechanism
          driver

        """

        # Configure the Cisco Nexus mechanism driver
        nexus_config = {
            (NEXUS_IP_ADDR, 'username'): 'admin',
            (NEXUS_IP_ADDR, 'password'): 'mySecretPassword',
            (NEXUS_IP_ADDR, 'ssh_port'): 22,
            (NEXUS_IP_ADDR, COMP_HOST_NAME): NEXUS_INTERFACE,
            (NEXUS_IP_ADDR, COMP_HOST_NAME_2): NEXUS_INTERFACE_2}
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

        # Mock port context values for bound_segments and 'status'.
        self.mock_bound_segment = mock.patch.object(
            driver_context.PortContext,
            'bottom_bound_segment',
            new_callable=mock.PropertyMock).start()
        self.mock_bound_segment.return_value = BOUND_SEGMENT1

        self.mock_original_bound_segment = mock.patch.object(
            driver_context.PortContext,
            'original_bottom_bound_segment',
            new_callable=mock.PropertyMock).start()
        self.mock_original_bound_segment.return_value = None

        # Use _is_status_active method to determine bind state.
        def _mock_check_bind_state(port_context):
            if (port_context[portbindings.VIF_TYPE] !=
                portbindings.VIF_TYPE_UNBOUND):
                return True
            else:
                return False

        self.mock_status = mock.patch.object(
            mech_cisco_nexus.CiscoNexusMechanismDriver,
            '_is_status_active').start()
        self.mock_status.side_effect = _mock_check_bind_state

        super(CiscoML2MechanismTestCase, self).setUp()

        self.port_create_status = 'DOWN'

    def _create_deviceowner_mock(self):
        # Mock deviceowner method for UT's that expect update precommit
        # failures. This allows control of delete_port_pre/postcommit()
        # actions.
        mock_deviceowner = mock.patch.object(
            mech_cisco_nexus.CiscoNexusMechanismDriver,
            '_is_deviceowner_compute').start()
        mock_deviceowner.return_value = False
        self.addCleanup(mock_deviceowner.stop)

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

    @staticmethod
    def _config_dependent_side_effect(match_config, exc):
        """Generates a config-dependent side effect for ncclient edit_config.

        This method generates a mock side-effect function which can be
        configured on the mock ncclient module for the edit_config method.
        This side effect will cause a given exception to be raised whenever
        the XML config string that is passed to edit_config contains all
        words in a given match config string.

        :param match_config: String containing keywords to be matched
        :param exc: Exception to be raised when match is found
        :return: Side effect function for the mock ncclient module's
                 edit_config method.

        """
        keywords = match_config.split()

        def _side_effect_function(target, config):
            if all(word in config for word in keywords):
                raise exc
        return _side_effect_function

    def _is_in_nexus_cfg(self, words):
        """Check if any config sent to Nexus contains all words in a list."""
        for call in (self.mock_ncclient.connect.return_value.
                     edit_config.mock_calls):
            configlet = call[2]['config']
            if all(word in configlet for word in words):
                return True
        return False

    def _is_in_last_nexus_cfg(self, words):
        """Confirm last config sent to Nexus contains specified keywords."""
        last_cfg = (self.mock_ncclient.connect.return_value.
                    edit_config.mock_calls[-1][2]['config'])
        return all(word in last_cfg for word in words)

    def _is_vlan_configured(self, vlan_creation_expected=True,
                            first_vlan_addition=False):
        """Confirm if VLAN was configured or not."""
        vlan_created = self._is_in_nexus_cfg(['vlan', 'vlan-name'])
        add_appears = self._is_in_last_nexus_cfg(['add'])
        # The first VLAN being configured should be done without the
        # ADD keyword. Thereafter additional VLANs to be configured
        # should be done with the ADD keyword.
        add_keyword_expected = not first_vlan_addition
        return (self._is_in_last_nexus_cfg(['allowed', 'vlan']) and
                vlan_created == vlan_creation_expected and
                add_appears == add_keyword_expected)

    def _is_vlan_unconfigured(self, vlan_deletion_expected=True):
        vlan_deleted = self._is_in_last_nexus_cfg(
            ['no', 'vlan', 'vlan-id-create-delete'])
        return (self._is_in_nexus_cfg(['allowed', 'vlan', 'remove']) and
                vlan_deleted == vlan_deletion_expected)


class TestCiscoBasicGet(CiscoML2MechanismTestCase,
                        test_ml2_plugin.TestMl2BasicGet):

    pass


class TestCiscoV2HTTPResponse(CiscoML2MechanismTestCase,
                              test_ml2_plugin.TestMl2V2HTTPResponse):

    pass


class TestCiscoPortsV2(CiscoML2MechanismTestCase,
                       test_ml2_plugin.TestMl2PortsV2):

    @contextlib.contextmanager
    def _create_resources(self, name=NETWORK_NAME, cidr=CIDR_1,
                          device_id=DEVICE_ID_1,
                          host_id=COMP_HOST_NAME,
                          expected_failure=False):
        """Create network, subnet, and port resources for test cases.

        Create a network, subnet, port and then update the port, yield the
        result, then delete the port, subnet and network.

        :param name: Name of network to be created.
        :param cidr: cidr address of subnetwork to be created.
        :param device_id: Device ID to use for port to be created/updated.
        :param host_id: Host ID to use for port create/update.
        :param expected_failure: Set to True when an update_port_precommit
            failure is expected. Results in no actions being taken in
            delete_port_pre/postcommit() methods.
        """
        with self.network(name=name) as network:
            with self.subnet(network=network, cidr=cidr) as subnet:
                with self.port(subnet=subnet, cidr=cidr) as port:

                    data = {'port': {portbindings.HOST_ID: host_id,
                                     'device_id': device_id,
                                     'device_owner': DEVICE_OWNER,
                                     'admin_state_up': True}}
                    req = self.new_update_request('ports', data,
                                                  port['port']['id'])
                    yield req.get_response(self.api)
                    if expected_failure:
                        self._create_deviceowner_mock()
        self._delete('ports', port['port']['id'])
        self._delete('networks', network['network']['id'])

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

    def _mock_config_first_trunk(self):
        """Mock the behavior for the first VLAN addition.

        When the first VLAN is being added to the interface the usage of
        the ADD keyword should raise an exception specifying that the ADD
        keyword cannot be used till a VLAN list is created and to create
        a VLAN list the configuration should not contain the ADD keyword.

        """
        config = "switchport trunk allowed vlan add"
        exc = Exception("switchport trunk allowed vlan list is empty, "
                        "please specify a list using "
                        "'switchport trunk allowed vlan X' "
                        "before using the add option")
        return (self._patch_ncclient(
                'connect.return_value.edit_config.side_effect',
                self._config_dependent_side_effect(config, exc)))

    def test_create_ports_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API chooses the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_obj = manager.NeutronManager.get_plugin()
            orig = plugin_obj.create_port
            with mock.patch.object(plugin_obj,
                                   '_create_port_db') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._fail_second_call(patched_plugin, orig,
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
            plugin_obj = manager.NeutronManager.get_plugin()
            orig = plugin_obj.create_port
            with mock.patch.object(plugin_obj,
                                   '_create_port_db') as patched_plugin:

                def side_effect(*args, **kwargs):
                    return self._fail_second_call(patched_plugin, orig,
                                                  *args, **kwargs)

                patched_plugin.side_effect = side_effect
                res = self._create_port_bulk(self.fmt, 2, net['network']['id'],
                                             'test', True, context=ctx)
                # We expect an internal server error as we injected a fault
                self._validate_behavior_on_bulk_failure(
                    res,
                    'ports',
                    wexc.HTTPInternalServerError.code)

    def test_nexus_enable_vlan_cmd_on_same_host(self):
        """Verify the syntax of the command to enable a vlan on an intf.

        Test of the following ml2_conf_cisco_ini config:
        [ml2_mech_cisco_nexus:1.1.1.1]
        Resource A on host=COMP_HOST_NAME with vlan_id = 1000
        Resource B on host=COMP_HOST_NAME with vlan_id = 1001

        Confirm that when configuring the first VLAN on a Nexus interface,
        the final command string sent to the switch does not contain the
        keyword 'add'. The initial attempt will contain 'add' but when
        the switch rejects it, the re-attempt shouldn't contain the 'add'.

        Confirm that for the second VLAN configured on a Nexus interface,
        the command string sent to the switch contains the keyword 'add'
        since it is on the same host.

        """
        # First vlan should be configured without 'add' keyword and an
        # exception should be raised when it is done with the 'add'
        # thereby triggering a re-attempt without the 'add'.
        with self._mock_config_first_trunk():
            with self._create_resources():
                self.assertTrue(self._is_vlan_configured(
                        vlan_creation_expected=True,
                        first_vlan_addition=True))
                self.mock_ncclient.reset_mock()
                self.mock_bound_segment.return_value = BOUND_SEGMENT2

                # Second vlan should be configured with the 'add' keyword
                # when on first host.
                with(self._patch_ncclient(
                        'connect.return_value.edit_config.side_effect',
                        None)):
                    with self._create_resources(name=NETWORK_NAME_2,
                                                device_id=DEVICE_ID_2,
                                                cidr=CIDR_2,
                                                host_id=COMP_HOST_NAME):
                        self.assertTrue(self._is_vlan_configured(
                                vlan_creation_expected=True,
                                first_vlan_addition=False
                        ))

                    # Return to first segment for delete port calls.
                    self.mock_bound_segment.return_value = BOUND_SEGMENT1

    def test_nexus_enable_vlan_cmd_on_different_hosts(self):
        """Verify the syntax of the command to enable a vlan on an intf.

        Test of the following ml2_conf_cisco_ini config:
        [ml2_mech_cisco_nexus:1.1.1.1]
        Resource A on host=COMP_HOST_NAME with vlan_id = 1000
        Resource B on host=COMP_HOST_NAME_2 with vlan_id = 1001

        Confirm that when configuring the first VLAN on a Nexus interface,
        the final command string sent to the switch does not contain the
        keyword 'add'. The initial attempt will contain 'add' but when
        the switch rejects it, the re-attempt shouldn't contain the 'add'.

        Confirm that for the second VLAN configured on a Nexus interface,
        the command string sent to the switch does not contain the
        keyword 'add' since it is on a different host.

        """
        # First vlan should be configured without 'add' keyword and an
        # exception should be raised when it is done with the 'add'
        # thereby triggering a re-attempt without the 'add'.
        with self._mock_config_first_trunk():
            with self._create_resources():
                self.assertTrue(self._is_vlan_configured(
                        vlan_creation_expected=True,
                        first_vlan_addition=True))
                self.mock_ncclient.reset_mock()
                self.mock_bound_segment.return_value = BOUND_SEGMENT2

                # Second vlan should be configured without the 'add' keyword
                # when on second host.
                with self._create_resources(name=NETWORK_NAME_2,
                                            device_id=DEVICE_ID_2,
                                            cidr=CIDR_2,
                                            host_id=COMP_HOST_NAME_2):
                    self.assertTrue(self._is_vlan_configured(
                            vlan_creation_expected=True,
                            first_vlan_addition=True
                    ))

                # Return to first segment for delete port calls.
                self.mock_bound_segment.return_value = BOUND_SEGMENT1

    def test_ncclient_version_detect(self):
        """Test ability to handle connection to old and new-style ncclient.

        We used to require a custom version of the ncclient library. However,
        recent contributions to the ncclient make this unnecessary. Our
        driver was modified to be able to establish a connection via both
        the old and new type of ncclient.

        The new style ncclient.connect() function takes one additional
        parameter.

        The ML2 driver uses this to detect whether we are dealing with an
        old or new ncclient installation.

        """
        # The code we are exercising calls connect() twice, if there is a
        # TypeError on the first call (if the old ncclient is installed).
        # The second call should succeed. That's what we are simulating here.
        orig_connect_return_val = self.mock_ncclient.connect.return_value
        with self._patch_ncclient('connect.side_effect',
                                  [TypeError, orig_connect_return_val]):
            with self._create_resources() as result:
                self.assertEqual(result.status_int,
                                 wexc.HTTPOk.code)

    def test_ncclient_fail_on_second_connect(self):
        """Test that other errors during connect() sequences are still handled.

        If the old ncclient is installed, we expect to get a TypeError first,
        but should still handle other errors in the usual way, whether they
        appear on the first or second call to connect().

        """
        with self._patch_ncclient('connect.side_effect',
                                  [TypeError, IOError]):
            with self._create_resources() as result:
                self._assertExpectedHTTP(result.status_int,
                                         c_exc.NexusConnectFailed)

    def test_nexus_connect_fail(self):
        """Test failure to connect to a Nexus switch.

        While creating a network, subnet, and port, simulate a connection
        failure to a nexus switch. Confirm that the expected HTTP code
        is returned for the create port operation.

        """
        with self._patch_ncclient('connect.side_effect',
                                  AttributeError):
            with self._create_resources() as result:
                self._assertExpectedHTTP(result.status_int,
                                         c_exc.NexusConnectFailed)

    def test_nexus_vlan_config_two_hosts(self):
        """Verify config/unconfig of vlan on two compute hosts."""

        @contextlib.contextmanager
        def _create_port_check_vlan(comp_host_name, device_id,
                                    vlan_creation_expected=True):
            with self.port(subnet=subnet, fmt=self.fmt) as port:
                data = {'port': {portbindings.HOST_ID: comp_host_name,
                                 'device_id': device_id,
                                 'device_owner': DEVICE_OWNER,
                                 'admin_state_up': True}}
                req = self.new_update_request('ports', data,
                                              port['port']['id'])
                req.get_response(self.api)
                self.assertTrue(self._is_vlan_configured(
                    vlan_creation_expected=vlan_creation_expected,
                    first_vlan_addition=True))
                self.mock_ncclient.reset_mock()
                yield
            self._delete('ports', port['port']['id'])

        # Create network and subnet
        with self._mock_config_first_trunk():
            with self.network(name=NETWORK_NAME) as network:
                with self.subnet(network=network, cidr=CIDR_1) as subnet:

                    # Create an instance on first compute host
                    with _create_port_check_vlan(COMP_HOST_NAME, DEVICE_ID_1,
                                                 vlan_creation_expected=True):
                        # Create an instance on second compute host
                        with _create_port_check_vlan(
                            COMP_HOST_NAME_2,
                            DEVICE_ID_2,
                            vlan_creation_expected=False):
                            pass

                        # Instance on second host is now terminated.
                        # Vlan should be untrunked from port, but vlan should
                        # still exist on the switch.
                        self.assertTrue(self._is_vlan_unconfigured(
                                vlan_deletion_expected=False))
                        self.mock_ncclient.reset_mock()

                    # Instance on first host is now terminated.
                    # Vlan should be untrunked from port and vlan should have
                    # been deleted from the switch.
                    self.assertTrue(self._is_vlan_unconfigured(
                            vlan_deletion_expected=True))

    def test_nexus_vm_migration(self):
        """Verify VM (live) migration.

        Simulate the following:
        Nova informs neutron of live-migration with port-update(new host).
        This should trigger two update_port_pre/postcommit() calls.

        The first one should only change the current host_id and remove the
        binding resulting in the mechanism drivers receiving:
          PortContext.original['binding:host_id']: previous value
          PortContext.original_bottom_bound_segment: previous value
          PortContext.current['binding:host_id']: current (new) value
          PortContext.bottom_bound_segment: None

        The second one binds the new host resulting in the mechanism
        drivers receiving:
          PortContext.original['binding:host_id']: previous value
          PortContext.original_bottom_bound_segment: None
          PortContext.current['binding:host_id']: previous value
          PortContext.bottom_bound_segment: new value
        """

        # Create network, subnet and port.
        with self._create_resources() as result:
            # Verify initial database entry.
            # Use port_id to verify that 1st host name was used.
            binding = nexus_db_v2.get_nexusvm_bindings(VLAN_START,
                                                       DEVICE_ID_1)[0]
            intf_type, nexus_port = binding.port_id.split(':')
            self.assertEqual(nexus_port, NEXUS_INTERFACE)

            port = self.deserialize(self.fmt, result)
            port_id = port['port']['id']

            # Trigger update event to unbind segment.
            # Results in port being deleted from nexus DB and switch.
            data = {'port': {portbindings.HOST_ID: COMP_HOST_NAME_2}}
            self.mock_bound_segment.return_value = None
            self.mock_original_bound_segment.return_value = BOUND_SEGMENT1
            self.new_update_request('ports', data,
                                    port_id).get_response(self.api)

            # Verify that port entry has been deleted.
            self.assertRaises(c_exc.NexusPortBindingNotFound,
                              nexus_db_v2.get_nexusvm_bindings,
                              VLAN_START, DEVICE_ID_1)

            # Trigger update event to bind segment with new host.
            self.mock_bound_segment.return_value = BOUND_SEGMENT1
            self.mock_original_bound_segment.return_value = None
            self.new_update_request('ports', data,
                                    port_id).get_response(self.api)

            # Verify that port entry has been added using new host name.
            # Use port_id to verify that 2nd host name was used.
            binding = nexus_db_v2.get_nexusvm_bindings(VLAN_START,
                                                       DEVICE_ID_1)[0]
            intf_type, nexus_port = binding.port_id.split(':')
            self.assertEqual(nexus_port, NEXUS_INTERFACE_2)

    def test_nexus_config_fail(self):
        """Test a Nexus switch configuration failure.

        While creating a network, subnet, and port, simulate a nexus
        switch configuration error. Confirm that the expected HTTP code
        is returned for the create port operation.

        """
        with self._patch_ncclient(
            'connect.return_value.edit_config.side_effect',
            AttributeError):
            with self._create_resources() as result:
                self._assertExpectedHTTP(result.status_int,
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
            'connect.return_value.edit_config.side_effect',
            mock_edit_config_a):
            with self._create_resources() as result:
                self.assertEqual(result.status_int, wexc.HTTPOk.code)

        def mock_edit_config_b(target, config):
            if all(word in config for word in ['no', 'shutdown']):
                raise Exception("Command is only allowed on VLAN")

        with self._patch_ncclient(
            'connect.return_value.edit_config.side_effect',
            mock_edit_config_b):
            with self._create_resources() as result:
                self.assertEqual(result.status_int, wexc.HTTPOk.code)

    def test_nexus_vlan_config_rollback(self):
        """Test rollback following Nexus VLAN state config failure.

        Test that the Cisco Nexus plugin correctly deletes the VLAN
        on the Nexus switch when the 'state active' command fails (for
        a reason other than state configuration change is rejected
        for the extended VLAN range).

        """
        vlan_state_configs = ['state active', 'no shutdown']
        for config in vlan_state_configs:
            with self._patch_ncclient(
                'connect.return_value.edit_config.side_effect',
                self._config_dependent_side_effect(config, ValueError)):
                with self._create_resources() as result:
                    # Confirm that the last configuration sent to the Nexus
                    # switch was deletion of the VLAN.
                    self.assertTrue(
                        self._is_in_last_nexus_cfg(['<no>', '<vlan>'])
                    )
                    self._assertExpectedHTTP(result.status_int,
                                             c_exc.NexusConfigFailed)

    def test_nexus_host_not_configured(self):
        """Test handling of a NexusComputeHostNotConfigured exception.

        Test the Cisco NexusComputeHostNotConfigured exception by using
        a fictitious host name during port creation.

        """
        with self._create_resources(host_id='fake_host',
                                    expected_failure=True) as result:
            self._assertExpectedHTTP(result.status_int,
                                     c_exc.NexusComputeHostNotConfigured)

    def test_nexus_missing_fields(self):
        """Test handling of a NexusMissingRequiredFields exception.

        Test the Cisco NexusMissingRequiredFields exception by using
        empty device_id value during port creation.

        """
        with self._create_resources(device_id='',
                                    expected_failure=True) as result:
            self._assertExpectedHTTP(result.status_int,
                                     c_exc.NexusMissingRequiredFields)

    def test_update_port_mac(self):
        # REVISIT: test passes, but is back-end OK?
        host_arg = {
            portbindings.HOST_ID: COMP_HOST_NAME,
            'device_id': DEVICE_ID_1,
        }
        arg_list = (portbindings.HOST_ID, 'device_id',)
        self.check_update_port_mac(host_arg=host_arg, arg_list=arg_list)


class TestCiscoNetworksV2(CiscoML2MechanismTestCase,
                          test_ml2_plugin.TestMl2NetworksV2):

    def test_create_networks_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        plugin_obj = manager.NeutronManager.get_plugin()
        orig = plugin_obj.create_network
        #ensures the API choose the emulation code path
        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            with mock.patch.object(plugin_obj,
                                   '_create_network_db') as patched_plugin:
                def side_effect(*args, **kwargs):
                    return self._fail_second_call(patched_plugin, orig,
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
        plugin_obj = manager.NeutronManager.get_plugin()
        orig = plugin_obj.create_network
        with mock.patch.object(plugin_obj,
                               '_create_network_db') as patched_plugin:

            def side_effect(*args, **kwargs):
                return self._fail_second_call(patched_plugin, orig,
                                              *args, **kwargs)

            patched_plugin.side_effect = side_effect
            res = self._create_network_bulk(self.fmt, 2, 'test', True)
            # We expect an internal server error as we injected a fault
            self._validate_behavior_on_bulk_failure(
                res,
                'networks',
                wexc.HTTPInternalServerError.code)


class TestCiscoSubnetsV2(CiscoML2MechanismTestCase,
                         test_ml2_plugin.TestMl2SubnetsV2):

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        real_has_attr = hasattr

        #ensures the API choose the emulation code path
        def fakehasattr(item, attr):
            if attr.endswith('__native_bulk_support'):
                return False
            return real_has_attr(item, attr)

        with mock.patch('__builtin__.hasattr',
                        new=fakehasattr):
            plugin_obj = manager.NeutronManager.get_plugin()
            orig = plugin_obj.create_subnet
            with mock.patch.object(plugin_obj,
                                   '_create_subnet_db') as patched_plugin:

                def side_effect(*args, **kwargs):
                    self._fail_second_call(patched_plugin, orig,
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
        plugin_obj = manager.NeutronManager.get_plugin()
        orig = plugin_obj.create_subnet
        with mock.patch.object(plugin_obj,
                               '_create_subnet_db') as patched_plugin:
            def side_effect(*args, **kwargs):
                return self._fail_second_call(patched_plugin, orig,
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
