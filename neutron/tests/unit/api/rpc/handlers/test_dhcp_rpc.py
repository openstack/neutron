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

import operator
import pathlib

from collections import UserDict
from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_messaging.rpc import dispatcher as rpc_dispatcher
from oslo_utils import uuidutils

from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers.dhcp_rpc import CustomNetworkConfigError
from neutron.api.rpc.handlers.dhcp_rpc import CustomNetworkConfigurator
from neutron.api.rpc.handlers.dhcp_rpc import CustomNetworkSettings
from neutron.api.rpc.handlers.dhcp_rpc import DhcpRpcCallback
from neutron.common import utils
from neutron.db import provisioning_blocks
from neutron.objects import network as network_obj
from neutron.tests import base


class MockedDBObj(UserDict):
    def __getattr__(self, attr):
        try:
            return self.data[attr]
        except KeyError:
            raise AttributeError(f"'MockedNetwork' has no attribute '{attr}'")


class TestDhcpRpcCustomNetworkConfigurator(base.BaseTestCase):

    def _get_cnc_from_yaml_config(self, configdata: bytes)\
            -> CustomNetworkConfigurator:
        """returns a CustomNetworkConfigurator instance
        using the configuration in configdata provided as raw binary yaml
        """

        cfg.CONF.set_override('enabled', True,
                              group='customdns')
        # just needs to be set and a valid filename,
        # return data is mocked to return 'configdata'.
        cfg.CONF.set_override('config_file', 'irrelevant.yaml',
                              group='customdns')

        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            mock_pathlib.return_value = configdata
            cnc = CustomNetworkConfigurator()

        return cnc

    def test_network_dict_empty(self):
        """Ensure nothing is added to the network dict when
        nothing is configured.
        """
        cfg.CONF.set_override('enabled', True,
                              group='customdns')
        cfg.CONF.set_override('config_file', 'irrelevant.yaml',
                              group='customdns')

        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:

            mock_pathlib.return_value = b"matches:\n"
            cnc = CustomNetworkConfigurator()
            mock_pathlib.assert_called_once()

            empty_dict = {}
            cnc.add_dnssettings_to_net(empty_dict)
            self.assertFalse(bool(empty_dict))

    def test_ensure_config_not_read_if_not_enabled(self):
        """Ensure that we do not try to load the config file and there is no
        CustomNetworkConfigurator instance created, when the feature is not
        enabled.
        """
        cfg.CONF.set_override('enabled', False,
                              group='customdns')
        cfg.CONF.set_override('config_file', 'mock_did_not_work.yaml',
                              group='customdns')

        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            msg = "[Errno 2] No such file or directory: 'mock_was_called.yaml'"
            mock_pathlib.side_effect = FileNotFoundError(msg)
            rpc_callback = DhcpRpcCallback()

        mock_pathlib.assert_not_called()
        self.assertIsNone(rpc_callback._config_lookup)

    def test_ensure_config_file_is_required_if_enabled(self):
        """Ensure that if the feature is enabled but the file cannot be found
           we raise an exception when trying to start and trying to create
           an instance of DhcpRpcCallback.
        """
        cfg.CONF.set_override('enabled', True,
                              group='customdns')
        cfg.CONF.set_override('config_file', 'mock_did_not_work.yaml',
                              group='customdns')

        # DhcpRpcCallback will try to create a CustomNetworkConfigurator
        # which should trigger the exception:
        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            msg = "[Errno 2] No such file or directory: 'mock_was_called.yaml'"
            mock_pathlib.side_effect = FileNotFoundError(msg)
            self.assertRaises(CustomNetworkConfigError,
                              DhcpRpcCallback)
            mock_pathlib.assert_called_once()

    def test_ensure_config_enabled_flag_ignored_by_configurator(self):
        """Ensure that if the feature is disabled, we still can instanciate
        a CustomNetworkConfigurator.
        """
        cfg.CONF.set_override('enabled', False,
                              group='customdns')
        cfg.CONF.set_override('config_file', 'mock_did_not_work.yaml',
                              group='customdns')

        # CustomNetworkConfigurator will try to load the config file
        # with enabled=False because the flag triggers the overall feature
        # only and the config parser/config helper should not be too closely
        # coupled here.
        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:

            mock_pathlib.return_value = b"matches:\n"
            cnc = CustomNetworkConfigurator()
            mock_pathlib.assert_called_once()
            self.assertEqual({}, cnc._dns_config)

    def test_ensure_config_enabled_requires_valid_configfile(self):
        """Ensure that if the feature is enabled, we require a valid
        configuration file.
        """
        cfg.CONF.set_override('enabled', True,
                              group='customdns')
        cfg.CONF.set_override('config_file', None,
                              group='customdns')

        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            msg = "[Errno 2] No such file or directory: 'mock_was_called.yaml'"
            mock_pathlib.side_effect = FileNotFoundError(msg)
            self.assertRaises(CustomNetworkConfigError,
                              DhcpRpcCallback)
            mock_pathlib.assert_not_called()

    def test_yaml_config_parser(self):
        """Basic tests for an empty, invalid or on-purpose empty
        config file.
        """

        cfg.CONF.set_override('enabled', True,
                              group='customdns')
        # just needs to be set and a valid filename,
        # returned data is mocked.
        cfg.CONF.set_override('config_file', 'irrelevant.yaml',
                              group='customdns')

        # we do not allow an empty file as valid config
        empty_config = b""
        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            mock_pathlib.return_value = empty_config
            self.assertRaises(CustomNetworkConfigError,
                              CustomNetworkConfigurator)

        # we do not allow a file that has no metrics: key as valid config
        invalid_config = b"""
                          foobar:
                        """
        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            mock_pathlib.return_value = invalid_config
            self.assertRaises(CustomNetworkConfigError,
                              CustomNetworkConfigurator)

        # we _do_ allow a config with an on-purpose empty ruleset
        no_config = b"""
                     matches:
                    """
        with mock.patch.object(pathlib.Path, 'read_bytes') as \
                mock_pathlib:
            mock_pathlib.return_value = no_config
            cnc = CustomNetworkConfigurator()
            self.assertEqual({}, cnc._dns_config)

    def test_yaml_config_loader(self):
        """Test if the yaml config is converted to the expected internal
        data structure of our class. Ensures all options are picked up.
        """

        example_config = b"""
                matches:
                    -  domain_name_prefixes:
                        - ext-abc
                        - ext-def
                       project_ids:
                        - 5dc81c6355ff478188f8fda11a971c41
                        - 0631d17744fe4a04b16494ae9056ae17
                       ednslogging: False
                       upstream_dns_servers:
                        - 192.0.2.10
                        - 192.0.2.20
                    -  domain_name_prefixes:
                        - ext-abcd
                        - ext-
                       ednslogging: True
                       upstream_dns_servers:
                        - 192.0.2.30
                        - 192.0.2.40
                """

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        # CustomNetworkSettings will convert the list of IPs to a set
        # so we can compare them with ease below.
        config_1 = CustomNetworkSettings(
                False, {'192.0.2.10', '192.0.2.20'})
        config_2 = CustomNetworkSettings(
                True, {'192.0.2.30', '192.0.2.40'})

        example_config_expected = {
            'domains': {'ext-': config_2,
                        'ext-abc': config_1,
                        'ext-abcd': config_2,
                        'ext-def': config_1
                        },
            'projects': {'0631d17744fe4a04b16494ae9056ae17': config_1,
                         '5dc81c6355ff478188f8fda11a971c41': config_1
                         }
        }

        self.assertEqual(example_config_expected, cnc._dns_config)

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_no_match_no_change(self, mock_keystone):
        """ensure that we do not change a network setting if the domain
         and project do not match the ones in the config
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network = {'id': 'net-123', 'project_id': 'p-666'}
        mock_project = MockedDBObj(id='p-666', domain_id='d-42')
        mock_domain = MockedDBObj(id='d-42', name='mydomain')

        mock_keystone.get_project.return_value = mock_project
        mock_keystone.get_domain.return_value = mock_domain

        example_config = b"""
                matches:
                    -  domain_name_prefixes:
                        - ext-abc
                       project_ids:
                        - 5dc81c6355ff478188f8fda11a971c41
                       ednslogging: True
                       upstream_dns_servers:
                        - 192.0.2.10
                        - 192.0.2.20
                """

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network)

        mock_keystone.get_project.assert_called_with('p-666')
        mock_keystone.get_domain.assert_called_with('d-42')

        # assert we do not change the settings
        self.assertIsNone(mock_network.get('dns_ednslogging_enabled'))
        self.assertIsNone(mock_network.get('dns_custom_upstreams'))

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_network_id_lookup(self, mock_keystone):
        """ensure keystone lookup methods are called and the network
           returned matches the expected settings
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network = {'id': 'net-123', 'project_id': 'p-666'}
        mock_project = MockedDBObj(id='p-666', domain_id='d-42')
        mock_domain = MockedDBObj(id='d-42', name='mydomain')

        mock_keystone.get_project.return_value = mock_project
        mock_keystone.get_domain.return_value = mock_domain

        example_config = b"""
                matches:
                    -  domain_name_prefixes:
                        - mydomain
                       ednslogging: False
                """

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network)

        mock_keystone.get_project.assert_called_with('p-666')
        mock_keystone.get_domain.assert_called_with('d-42')

        # assert we get the correct settings when no nameservers are set
        # but logging should be off
        self.assertFalse(mock_network.get('dns_ednslogging_enabled'))
        self.assertIsNone(mock_network.get('dns_custom_upstreams'))

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_nameserver_settings_applied(self, mock_keystone):
        """ensure that if the domain of a network matched, the configured
           nameserver IPs are present in the network dict returned
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network = {'id': 'net-123', 'project_id': 'p-666'}
        mock_project = MockedDBObj(id='p-666', domain_id='d-42')
        mock_domain = MockedDBObj(id='d-42', name='mydomain')

        mock_keystone.get_project.return_value = mock_project
        mock_keystone.get_domain.return_value = mock_domain

        dns1 = "2001:db8::456"
        dns2 = "192.0.2.123"

        example_config = b"""
                   matches:
                       -  domain_name_prefixes:
                           - mydomain
                          upstream_dns_servers:
                           - %s
                           - %s
                          ednslogging: False
                   """ % (dns1.encode(), dns2.encode())

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network)
        self.assertFalse(mock_network.get('dns_ednslogging_enabled'))
        sentinel = object()
        upstreams = mock_network.get('dns_custom_upstreams', sentinel)
        self.assertNotEqual(sentinel, upstreams)
        self.assertIsNotNone(upstreams)
        self.assertIn(dns1, upstreams)
        self.assertIn(dns2, upstreams)
        self.assertEqual(len(upstreams), 2)

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_longest_domain_prefix_wins(self, mock_keystone):
        """ensure we are doing a longest prefix match on the domain name,
        that is if a match 'ext-123' and 'ext-' is present, a domain named
        'ext-1234' will match the settings for 'ext-123' and not 'ext-'.

        This allows configuration of a fallback for all "ext-*" domains.
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network = {'id': 'net-123', 'project_id': 'p-666'}
        mock_project = MockedDBObj(id='p-666', domain_id='d-42')
        mock_domain = MockedDBObj(id='d-42', name='mydomain-123')

        mock_keystone.get_project.return_value = mock_project
        mock_keystone.get_domain.return_value = mock_domain

        dns1 = "2001:db8::456"
        dns2 = "192.0.2.123"

        example_config = b"""
                   matches:
                       -  domain_name_prefixes:
                           - mydo
                          upstream_dns_servers:
                           - 192.0.2.222
                           - 192.0.2.111
                          ednslogging: True
                       -  domain_name_prefixes:
                           - mydomain-
                          upstream_dns_servers:
                           - %s
                           - %s
                          ednslogging: False
                   """ % (dns1.encode(), dns2.encode())

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network)

        self.assertFalse(mock_network.get('dns_ednslogging_enabled'))

        upstreams = mock_network.get('dns_custom_upstreams')
        self.assertIn(dns1, upstreams)
        self.assertIn(dns2, upstreams)

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_project_lookup_exceptions_dont_prevent_netconf(
            self,
            mock_keystone):
        """ensure that all exceptions are catched and do not break the
           rpc call when doing the project lookup
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network = {'id': 'net-123', 'project_id': 'p-666'}
        mock_domain = MockedDBObj(id='d-42', name='mydomain-123')

        mock_keystone.get_project.side_effect = Exception('Test')
        mock_keystone.get_domain.return_value = mock_domain

        example_config = b"""
                   matches:
                       -  domain_name_prefixes:
                           - mydomain-
                          upstream_dns_servers:
                           - 2001:db8::456
                           - 192.0.2.123
                          ednslogging: False
                   """

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network)
        upstreams = mock_network.get('dns_custom_upstreams')
        self.assertIsNone(upstreams)

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_domain_lookup_exceptions_do_not_prevent_netconfig(
            self,
            mock_keystone):
        """ensure that all exceptions are catched and do not break the
           rpc call when doing the domain lookup
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network = {'id': 'net-123', 'project_id': 'p-666'}
        mock_project = MockedDBObj(id='p-666', domain_id='d-42')

        mock_keystone.get_project.return_value = mock_project
        mock_keystone.get_domain.side_effect = Exception('Test')

        example_config = b"""
                   matches:
                       -  domain_name_prefixes:
                           - mydomain
                          upstream_dns_servers:
                           - 2001:db8::456
                           - 192.0.2.123
                          ednslogging: False
                   """

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network)
        upstreams = mock_network.get('dns_custom_upstreams')
        self.assertIsNone(upstreams)

    @mock.patch.object(CustomNetworkConfigurator, "_keystone_connection")
    def test_network_ednslogging_setting(self, mock_keystone):
        """ensure the networks can be configured with or without edns logging
        """

        # we manipulate the network, so we need fresh mock objects
        mock_network_nologging = {'id': 'net-nolog-123', 'project_id': 'p-666'}
        mock_network_logging = {'id': 'net-log-456', 'project_id': 'p-667'}

        example_config = b"""
                matches:
                    -  project_ids:
                        - p-666
                       ednslogging: False
                    -  project_ids:
                        - p-667
                       ednslogging: True
                """

        cnc = self._get_cnc_from_yaml_config(configdata=example_config)

        cnc.add_dnssettings_to_net(mock_network_nologging)
        cnc.add_dnssettings_to_net(mock_network_logging)

        # assert we get the correct settings when no nameservers are set
        # but logging is configured accordingly
        self.assertFalse(mock_network_nologging.get('dns_ednslogging_enabled'))
        self.assertTrue(mock_network_logging.get('dns_ednslogging_enabled'))

        self.assertIsNone(mock_network_nologging.get('dns_custom_upstreams'))
        self.assertIsNone(mock_network_logging.get('dns_custom_upstreams'))

    def test_exceptions_configerror_types(self):
        """ensure we are catching non-ip entries in the dns server settings
        """

        example_config = b"""
                   matches:
                       -  project_ids:
                           - p-666
                          upstream_dns_servers:
                           - not-an-ip-address
                          ednslogging: False
                   """

        try:
            self._get_cnc_from_yaml_config(configdata=example_config)
        except CustomNetworkConfigError as e:
            self.assertIn('not-an-ip-address', str(e))

        example_config = b"""
                   matches:
                       -  project_ids:
                           - p-666
                          ednslogging: NotABoolean
                   """
        try:
            self._get_cnc_from_yaml_config(configdata=example_config)
        except CustomNetworkConfigError as e:
            self.assertIn('NotABoolean', str(e))


class TestDhcpRpcCallback(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpRpcCallback, self).setUp()
        self.plugin = mock.MagicMock()
        directory.add_plugin(plugin_constants.CORE, self.plugin)
        self.callbacks = dhcp_rpc.DhcpRpcCallback()
        self.log_p = mock.patch('neutron.api.rpc.handlers.dhcp_rpc.LOG')
        self.log = self.log_p.start()
        set_dirty_p = mock.patch('neutron.quota.resource_registry.'
                                 'set_resources_dirty')
        self.mock_set_dirty = set_dirty_p.start()
        self.utils_p = mock.patch('neutron_lib.plugins.utils.create_port')
        self.utils = self.utils_p.start()
        self.agent_hosting_network_p = mock.patch.object(self.callbacks,
            '_is_dhcp_agent_hosting_network')
        self.mock_agent_hosting_network = self.agent_hosting_network_p.start()
        self.mock_agent_hosting_network.return_value = True
        self.segment_plugin = mock.MagicMock()
        directory.add_plugin('segments', self.segment_plugin)

    def test_group_by_network_id(self):
        port1 = {'network_id': 'a'}
        port2 = {'network_id': 'b'}
        port3 = {'network_id': 'a'}
        grouped_ports = self.callbacks._group_by_network_id(
                                                        [port1, port2, port3])
        expected = {'a': [port1, port3], 'b': [port2]}
        self.assertEqual(expected, grouped_ports)

    def test_get_active_networks_info(self):
        networks = [mock.Mock(id='net1'), mock.Mock(id='net2'),
                    mock.Mock(id='net3')]
        ports = [{'id': 'port1', 'network_id': 'net1'},
                 {'id': 'port2', 'network_id': 'net2'},
                 {'id': 'port3', 'network_id': 'net3'}]
        self.plugin.get_ports.return_value = ports
        iter_kwargs = iter([{'enable_dhcp_filter': True, 'host': 'test-host'},
                            {'enable_dhcp_filter': False, 'host': 'test-host'},
                            {'host': 'test-host'}])
        with mock.patch.object(self.callbacks, '_get_active_networks') as \
                mock_get_networks, \
                mock.patch.object(self.callbacks, 'get_network_info') as \
                mock_get_network_info:
            mock_get_networks.return_value = networks
            mock_get_network_info.side_effect = networks
            kwargs = next(iter_kwargs)
            ret = self.callbacks.get_active_networks_info('ctx', **kwargs)
            self.assertEqual(networks, ret)
            enable_dhcp = (True if kwargs.get('enable_dhcp_filter', True) else
                           None)
            mock_get_network_info.assert_has_calls([
                mock.call('ctx', network=networks[0], enable_dhcp=enable_dhcp,
                          host='test-host', ports=[ports[0]]),
                mock.call('ctx', network=networks[1], enable_dhcp=enable_dhcp,
                          host='test-host', ports=[ports[1]]),
                mock.call('ctx', network=networks[2], enable_dhcp=enable_dhcp,
                          host='test-host', ports=[ports[2]])
            ])

    def _test__port_action_with_failures(self, exc=None, action=None):
        port = {
            'network_id': 'foo_network_id',
            'device_owner': constants.DEVICE_OWNER_DHCP,
            'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
        }
        self.plugin.create_port.side_effect = exc
        self.utils.side_effect = exc
        self.assertIsNone(self.callbacks._port_action(self.plugin,
                                                      mock.Mock(),
                                                      {'port': port},
                                                      action))

    def _test__port_action_good_action(self, action, port, expected_call):
        self.callbacks._port_action(self.plugin, mock.Mock(),
                                    port, action)
        if action == 'create_port':
            self.utils.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY)
        else:
            self.plugin.assert_has_calls([expected_call])

    def test_port_action_create_port(self):
        self._test__port_action_good_action(
            'create_port', mock.Mock(),
            mock.call.create_port(mock.ANY, mock.ANY))

    def test_port_action_update_port(self):
        fake_port = {'id': 'foo_port_id', 'port': mock.Mock()}
        self._test__port_action_good_action(
            'update_port', fake_port,
            mock.call.update_port(mock.ANY, 'foo_port_id', mock.ANY))

    def test__port_action_bad_action(self):
        self.assertRaises(
            exceptions.Invalid,
            self._test__port_action_with_failures,
            exc=None,
            action='foo_action')

    def test_create_port_catch_network_not_found(self):
        self._test__port_action_with_failures(
            exc=exceptions.NetworkNotFound(net_id='foo_network_id'),
            action='create_port')

    def test_create_port_catch_subnet_not_found(self):
        self._test__port_action_with_failures(
            exc=exceptions.SubnetNotFound(subnet_id='foo_subnet_id'),
            action='create_port')

    def test_create_port_catch_db_reference_error(self):
        self._test__port_action_with_failures(
            exc=db_exc.DBReferenceError('a', 'b', 'c', 'd'),
            action='create_port')

    def test_create_port_catch_ip_generation_failure_reraise(self):
        self.assertRaises(
            exceptions.IpAddressGenerationFailure,
            self._test__port_action_with_failures,
            exc=exceptions.IpAddressGenerationFailure(net_id='foo_network_id'),
            action='create_port')

    def test_create_port_catch_and_handle_ip_generation_failure(self):
        self.plugin.get_subnet.side_effect = (
            exceptions.SubnetNotFound(subnet_id='foo_subnet_id'))
        self._test__port_action_with_failures(
            exc=exceptions.IpAddressGenerationFailure(net_id='foo_network_id'),
            action='create_port')
        self._test__port_action_with_failures(
            exc=exceptions.InvalidInput(error_message='sorry'),
            action='create_port')

    def test_update_port_missing_port_on_get(self):
        self.plugin.get_port.side_effect = exceptions.PortNotFound(
            port_id='66')
        self.assertIsNone(self.callbacks.update_dhcp_port(
            context='ctx', host='host', port_id='66',
            port={'port': {'network_id': 'a'}}))

    def test_update_port_missing_port_on_update(self):
        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.plugin.update_port.side_effect = exceptions.PortNotFound(
            port_id='66')
        self.assertIsNone(self.callbacks.update_dhcp_port(
            context='ctx', host='host', port_id='66',
            port={'port': {'network_id': 'a'}}))

    @mock.patch.object(network_obj.Network, 'get_object', return_value=None)
    def test_get_network_info_return_none_on_not_found(self, *args):
        retval = self.callbacks.get_network_info(mock.Mock(), network_id='a')
        self.assertIsNone(retval)

    @mock.patch.object(network_obj.Network, 'get_object')
    def _test_get_network_info(self, mock_net_get_object,
                               segmented_network=False, routed_network=False,
                               network_info=False, enable_dhcp=True):
        def _network_to_dict(network, ports, enable_dhcp):
            segment_ids = ['1']
            if enable_dhcp is None:
                subnets = [_make_subnet_dict(sn) for sn in
                           network.db_obj.subnets]
            else:
                subnets = [_make_subnet_dict(sn) for sn in
                           network.db_obj.subnets if
                           sn.enable_dhcp == enable_dhcp]
            if routed_network:
                non_local_subnets = [subnet for subnet in subnets
                                     if subnet.get('segment_id') not in
                                     segment_ids]
                subnets = [subnet for subnet in subnets
                           if subnet.get('segment_id') in segment_ids]
            else:
                non_local_subnets = []
            ret = {'id': network.id,
                   'project_id': network.project_id,
                   'tenant_id': network.project_id,
                   'admin_state_up': network.admin_state_up,
                   'ports': ports,
                   'subnets': sorted(subnets, key=operator.itemgetter('id')),
                   'non_local_subnets': sorted(non_local_subnets,
                                               key=operator.itemgetter('id')),
                   'mtu': network.mtu}
            # Plugin segment is activated globally, the tests is asserting the
            # return.
            ret['segments'] = [{'id': segment.id,
                                'network_id': segment.network_id,
                                'name': segment.name,
                                'network_type': segment.network_type,
                                'physical_network': segment.physical_network,
                                'segmentation_id': segment.segmentation_id,
                                'is_dynamic': segment.is_dynamic,
                                'segment_index': segment.segment_index,
                                'hosts': segment.hosts
                                } for segment in network.segments]
            return ret

        def _make_subnet_dict(subnet):
            ret = {'id': subnet.id}
            if isinstance(subnet.segment_id, str):
                ret['segment_id'] = subnet.segment_id
            return ret

        if not routed_network:
            subnets = [mock.Mock(id='a', enable_dhcp=True),
                       mock.Mock(id='c', enable_dhcp=True),
                       mock.Mock(id='b', enable_dhcp=False)]
        else:
            subnets = [mock.Mock(id='a', segment_id='1', enable_dhcp=True),
                       mock.Mock(id='c', segment_id='2', enable_dhcp=True),
                       mock.Mock(id='b', segment_id='1', enable_dhcp=False)]
        db_obj = mock.Mock(subnets=subnets)
        project_id = uuidutils.generate_uuid()
        network = mock.Mock(id='a', admin_state_up=True, db_obj=db_obj,
                            project_id=project_id, mtu=1234)
        ports = mock.Mock()
        if not network_info:
            mock_net_get_object.return_value = network
            self.plugin.get_ports.return_value = ports
        self.plugin._make_subnet_dict = _make_subnet_dict

        if segmented_network:
            network.segments = [mock.Mock(id='1', hosts=['host1']),
                                mock.Mock(id='2', hosts=['host2'])]
        else:
            network.segments = []

        _kwargs = {'network_id': 'a', 'host': 'host1'}
        if network_info:
            _kwargs.update({'network': network,
                            'enable_dhcp': enable_dhcp,
                            'ports': ports})
        retval = self.callbacks.get_network_info(mock.Mock(), **_kwargs)
        reference = _network_to_dict(network, ports, enable_dhcp)
        self.assertEqual(reference, retval)

    def test_get_network_info(self):
        self._test_get_network_info()

    def test_get_network_info_with_routed_network(self):
        self._test_get_network_info(segmented_network=True,
                                    routed_network=True)

    def test_get_network_info_with_segmented_network_but_not_routed(self):
        self._test_get_network_info(segmented_network=True)

    def test_get_network_info_with_non_segmented_network(self):
        self._test_get_network_info()

    def test_get_network_info_with_network_info_provided(self):
        self._test_get_network_info(network_info=True)
        self._test_get_network_info(network_info=True, enable_dhcp=True)
        self._test_get_network_info(network_info=True, enable_dhcp=False)
        self._test_get_network_info(network_info=True, enable_dhcp=None)

    def test_update_dhcp_port_verify_port_action_port_dict(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  portbindings.HOST_ID: 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }

        def _fake_port_action(plugin, context, port, action):
            self.assertEqual(expected_port, port)

        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.callbacks._port_action = _fake_port_action
        self.callbacks.update_dhcp_port(mock.Mock(),
                                        host='foo_host',
                                        port_id='foo_port_id',
                                        port=port)

    def test_update_reserved_dhcp_port(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  portbindings.HOST_ID: 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }

        def _fake_port_action(plugin, context, port, action):
            self.assertEqual(expected_port, port)

        self.plugin.get_port.return_value = {
            'device_id': utils.get_dhcp_agent_device_id('foo_network_id',
                                                        'foo_host')}
        self.callbacks._port_action = _fake_port_action
        self.callbacks.update_dhcp_port(
            mock.Mock(), host='foo_host', port_id='foo_port_id', port=port)

        self.plugin.get_port.return_value = {
            'device_id': 'other_id'}
        res = self.callbacks.update_dhcp_port(mock.Mock(), host='foo_host',
                                        port_id='foo_port_id', port=port)
        self.assertIsNone(res)

    def test_update_dhcp_port(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  portbindings.HOST_ID: 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }
        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.callbacks.update_dhcp_port(mock.Mock(),
                                        host='foo_host',
                                        port_id='foo_port_id',
                                        port=port)
        self.plugin.assert_has_calls([
            mock.call.update_port(mock.ANY, 'foo_port_id', expected_port)])

    def test_update_dhcp_port_with_agent_not_hosting_network(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.mock_agent_hosting_network.return_value = False
        self.assertRaises(rpc_dispatcher.ExpectedException,
                          self.callbacks.update_dhcp_port,
                          mock.Mock(),
                          host='foo_host',
                          port_id='foo_port_id',
                          port=port)

    def test__is_dhcp_agent_hosting_network(self):
        self.agent_hosting_network_p.stop()
        agent = mock.Mock()
        with mock.patch.object(self.plugin, 'get_dhcp_agents_hosting_networks',
                               return_value=[agent]):
            ret = self.callbacks._is_dhcp_agent_hosting_network(self.plugin,
                mock.Mock(), host='foo_host', network_id='foo_network_id')
        self.assertTrue(ret)

    def test__is_dhcp_agent_hosting_network_false(self):
        self.agent_hosting_network_p.stop()
        with mock.patch.object(self.plugin, 'get_dhcp_agents_hosting_networks',
                               return_value=[]):
            ret = self.callbacks._is_dhcp_agent_hosting_network(self.plugin,
                mock.Mock(), host='foo_host', network_id='foo_network_id')
        self.assertFalse(ret)

    def test_release_dhcp_port(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        self.plugin.get_ports.return_value = [port_retval]

        self.callbacks.release_dhcp_port(mock.ANY, network_id='netid',
                                         device_id='devid')

        self.plugin.assert_has_calls([
            mock.call.delete_ports_by_device_id(mock.ANY, 'devid', 'netid')])

    def test_dhcp_ready_on_ports(self):
        context = mock.Mock()
        port_ids = range(10)
        with mock.patch.object(provisioning_blocks,
                               'provisioning_complete') as pc:
            self.callbacks.dhcp_ready_on_ports(context, port_ids)
        calls = [mock.call(context, port_id, resources.PORT,
                           provisioning_blocks.DHCP_ENTITY)
                 for port_id in port_ids]
        pc.assert_has_calls(calls)
