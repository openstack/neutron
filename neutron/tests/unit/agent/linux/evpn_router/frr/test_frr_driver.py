# Copyright 2026 Red Hat, Inc.
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

from neutron_lib import exceptions
from oslo_config import cfg

from neutron.agent.linux.evpn_router.frr import exceptions as frr_exceptions
from neutron.agent.linux.evpn_router.frr import frr_driver
from neutron.agent.linux.evpn_router import interface
from neutron.conf.agent.ovn.evpn import config as evpn_conf
from neutron.tests import base


def _build_test_evpn_router_config(vni):
    return interface.EVPNRouterConfig(
        asn=65000,
        bgp_router_id='10.0.0.1',
        vrf_name=f'vrf-{vni}',
        vni=vni,
    )


class TestFrrCommandBuilder(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.builder = frr_driver.FrrCommandBuilder()

    def test_add_bgp_router_cmds(self):
        config = _build_test_evpn_router_config(100)
        peer_iface = 'eth1'
        result = self.builder.add_bgp_router_cmds(config, peer_iface)

        self.assertIn(
            'router bgp %d' % config.asn, result)
        self.assertIn(
            'bgp router-id %s' % config.bgp_router_id, result)
        self.assertIn(
            'neighbor %s interface remote-as internal'
            % peer_iface, result)
        self.assertIn('address-family ipv4 unicast', result)
        self.assertIn('address-family ipv6 unicast', result)
        self.assertIn('address-family l2vpn evpn', result)
        self.assertIn('advertise-all-vni', result)

    def test_add_evpn_router_cmds(self):
        config = _build_test_evpn_router_config(100)
        result = self.builder.add_evpn_router_cmds(config)

        self.assertIn('vrf %s' % config.vrf_name, result)
        self.assertIn('vni %d' % config.vni, result)
        self.assertIn('address-family ipv4 unicast', result)
        self.assertIn('address-family ipv6 unicast', result)
        self.assertIn('address-family l2vpn evpn', result)
        self.assertIn('redistribute kernel', result)

    def test_delete_evpn_router_cmds(self):
        config = _build_test_evpn_router_config(100)
        result = self.builder.delete_evpn_router_cmds(config)

        self.assertIn('no vni %d' % config.vni, result)
        self.assertIn(
            'no router bgp %d vrf %s'
            % (config.asn, config.vrf_name), result)
        self.assertIn('no vrf %s' % config.vrf_name, result)

    def test_delete_bgp_router_cmds(self):
        config = _build_test_evpn_router_config(100)
        result = self.builder.delete_bgp_router_cmds(config)

        self.assertIn('no router bgp %d' % config.asn, result)


class TestFrrVtyshExecutor(base.BaseTestCase):

    VTY_SOCKET = '/run/frr'

    def setUp(self):
        super().setUp()
        evpn_conf.register_opts()
        self.execute = mock.patch.object(
            frr_driver.linux_utils, 'execute').start()
        self.executor = frr_driver.FrrVtyshExecutor()

    def test_execute_cli_cmd(self):
        self.execute.return_value = "BGP summary output"
        mock_cmd = 'show me something'

        out = self.executor.execute_cli_cmd(mock_cmd)

        self.assertEqual("BGP summary output", out)
        self.execute.assert_called_once_with(
            ['vtysh', '--vty_socket', self.VTY_SOCKET, '-c', mock_cmd],
            run_as_root=True,
        )

    def test_execute_cli_cmd_raises_on_failure(self):
        self.execute.side_effect = exceptions.ProcessExecutionError(
            'vtysh failure', returncode=1)

        self.assertRaises(
            frr_exceptions.FrrApplyError,
            self.executor.execute_cli_cmd,
            "show bgp summary",
        )

    def test_execute_cmds_calls_dryrun_then_apply(self):
        mock_cmds = "some config"
        self.executor.execute_cmds(mock_cmds)

        calls = self.execute.call_args_list
        self.assertEqual(3, len(calls))
        dryrun_cmd = calls[0][0][0]
        apply_cmd = calls[1][0][0]
        write_mem_cmd = calls[2][0][0]
        self.assertEqual('vtysh', dryrun_cmd[0])
        self.assertIn('--dryrun', dryrun_cmd)
        self.assertIn('-f', dryrun_cmd)
        self.assertEqual('vtysh', apply_cmd[0])
        self.assertIn('-f', apply_cmd)
        self.assertNotIn('--dryrun', apply_cmd)
        self.assertEqual(
            ['vtysh', '--vty_socket', self.VTY_SOCKET,
             '-c', 'write memory'], write_mem_cmd)

    def test_execute_cmds_raises_dryrun_error(self):
        mock_cmds = "bad config"
        self.execute.side_effect = exceptions.ProcessExecutionError(
            'syntax error', returncode=1)

        self.assertRaises(
            frr_exceptions.FrrDryrunError,
            self.executor.execute_cmds,
            mock_cmds,
        )
        self.execute.assert_called_once()
        dryrun_cmd = self.execute.call_args[0][0]
        self.assertIn('--dryrun', dryrun_cmd)

    def test_execute_cmds_raises_apply_error(self):
        mock_cmds = "config syntactically correct, but apply failed"

        def _dryrun_ok_apply_fail(cmd, **_kwargs):
            if '--dryrun' in cmd:
                return ''
            raise exceptions.ProcessExecutionError(
                'apply failed', returncode=1)

        self.execute.side_effect = _dryrun_ok_apply_fail

        self.assertRaises(
            frr_exceptions.FrrApplyError,
            self.executor.execute_cmds,
            mock_cmds,
        )

    def test_execute_cli_cmd_custom_vty_socket(self):
        custom_path = '/custom/frr/socket'
        cfg.CONF.set_override('frr_vty_socket', custom_path, group='ovn_evpn')
        self.execute.return_value = "output"

        self.executor.execute_cli_cmd('show version')

        self.execute.assert_called_once_with(
            ['vtysh', '--vty_socket', custom_path, '-c', 'show version'],
            run_as_root=True,
        )


class TestFrrVtyshDriver(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        self.vrf_handler = mock.Mock(spec=interface.EVPNRouterVrfHandler)
        self.driver = frr_driver.FrrVtyshDriver(
            peer_interface='peer_iface',
            vrf_handler=self.vrf_handler)
        self.cmd_builder = mock.Mock(
            spec=frr_driver.FrrCommandBuilder)
        self.executor = mock.Mock(
            spec=frr_driver.FrrVtyshExecutor)
        self.driver.cmd_builder = self.cmd_builder
        self.driver.executor = self.executor
        self.executor.execute_cli_cmd.return_value = '{}'
        mock.patch.object(frr_driver, 'LOG').start()

    def test_create_evpn_router(self):
        config = _build_test_evpn_router_config(100)
        self.driver.create_evpn_router(config)

        self.vrf_handler.ensure_vrf_exists.assert_called_once_with(
            config.vrf_name)
        self.executor.execute_cli_cmd.assert_called_once_with(
            'show bgp summary json')
        self.cmd_builder.add_bgp_router_cmds.assert_called_once_with(
            config, self.driver.peer_interface)
        self.cmd_builder.add_evpn_router_cmds.assert_called_once_with(
            config)
        self.executor.execute_cmds.assert_any_call(
            self.cmd_builder.add_bgp_router_cmds.return_value)
        self.executor.execute_cmds.assert_any_call(
            self.cmd_builder.add_evpn_router_cmds.return_value)

    def test_create_evpn_router_skips_bgp_when_exists(self):
        config = _build_test_evpn_router_config(100)
        self.executor.execute_cli_cmd.return_value = (
            '{"l2VpnEvpn": '
            '{"routerId": "%s", "as": %d}}'
            % (config.bgp_router_id, config.asn)
        )

        self.driver.create_evpn_router(config)

        self.cmd_builder.add_bgp_router_cmds.assert_not_called()
        self.cmd_builder.add_evpn_router_cmds.assert_called_once_with(
            config)
        self.executor.execute_cmds.assert_called_once_with(
            self.cmd_builder.add_evpn_router_cmds.return_value)

    def test_delete_evpn_router(self):
        config = _build_test_evpn_router_config(100)
        self.driver.delete_evpn_router(config)

        self.vrf_handler.ensure_vrf_deleted.assert_called_once_with(
            config.vrf_name)
        self.cmd_builder.delete_evpn_router_cmds\
            .assert_called_once_with(config)
        self.executor.execute_cmds.assert_called_once_with(
            self.cmd_builder.delete_evpn_router_cmds.return_value)

    def test_create_raises_on_vrf_failure(self):
        self.vrf_handler.ensure_vrf_exists.side_effect = (
            frr_exceptions.FrrVrfError(
                'vrf failed', step='ensure_vrf_exists'))

        self.assertRaises(
            frr_exceptions.FrrVrfError,
            self.driver.create_evpn_router,
            _build_test_evpn_router_config(100),
        )
        self.executor.execute_cli_cmd.assert_not_called()
        self.executor.execute_cmds.assert_not_called()

    def test_create_raises_on_bgp_check_failure(self):
        self.executor.execute_cli_cmd.side_effect = (
            frr_exceptions.FrrApplyError(
                'vtysh failed', step='execute_cli'))

        self.assertRaises(
            frr_exceptions.FrrApplyError,
            self.driver.create_evpn_router,
            _build_test_evpn_router_config(100),
        )
        self.cmd_builder.add_bgp_router_cmds.assert_not_called()
        self.executor.execute_cmds.assert_not_called()

    def test_create_raises_on_invalid_bgp_json(self):
        self.executor.execute_cli_cmd.return_value = 'not-json'

        self.assertRaises(
            frr_exceptions.FrrApplyError,
            self.driver.create_evpn_router,
            _build_test_evpn_router_config(100),
        )
        self.cmd_builder.add_bgp_router_cmds.assert_not_called()

    def test_create_raises_on_template_failure(self):
        self.cmd_builder.add_bgp_router_cmds.side_effect = (
            frr_exceptions.FrrTemplateRenderError(
                'render failed', step='template_render'))

        self.assertRaises(
            frr_exceptions.FrrTemplateRenderError,
            self.driver.create_evpn_router,
            _build_test_evpn_router_config(100),
        )
        self.executor.execute_cmds.assert_not_called()

    def test_delete_raises_on_vrf_failure(self):
        self.vrf_handler.ensure_vrf_deleted.side_effect = (
            frr_exceptions.FrrVrfError(
                'vrf failed', step='ensure_vrf_deleted'))

        self.assertRaises(
            frr_exceptions.FrrVrfError,
            self.driver.delete_evpn_router,
            _build_test_evpn_router_config(100),
        )
        self.executor.execute_cmds.assert_not_called()
