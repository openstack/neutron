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

import tempfile
import typing

import jinja2
from neutron_lib import exceptions
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.agent.linux.evpn_router.frr import exceptions as frr_exceptions
from neutron.agent.linux.evpn_router.frr import templates as frr_tmpl
from neutron.agent.linux.evpn_router import interface
from neutron.agent.linux import utils as linux_utils


LOG = logging.getLogger(__name__)


class FrrCommandBuilder:

    def __init__(self):
        self._env = jinja2.Environment(
            loader=jinja2.DictLoader(frr_tmpl.TMPL_MAP),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def _render_template(
            self, template_name: frr_tmpl.TmplName,
            context: dict[str, typing.Any]) -> str:
        try:
            template = self._env.get_template(str(template_name))
            return template.render(context)
        except Exception as err:
            raise frr_exceptions.FrrTemplateRenderError(
                "Failed to render FRR template context:\n%s" % context,
                step=str(template_name),
                cause=err,
            ) from err

    def _build_base_bgp_context(
            self, config: interface.EVPNRouterConfig,
            peer_interface: str) -> dict[str, str]:
        bgp_router_context = {
            'asn': config.asn,
            'bgp_router_id': config.bgp_router_id,
            'peer_interface': peer_interface,
        }
        bgp_af_context = {
            'peer_interface': peer_interface,
        }
        return {
            frr_tmpl.TmplName.BGP_ROUTER_CONFIG: self._render_template(
                frr_tmpl.TmplName.BGP_ROUTER_CONFIG,
                bgp_router_context,
            ),
            frr_tmpl.TmplName.BGP_AF_IPV4_UNICAST: self._render_template(
                frr_tmpl.TmplName.BGP_AF_IPV4_UNICAST,
                bgp_af_context,
            ),
            frr_tmpl.TmplName.BGP_AF_IPV6_UNICAST: self._render_template(
                frr_tmpl.TmplName.BGP_AF_IPV6_UNICAST,
                bgp_af_context,
            ),
            frr_tmpl.TmplName.BGP_AF_L2VPN_EVPN: self._render_template(
                frr_tmpl.TmplName.BGP_AF_L2VPN_EVPN,
                bgp_af_context,
            ),
        }

    def _build_evpn_context(
            self, config: interface.EVPNRouterConfig) -> dict[str, typing.Any]:
        evpn_router_context = {
            'asn': config.asn,
            'bgp_router_id': config.bgp_router_id,
            'vrf_name': config.vrf_name,
        }
        return {
            'vrf_name': config.vrf_name,
            'vni': config.vni,
            frr_tmpl.TmplName.EVPN_ROUTER_CONFIG: self._render_template(
                frr_tmpl.TmplName.EVPN_ROUTER_CONFIG,
                evpn_router_context,
            ),
            frr_tmpl.TmplName.EVPN_AF_IPV4_UNICAST: self._render_template(
                frr_tmpl.TmplName.EVPN_AF_IPV4_UNICAST,
                {},
            ),
            frr_tmpl.TmplName.EVPN_AF_IPV6_UNICAST: self._render_template(
                frr_tmpl.TmplName.EVPN_AF_IPV6_UNICAST,
                {},
            ),
            frr_tmpl.TmplName.EVPN_AF_L2VPN_EVPN: self._render_template(
                frr_tmpl.TmplName.EVPN_AF_L2VPN_EVPN,
                {},
            ),
        }

    def _build_delete_evpn_context(
            self, config: interface.EVPNRouterConfig) -> dict[str, typing.Any]:
        return {
            'vrf_name': config.vrf_name,
            'vni': config.vni,
            'asn': config.asn,
        }

    def _build_delete_bgp_context(
            self, asn: int) -> dict[str, typing.Any]:
        return {
            'asn': asn,
        }

    def add_bgp_router_cmds(self, config: interface.EVPNRouterConfig,
                            peer_interface: str) -> str:
        context = self._build_base_bgp_context(
            config=config, peer_interface=peer_interface)
        return self._render_template(frr_tmpl.TmplName.ADD_BGP_ROUTER, context)

    def add_evpn_router_cmds(
            self, config: interface.EVPNRouterConfig) -> str:
        context = self._build_evpn_context(config=config)
        return self._render_template(
            frr_tmpl.TmplName.ADD_EVPN_ROUTER, context)

    def delete_evpn_router_cmds(
            self, config: interface.EVPNRouterConfig) -> str:
        context = self._build_delete_evpn_context(config=config)
        return self._render_template(
            frr_tmpl.TmplName.DEL_EVPN_ROUTER, context)

    def delete_bgp_router_cmds(
            self, config: interface.EVPNRouterConfig) -> str:
        context = self._build_delete_bgp_context(config.asn)
        return self._render_template(frr_tmpl.TmplName.DEL_BGP_ROUTER, context)


class FrrVtyshExecutor:

    @property
    def _vtysh_base_cmd(self) -> list[str]:
        return ['vtysh']

    def _execute_vtysh(self, vtysh_args: list[str]) -> str:
        """Execute any vtysh command args and return stdout."""
        cmd = self._vtysh_base_cmd + vtysh_args
        return typing.cast(str, linux_utils.execute(cmd, run_as_root=True))

    def execute_cli_cmd(self, cmd_string: str) -> str:
        """Execute single vtysh CLI command (e.g. show)."""
        try:
            return self._execute_vtysh(['-c', cmd_string])
        except exceptions.ProcessExecutionError as err:
            raise frr_exceptions.FrrApplyError(
                "Failed to execute vtysh command:\n%s" % cmd_string,
                step='execute_cli',
                cause=err,
            ) from err

    def execute_cmds(self, cmd_string: str) -> None:
        with tempfile.NamedTemporaryFile(
                mode='w+', delete=True, suffix=".cmd") as f:
            f.write(cmd_string)
            f.flush()
            temp_path = f.name
            try:
                self._execute_vtysh(['--dryrun', '-f', temp_path])
            except exceptions.ProcessExecutionError as err:
                raise frr_exceptions.FrrDryrunError(
                    "FRR syntatic validity failed for "
                    "command:\n%s" % cmd_string,
                    step='dryrun',
                    cause=err,
                ) from err
            try:
                self._execute_vtysh(['-f', temp_path])
            except exceptions.ProcessExecutionError as err:
                raise frr_exceptions.FrrApplyError(
                    "Failed to apply FRR configuration:\n%s\n"
                    "via vtysh" % cmd_string,
                    step='apply',
                    cause=err,
                ) from err


class FrrVtyshDriver(interface.EVPNRouterDriver):

    def __init__(self, vrf_handler: interface.EVPNRouterVrfHandler,
                 peer_interface: str,
                 executor: FrrVtyshExecutor | None = None):
        self.vrf_handler = vrf_handler
        self.peer_interface = peer_interface
        self.cmd_builder = FrrCommandBuilder()
        self.executor = executor or FrrVtyshExecutor()

    def _bgp_router_exist(self, asn: int, bgp_router_id: str) -> bool:
        try:
            std_out = self.executor.execute_cli_cmd('show bgp summary json')
        except frr_exceptions.FrrApplyError as err:
            raise frr_exceptions.FrrApplyError(
                "Failed to fetch BGP summary for router existence check",
                step='check_bgp_exists',
                cause=err,
            ) from err

        try:
            data = jsonutils.loads(std_out)
        except ValueError as err:
            raise frr_exceptions.FrrApplyError(
                "Failed to parse BGP summary JSON for router existence check",
                step='check_bgp_exists',
                cause=err,
            ) from err

        if not isinstance(data, dict):
            raise frr_exceptions.FrrApplyError(
                "Unexpected BGP summary format for router existence check",
                step='check_bgp_exists',
            )
        l2vpn_evpn = data.get('l2VpnEvpn')
        if not isinstance(l2vpn_evpn, dict):
            return False

        existing_router_id = l2vpn_evpn.get('routerId')
        existing_asn = l2vpn_evpn.get('as')
        if not isinstance(existing_asn, (int, str)):
            raise frr_exceptions.FrrApplyError(
                "Unexpected BGP ASN type while checking router existence",
                step='check_bgp_exists',
            )
        try:
            existing_asn = int(existing_asn)
        except (TypeError, ValueError):
            raise frr_exceptions.FrrApplyError(
                "Unable to parse BGP ASN while checking router existence",
                step='check_bgp_exists',
            )
        return (
            existing_router_id == bgp_router_id and
            existing_asn == asn
        )

    def _create_bgp_router(self, config: interface.EVPNRouterConfig):
        if self._bgp_router_exist(config.asn, config.bgp_router_id):
            return
        add_bgp_router_cmd = self.cmd_builder.add_bgp_router_cmds(
            config,
            self.peer_interface)
        self.executor.execute_cmds(add_bgp_router_cmd)

    def create_evpn_router(self, config: interface.EVPNRouterConfig) -> None:
        LOG.debug("Creating EVPN router: %s", config)
        self.vrf_handler.ensure_vrf_exists(config.vrf_name)
        self._create_bgp_router(config)
        add_evpn_router_cmd = self.cmd_builder.add_evpn_router_cmds(config)
        self.executor.execute_cmds(add_evpn_router_cmd)

    def delete_evpn_router(self, config: interface.EVPNRouterConfig) -> None:
        LOG.debug("Deleting EVPN router: %s", config)
        self.vrf_handler.ensure_vrf_deleted(config.vrf_name)
        self.executor.execute_cmds(
            self.cmd_builder.delete_evpn_router_cmds(config))
