# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012,  Nachi Ueno,  NTT MCL,  Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License,  Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,  software
#    distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND,  either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import sys

from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent.linux import interface
from neutron.common import legacy
from neutron.debug.debug_agent import NeutronDebugAgent
from neutron.openstack.common import importutils
from neutronclient.common import exceptions as exc
from neutronclient.shell import env, NeutronShell, NEUTRON_API_VERSION

COMMAND_V2 = {
    'probe-create': importutils.import_class(
        'neutron.debug.commands.CreateProbe'),
    'probe-delete': importutils.import_class(
        'neutron.debug.commands.DeleteProbe'),
    'probe-list': importutils.import_class(
        'neutron.debug.commands.ListProbe'),
    'probe-clear': importutils.import_class(
        'neutron.debug.commands.ClearProbe'),
    'probe-exec': importutils.import_class(
        'neutron.debug.commands.ExecProbe'),
    'ping-all': importutils.import_class(
        'neutron.debug.commands.PingAll'),
    #TODO(nati)  ping, netcat , nmap, bench
}
COMMANDS = {'2.0': COMMAND_V2}


class NeutronDebugShell(NeutronShell):
    def __init__(self, api_version):
        super(NeutronDebugShell, self).__init__(api_version)
        for k, v in COMMANDS[api_version].items():
            self.command_manager.add_command(k, v)

    def build_option_parser(self, description, version):
        parser = super(NeutronDebugShell, self).build_option_parser(
            description, version)
        default = (
            env('NEUTRON_TEST_CONFIG_FILE') or env('QUANTUM_TEST_CONFIG_FILE')
        )
        parser.add_argument(
            '--config-file',
            default=default,
            help=_('Config file for interface driver '
                   '(You may also use l3_agent.ini)'))
        return parser

    def initialize_app(self, argv):
        super(NeutronDebugShell, self).initialize_app(argv)
        if not self.options.config_file:
            raise exc.CommandError(
                _("You must provide a config file for bridge -"
                  " either --config-file or env[NEUTRON_TEST_CONFIG_FILE]"))
        client = self.client_manager.neutron
        cfg.CONF.register_opts(interface.OPTS)
        cfg.CONF.register_opts(NeutronDebugAgent.OPTS)
        config.register_interface_driver_opts_helper(cfg.CONF)
        config.register_use_namespaces_opts_helper(cfg.CONF)
        config.register_root_helper(cfg.CONF)
        cfg.CONF(['--config-file', self.options.config_file])
        config.setup_logging(cfg.CONF)
        legacy.modernize_quantum_config(cfg.CONF)
        driver = importutils.import_object(cfg.CONF.interface_driver, cfg.CONF)
        self.debug_agent = NeutronDebugAgent(cfg.CONF, client, driver)


def main(argv=None):
    return NeutronDebugShell(NEUTRON_API_VERSION).run(argv or sys.argv[1:])
