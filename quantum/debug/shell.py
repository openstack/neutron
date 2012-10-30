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

import itertools
import sys

from quantum.agent.common import config
from quantum.agent.linux import interface
import quantum.debug.commands
from quantum.debug.debug_agent import QuantumDebugAgent
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantumclient.common import exceptions as exc
from quantumclient.common import utils
from quantumclient.shell import env, QuantumShell, QUANTUM_API_VERSION

COMMAND_V2 = {
    'probe-create': utils.import_class(
        'quantum.debug.commands.CreateProbe'),
    'probe-delete': utils.import_class(
        'quantum.debug.commands.DeleteProbe'),
    'probe-list': utils.import_class(
        'quantum.debug.commands.ListProbe'),
    'probe-clear': utils.import_class(
        'quantum.debug.commands.ClearProbe'),
    'probe-exec': utils.import_class(
        'quantum.debug.commands.ExecProbe'),
    'ping-all': utils.import_class(
        'quantum.debug.commands.PingAll'),
#TODO(nati)  ping, netcat , nmap, bench
}
COMMANDS = {'2.0': COMMAND_V2}


class QuantumDebugShell(QuantumShell):
    def __init__(self, api_version):
        super(QuantumDebugShell, self).__init__(api_version)
        for k, v in COMMANDS[api_version].items():
            self.command_manager.add_command(k, v)

    def build_option_parser(self, description, version):
        parser = super(QuantumDebugShell, self).build_option_parser(
            description, version)
        parser.add_argument(
            '--config-file',
            default=env('TEST_CONFIG_FILE'),
            help='Config file for interface driver '
                 '(You may also use l3_agent.ini)')
        return parser

    def initialize_app(self, argv):
        super(QuantumDebugShell, self).initialize_app(argv)
        if not self.options.config_file:
            raise exc.CommandError(
                "You must provide a config file for bridge -"
                " either --config-file or env[TEST_CONFIG_FILE]")
        client = self.client_manager.quantum
        cfg.CONF.register_opts(interface.OPTS)
        cfg.CONF.register_opts(QuantumDebugAgent.OPTS)
        cfg.CONF(['--config-file', self.options.config_file])
        config.setup_logging(cfg.CONF)
        driver = importutils.import_object(cfg.CONF.interface_driver, cfg.CONF)
        self.debug_agent = QuantumDebugAgent(cfg.CONF, client, driver)


def main(argv=None):
    return QuantumDebugShell(QUANTUM_API_VERSION).run(argv or sys.argv[1:])

if __name__ == "__main__":
    sys.exit(main())
