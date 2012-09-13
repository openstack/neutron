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

import logging

from cliff import lister

from quantumclient.common import utils
from quantumclient.quantum.v2_0 import QuantumCommand
from quantumclient.quantum.v2_0.port import _format_fixed_ips


class ProbeCommand(QuantumCommand):
    log = logging.getLogger(__name__ + '.ProbeCommand')

    def get_debug_agent(self):
        return self.app.debug_agent

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        self.app.stdout.write(_('Unimplemented commands') + '\n')


class CreateProbe(ProbeCommand):
    """Create probe port and interface, then plug it in."""

    log = logging.getLogger(__name__ + '.CreateProbe')

    def get_parser(self, prog_name):
        parser = super(CreateProbe, self).get_parser(prog_name)
        parser.add_argument(
            'id', metavar='network_id',
            help='ID of network to probe')
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        debug_agent = self.get_debug_agent()
        port = debug_agent.create_probe(parsed_args.id)
        self.app.stdout.write(_('Probe created : %s ') % port.id + '\n')


class DeleteProbe(ProbeCommand):
    """Delete probe - delete port then uplug """

    log = logging.getLogger(__name__ + '.DeleteProbe')

    def get_parser(self, prog_name):
        parser = super(DeleteProbe, self).get_parser(prog_name)
        parser.add_argument(
            'id', metavar='port_id',
            help='ID of probe port to delete')
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        debug_agent = self.get_debug_agent()
        debug_agent.delete_probe(parsed_args.id)
        self.app.stdout.write(_('Probe %s deleted') % parsed_args.id + '\n')


class ListProbe(QuantumCommand, lister.Lister):
    """ List probes """

    log = logging.getLogger(__name__ + '.ListProbe')
    _formatters = {'fixed_ips': _format_fixed_ips, }

    def get_debug_agent(self):
        return self.app.debug_agent

    def get_data(self, parsed_args):

        debug_agent = self.get_debug_agent()
        info = debug_agent.list_probes()
        columns = len(info) > 0 and sorted(info[0].keys()) or []
        return (columns, (utils.get_item_properties(
            s, columns, formatters=self._formatters, )
            for s in info), )


class ClearProbe(ProbeCommand):
    """Clear All probes """

    log = logging.getLogger(__name__ + '.ClearProbe')

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        debug_agent = self.get_debug_agent()
        debug_agent.clear_probe()
        self.app.stdout.write(_('All Probes deleted ') + '\n')


class ExecProbe(ProbeCommand):
    """Exec commands on the namespace of the probe
    """

    log = logging.getLogger(__name__ + '.ExecProbe')

    def get_parser(self, prog_name):
        parser = super(ExecProbe, self).get_parser(prog_name)
        parser.add_argument(
            'id', metavar='port_id',
            help='ID of probe port to execute command')
        parser.add_argument(
            'command', metavar='command',
            nargs='?',
            default=None,
            help='Command to execute')
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        debug_agent = self.get_debug_agent()
        result = debug_agent.exec_command(parsed_args.id, parsed_args.command)
        self.app.stdout.write(result + '\n')


class PingAll(ProbeCommand):
    """Ping all fixed_ip
    """

    log = logging.getLogger(__name__ + '.ExecProbe')

    def get_parser(self, prog_name):
        parser = super(PingAll, self).get_parser(prog_name)
        parser.add_argument(
            '--timeout', metavar='<timeout>',
            default=10,
            help='Ping timeout')
        parser.add_argument(
            '--id', metavar='network_id',
            default=None,
            help='ID of network')
        return parser

    def run(self, parsed_args):
        self.log.debug('run(%s)' % parsed_args)
        debug_agent = self.get_debug_agent()
        result = debug_agent.ping_all(parsed_args.id,
                                      timeout=parsed_args.timeout)
        self.app.stdout.write(result + '\n')
