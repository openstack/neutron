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

from cliff import lister
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as client
from neutronclient.neutron.v2_0 import port

from neutron._i18n import _


class ProbeCommand(client.NeutronCommand):

    def get_debug_agent(self):
        return self.app.debug_agent


class CreateProbe(ProbeCommand):
    """Create probe port and interface, then plug it in."""

    def get_parser(self, prog_name):
        parser = super(CreateProbe, self).get_parser(prog_name)
        parser.add_argument(
            'id', metavar='network_id',
            help=_('ID of network to probe'))
        parser.add_argument(
            '--device-owner',
            default='network', choices=['network', 'compute'],
            help=_('Owner type of the device: network/compute'))
        return parser

    def take_action(self, parsed_args):
        debug_agent = self.get_debug_agent()
        probe_port = debug_agent.create_probe(parsed_args.id,
                                              parsed_args.device_owner)
        self.log.info(_('Probe created : %s '), probe_port.id)


class DeleteProbe(ProbeCommand):
    """Delete probe - delete port then uplug."""

    def get_parser(self, prog_name):
        parser = super(DeleteProbe, self).get_parser(prog_name)
        parser.add_argument(
            'id', metavar='port_id',
            help=_('ID of probe port to delete'))
        return parser

    def take_action(self, parsed_args):
        debug_agent = self.get_debug_agent()
        debug_agent.delete_probe(parsed_args.id)
        self.log.info(_('Probe %s deleted'), parsed_args.id)


class ListProbe(ProbeCommand, lister.Lister):
    """List probes."""

    _formatters = {'fixed_ips': port._format_fixed_ips, }

    def take_action(self, parsed_args):
        debug_agent = self.get_debug_agent()
        info = debug_agent.list_probes()
        columns = sorted(info[0].keys()) if info else []
        return (columns, (utils.get_item_properties(
            s, columns, formatters=self._formatters, )
                          for s in info), )


class ClearProbe(ProbeCommand):
    """Clear All probes."""

    def take_action(self, parsed_args):
        debug_agent = self.get_debug_agent()
        cleared_probes_count = debug_agent.clear_probes()
        self.log.info('%d probe(s) deleted', cleared_probes_count)


class ExecProbe(ProbeCommand):
    """Exec commands on the namespace of the probe."""

    def get_parser(self, prog_name):
        parser = super(ExecProbe, self).get_parser(prog_name)
        parser.add_argument(
            'id', metavar='port_id',
            help=_('ID of probe port to execute command'))
        parser.add_argument(
            'command', metavar='command',
            nargs='?',
            default=None,
            help=_('Command to execute'))
        return parser

    def take_action(self, parsed_args):
        debug_agent = self.get_debug_agent()
        result = debug_agent.exec_command(parsed_args.id, parsed_args.command)
        self.app.stdout.write(result + '\n')


class PingAll(ProbeCommand):
    """Ping all fixed_ip."""

    def get_parser(self, prog_name):
        parser = super(PingAll, self).get_parser(prog_name)
        parser.add_argument(
            '--timeout', metavar='<timeout>',
            default=10,
            help=_('Ping timeout'))
        parser.add_argument(
            '--id', metavar='network_id',
            default=None,
            help=_('ID of network'))
        return parser

    def take_action(self, parsed_args):
        debug_agent = self.get_debug_agent()
        result = debug_agent.ping_all(parsed_args.id,
                                      timeout=parsed_args.timeout)
        self.app.stdout.write(result + '\n')
