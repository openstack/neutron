# Copyright 2014 VMware, Inc.
#
# All Rights Reserved
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
#

from neutronclient.neutron import v2_0 as client

LSN_PATH = '/lsns'


def print_report(write_func, report):
    write_func(_("\nService type = %s\n") % report['report']['type'])
    services = ','.join(report['report']['services'])
    ports = ','.join(report['report']['ports'])
    write_func(_("Service uuids = %s\n") % services)
    write_func(_("Port uuids = %s\n\n") % ports)


class NetworkReport(client.NeutronCommand):
    """Retrieve network migration report."""

    def get_parser(self, prog_name):
        parser = super(NetworkReport, self).get_parser(prog_name)
        parser.add_argument('network', metavar='network',
                            help=_('ID or name of network to run report on'))
        return parser

    def run(self, parsed_args):
        net = parsed_args.network
        net_id = client.find_resourceid_by_name_or_id(self.app.client,
                                                      'network', net)
        res = self.app.client.get("%s/%s" % (LSN_PATH, net_id))
        if res:
            self.app.stdout.write(_('Migration report is:\n'))
            print_report(self.app.stdout.write, res['lsn'])


class NetworkMigrate(client.NeutronCommand):
    """Perform network migration."""

    def get_parser(self, prog_name):
        parser = super(NetworkMigrate, self).get_parser(prog_name)
        parser.add_argument('network', metavar='network',
                            help=_('ID or name of network to migrate'))
        return parser

    def run(self, parsed_args):
        net = parsed_args.network
        net_id = client.find_resourceid_by_name_or_id(self.app.client,
                                                      'network', net)
        body = {'network': net_id}
        res = self.app.client.post(LSN_PATH, body={'lsn': body})
        if res:
            self.app.stdout.write(_('Migration has been successful:\n'))
            print_report(self.app.stdout.write, res['lsn'])
