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

import sys

from neutron.plugins.vmware.shell import commands as cmd
from neutronclient import shell


class NsxManage(shell.NeutronShell):

    def __init__(self, api_version):
        super(NsxManage, self).__init__(api_version)
        self.command_manager.add_command('net-migrate', cmd.NetworkMigrate)
        self.command_manager.add_command('net-report', cmd.NetworkReport)

    def build_option_parser(self, description, version):
        parser = super(NsxManage, self).build_option_parser(
            description, version)
        return parser

    def initialize_app(self, argv):
        super(NsxManage, self).initialize_app(argv)
        self.client = self.client_manager.neutron


def main():
    return NsxManage(shell.NEUTRON_API_VERSION).run(sys.argv[1:])
