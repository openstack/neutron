#!/usr/bin/env python
#
# Copyright (c) 2013 Brocade Communications Systems, Inc.
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


"""Brocade NOS Driver CLI."""
from __future__ import print_function

import argparse

from oslo_log import log as logging

from neutron.plugins.brocade.nos import nosdriver as nos

LOG = logging.getLogger(__name__)


class NOSCli(object):

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.driver = nos.NOSdriver()

    def execute(self, cmd):
        numargs = len(args.otherargs)

        if args.cmd == 'create' and numargs == 1:
            self._create(args.otherargs[0])
        elif args.cmd == 'delete' and numargs == 1:
            self._delete(args.otherargs[0])
        elif args.cmd == 'associate' and numargs == 2:
            self._associate(args.otherargs[0], args.otherargs[1])
        elif args.cmd == 'dissociate' and numargs == 2:
            self._dissociate(args.otherargs[0], args.otherargs[1])
        else:
            print(usage_desc)
            exit(0)

    def _create(self, net_id):
        self.driver.create_network(self.host, self.username, self.password,
                                   net_id)

    def _delete(self, net_id):
        self.driver.delete_network(self.host, self.username, self.password,
                                   net_id)

    def _associate(self, net_id, mac):
        self.driver.associate_mac_to_network(
            self.host, self.username, self.password, net_id, mac)

    def _dissociate(self, net_id, mac):
        self.driver.dissociate_mac_from_network(
            self.host, self.username, self.password, net_id, mac)


usage_desc = """
Command descriptions:

    create <id>
    delete <id>
    associate <id> <mac>
    dissociate <id> <mac>
"""

parser = argparse.ArgumentParser(description='process args',
                                 usage=usage_desc, epilog='foo bar help')
parser.add_argument('--ip', default='localhost')
parser.add_argument('--username', default='admin')
parser.add_argument('--password', default='password')
parser.add_argument('cmd')
parser.add_argument('otherargs', nargs='*')
args = parser.parse_args()

noscli = NOSCli(args.ip, args.username, args.password)
noscli.execute(args.cmd)
