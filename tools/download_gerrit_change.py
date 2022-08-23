#!/usr/bin/env python3

# Copyright 2020 Red Hat, Inc.
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

import base64
import sys

from cliff import app
from cliff import command
from cliff import commandmanager
import requests

GERRIT_URL = 'https://review.opendev.org/'
TIMEOUT = 10


def fetch(change, output_patch=None, url=GERRIT_URL, timeout=TIMEOUT):
    params = {'download': None}
    r = requests.get(
        url='{}/changes/{}/revisions/current/patch'.format(url, change),
        params=params,
        timeout=timeout)
    r.raise_for_status()
    message_bytes = base64.b64decode(r.text)
    if output_patch and output_patch != '-':
        with open(output_patch, 'wb') as output_fd:
            output_fd.write(message_bytes)
    return str(message_bytes, 'utf-8')


class Config(command.Command):
    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument('gerrit_change', help='Gerrit change')
        parser.add_argument(
            '-o', '--output_patch', default='-',
            help='Output patch file  [default: stdout]')
        parser.add_argument(
            '-g', '--gerrit_url', default=GERRIT_URL,
            help='The url to Gerrit server')
        parser.add_argument(
            '-t', '--timeout', default=TIMEOUT,
            help='Verify server certificate (default)',
        )
        return parser

    def take_action(self, parsed_args):
        pass


def cli():
    my_app = app.App(
        description='Download a gerrit change',
        version='1.0.0',
        command_manager=commandmanager.CommandManager('mycli.cli'))
    cmd = Config(my_app, None)
    parser = cmd.get_parser('migrate_names')
    parsed_args = parser.parse_args(sys.argv[1:])
    message = fetch(parsed_args.gerrit_change, parsed_args.output_patch,
                    parsed_args.gerrit_url, parsed_args.timeout)
    if not parsed_args.output_patch or parsed_args.output_patch == '-':
        print(message)


if __name__ == '__main__':
    cli()
