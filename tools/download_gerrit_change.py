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

import click
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


@click.command()
@click.argument('gerrit_change', nargs=1, type=click.INT)
@click.option('-o', '--output_patch',
              help='Output patch file  [default: stdout]')
@click.option('-g', '--gerrit_url',
              default=GERRIT_URL,
              show_default=True,
              help='The url to Gerrit server')
@click.option('-t', '--timeout',
              default=TIMEOUT,
              show_default=True,
              type=click.INT,
              help='Timeout, in seconds')
def cli(gerrit_change, output_patch, gerrit_url, timeout):
    message = fetch(gerrit_change, output_patch, gerrit_url, timeout)
    if not output_patch or output_patch == '-':
        print(message)


if __name__ == '__main__':
    cli()
