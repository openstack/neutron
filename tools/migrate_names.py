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

from collections import namedtuple
import contextlib
import os
import re
import sys

import click

import download_gerrit_change

root_dir = os.path.dirname(os.path.realpath(__file__))
Migration = namedtuple('Migration', 'from_repo to_repo')


def read_mapfile(mapfile):
    dirmaps = []
    with open(mapfile, 'r') as mapfile_fd:
        for line_buffer in mapfile_fd.readlines():
            # ignore empty lines and anything after #
            line_match = re.search("^([^#]+)", line_buffer.strip())
            if not line_match:
                continue
            line_buffer = line_match.group(1)
            # look for tuple of 2 elements
            line_match = re.search(r"^([^\s]+)\s+(.+)", line_buffer.strip())
            if not line_match:
                continue
            ovn_match, neutron_match = line_match.group(1), line_match.group(2)
            dirmaps.append(Migration(neutron_match, ovn_match))
    return dirmaps


def parse_input(dirmaps, patch_content, output_fd):
    for line_buffer in patch_content.splitlines():
        # locate markers in patch file for filenames and see if they need
        # to me renamed based on dirmaps
        filename_replaced = False
        line_match = re.search(r"^\s*---\s+([^\s@]+)[\s@]*", line_buffer)
        if not line_match:
            line_match = re.search(r"^\s*\+\+\+\s+([^\s@]+)[\s@]*",
                                   line_buffer)
        if line_match:
            for old, new in dirmaps:
                new_line_buffer = line_buffer.replace(old, new)
                if new_line_buffer != line_buffer:
                    filename_replaced = True
                    output_fd.write("{}\n".format(new_line_buffer))
                    break
        if not filename_replaced:
            output_fd.write("{}\n".format(line_buffer))


@contextlib.contextmanager
def open_output(filename=None):
    if filename and filename != '-':
        fh = open(filename, 'w')
    else:
        fh = sys.stdout
    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()


@click.command()
@click.option('-i', '--input_patch', prompt='Input patch file or gerrit id',
              help='input_patch patch file or gerrit change')
@click.option('-o', '--output_patch', default='-',
              help='Output patch file. Default: stdout')
@click.option('-m', '--mapfile',
              default=os.path.join(root_dir, 'migrate_names.txt'),
              show_default=True,
              type=click.Path(),
              help='Data file that specifies mapping to be applied to input')
@click.option('--reverse/--no-reverse',
              default=False,
              help='Map filenames from networking-ovn to Neutron repo')
def cli(input_patch, output_patch, mapfile, reverse):
    dirmaps = read_mapfile(mapfile)
    if reverse:
        dirmaps = [Migration(two, one) for one, two in dirmaps]
    if os.path.isfile(input_patch):
        with open(input_patch, 'r') as input_fd:
            patch_content = ''.join(input_fd.readlines())
    else:
        patch_content = download_gerrit_change.fetch(input_patch)

    with open_output(output_patch) as output_fd:
        parse_input(dirmaps, patch_content, output_fd)


if __name__ == '__main__':
    cli()
