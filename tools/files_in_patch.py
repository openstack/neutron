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

import re
import sys

file_names = set()


def parse_input(input_file):
    global file_names

    while True:
        line_buffer = input_file.readline()
        if not line_buffer:
            break
        line_match = re.search(r"^\s*---\s+([^\s@]+)[\s@]+", line_buffer)
        if not line_match:
            line_match = re.search(r"^\s*\+\+\+\s+([^\s@]+)[\s@]+",
                                   line_buffer)
        if line_match:
            curr_file_name = line_match.group(1)

            # trim off 'a/' and 'b/' that you will normally see in git output
            #
            if len(curr_file_name) > 2 and curr_file_name[1] == '/' and (
                    curr_file_name[0] == 'a' or curr_file_name[0] == 'b'):
                curr_file_name = curr_file_name[2:]

            file_names.add(curr_file_name)


def prune_unwanted_names():
    global file_names

    unwanted_names = {'/dev/null'}

    for curr_file_name in file_names:
        # ignore files that end in '.orig' as long as non-.orig exists
        line_match = re.search(r"^(.+)\.[oO][Rr][iI][gG]$", curr_file_name)
        if line_match and line_match.group(1) in file_names:
            unwanted_names.add(curr_file_name)
            continue

    file_names -= unwanted_names


def print_file_names():
    for name in sorted(file_names):
        print(name)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        parse_input(sys.stdin)
    else:
        for curr_input_name in sys.argv[1:]:
            try:
                with open(curr_input_name) as curr_input_file:
                    parse_input(curr_input_file)
            except OSError as e_str:
                sys.stderr.write(
                    f"Cannot open {curr_input_name}: {e_str}\n")
                sys.exit(255)

    prune_unwanted_names()
    print_file_names()
