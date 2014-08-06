# Copyright (c) 2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re

import pep8

"""
Guidelines for writing new hacking checks

 - Use only for Neutron specific tests. OpenStack general tests
   should be submitted to the common 'hacking' module.
 - Pick numbers in the range N3xx. Find the current test with
   the highest allocated number and then pick the next value.
 - Keep the test method code in the source file ordered based
   on the N3xx value.
 - List the new rule in the top level HACKING.rst file
 - Add test cases for each new rule to
   neutron/tests/unit/test_hacking.py

"""

log_translation = re.compile(
    r"(.)*LOG\.(audit|error|info|warn|warning|critical|exception)\(\s*('|\")")
author_tag_re = (re.compile("^\s*#\s*@?(a|A)uthor"),
                 re.compile("^\.\.\s+moduleauthor::"))


def validate_log_translations(logical_line, physical_line, filename):
    # Translations are not required in the test directory
    if "neutron/tests" in filename:
        return
    if pep8.noqa(physical_line):
        return
    msg = "N320: Log messages require translations!"
    if log_translation.match(logical_line):
        yield (0, msg)


def use_jsonutils(logical_line, filename):
    msg = "N321: jsonutils.%(fun)s must be used instead of json.%(fun)s"

    # Some files in the tree are not meant to be run from inside Neutron
    # itself, so we should not complain about them not using jsonutils
    json_check_skipped_patterns = [
        "neutron/plugins/openvswitch/agent/xenapi/etc/xapi.d/plugins/netwrap",
    ]

    for pattern in json_check_skipped_patterns:
        if pattern in filename:
            return

    if "json." in logical_line:
        json_funcs = ['dumps(', 'dump(', 'loads(', 'load(']
        for f in json_funcs:
            pos = logical_line.find('json.%s' % f)
            if pos != -1:
                yield (pos, msg % {'fun': f[:-1]})


def no_author_tags(physical_line):
    for regex in author_tag_re:
        if regex.match(physical_line):
            physical_line = physical_line.lower()
            pos = physical_line.find('moduleauthor')
            if pos < 0:
                pos = physical_line.find('author')
            return pos, "N322: Don't use author tags"


def factory(register):
    register(validate_log_translations)
    register(use_jsonutils)
    register(no_author_tags)
