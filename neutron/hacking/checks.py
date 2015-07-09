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

# Guidelines for writing new hacking checks
#
#  - Use only for Neutron specific tests. OpenStack general tests
#    should be submitted to the common 'hacking' module.
#  - Pick numbers in the range N3xx. Find the current test with
#    the highest allocated number and then pick the next value.
#  - Keep the test method code in the source file ordered based
#    on the N3xx value.
#  - List the new rule in the top level HACKING.rst file
#  - Add test cases for each new rule to
#    neutron/tests/unit/hacking/test_checks.py

_all_log_levels = {
    'error': '_LE',
    'info': '_LI',
    'warn': '_LW',
    'warning': '_LW',
    'critical': '_LC',
    'exception': '_LE',
}
_all_hints = set(_all_log_levels.values())


def _regex_for_level(level, hint):
    return r".*LOG\.%(level)s\(\s*((%(wrong_hints)s)\(|'|\")" % {
        'level': level,
        'wrong_hints': '|'.join(_all_hints - set([hint])),
    }


log_translation_hint = re.compile(
    '|'.join('(?:%s)' % _regex_for_level(level, hint)
             for level, hint in _all_log_levels.iteritems()))

oslo_namespace_imports_dot = re.compile(r"import[\s]+oslo[.][^\s]+")
oslo_namespace_imports_from_dot = re.compile(r"from[\s]+oslo[.]")
oslo_namespace_imports_from_root = re.compile(r"from[\s]+oslo[\s]+import[\s]+")


def validate_log_translations(logical_line, physical_line, filename):
    # Translations are not required in the test directory
    if "neutron/tests" in filename:
        return
    if pep8.noqa(physical_line):
        return

    msg = "N320: Log messages require translation hints!"
    if log_translation_hint.match(logical_line):
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


def no_translate_debug_logs(logical_line, filename):
    """Check for 'LOG.debug(_(' and 'LOG.debug(_Lx('

    As per our translation policy,
    https://wiki.openstack.org/wiki/LoggingStandards#Log_Translation
    we shouldn't translate debug level logs.

    * This check assumes that 'LOG' is a logger.
    N319
    """
    for hint in _all_hints:
        if logical_line.startswith("LOG.debug(%s(" % hint):
            yield(0, "N319 Don't translate debug level logs")


def check_assert_called_once_with(logical_line, filename):
    # Try to detect unintended calls of nonexistent mock methods like:
    #    assert_called_once
    #    assertCalledOnceWith
    #    assert_has_called
    if 'neutron/tests/' in filename:
        if '.assert_called_once_with(' in logical_line:
            return
        uncased_line = logical_line.lower().replace('_', '')

        if '.assertcalledonce' in uncased_line:
            msg = ("N322: Possible use of no-op mock method. "
                   "please use assert_called_once_with.")
            yield (0, msg)

        if '.asserthascalled' in uncased_line:
            msg = ("N322: Possible use of no-op mock method. "
                   "please use assert_has_calls.")
            yield (0, msg)


def check_oslo_namespace_imports(logical_line):
    if re.match(oslo_namespace_imports_from_dot, logical_line):
        msg = ("N323: '%s' must be used instead of '%s'.") % (
               logical_line.replace('oslo.', 'oslo_'),
               logical_line)
        yield(0, msg)
    elif re.match(oslo_namespace_imports_from_root, logical_line):
        msg = ("N323: '%s' must be used instead of '%s'.") % (
               logical_line.replace('from oslo import ', 'import oslo_'),
               logical_line)
        yield(0, msg)
    elif re.match(oslo_namespace_imports_dot, logical_line):
        msg = ("N323: '%s' must be used instead of '%s'.") % (
               logical_line.replace('import', 'from').replace('.', ' import '),
               logical_line)
        yield(0, msg)


def factory(register):
    register(validate_log_translations)
    register(use_jsonutils)
    register(check_assert_called_once_with)
    register(no_translate_debug_logs)
    register(check_oslo_namespace_imports)
