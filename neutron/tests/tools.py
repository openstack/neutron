# Copyright (c) 2013 NEC Corporation
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

import platform
import random
import string
import warnings

import fixtures
import mock
import six

from neutron.api.v2 import attributes


class AttributeMapMemento(fixtures.Fixture):
    """Create a copy of the resource attribute map so it can be restored during
    test cleanup.

    There are a few reasons why this is not included in a class derived
    from BaseTestCase:

        - Test cases may need more control about when the backup is
        made, especially if they are not direct descendants of
        BaseTestCase.

        - Inheritance is a bit of overkill for this facility and it's a
        stretch to rationalize the "is a" criteria.
    """

    def _setUp(self):
        # Shallow copy is not a proper choice for keeping a backup copy as
        # the RESOURCE_ATTRIBUTE_MAP map is modified in place through the
        # 0th level keys. Ideally deepcopy() would be used but this seems
        # to result in test failures. A compromise is to copy one level
        # deeper than a shallow copy.
        self.contents_backup = {}
        for res, attrs in six.iteritems(attributes.RESOURCE_ATTRIBUTE_MAP):
            self.contents_backup[res] = attrs.copy()
        self.addCleanup(self.restore)

    def restore(self):
        attributes.RESOURCE_ATTRIBUTE_MAP = self.contents_backup


class WarningsFixture(fixtures.Fixture):
    """Filters out warnings during test runs."""

    warning_types = (
        DeprecationWarning, PendingDeprecationWarning, ImportWarning
    )

    def _setUp(self):
        self.addCleanup(warnings.resetwarnings)
        for wtype in self.warning_types:
            warnings.filterwarnings(
                "always", category=wtype, module='^neutron\\.')


class OpenFixture(fixtures.Fixture):
    """Mock access to a specific file while preserving open for others."""

    def __init__(self, filepath, contents=''):
        self.path = filepath
        self.contents = contents

    def _setUp(self):
        self.mock_open = mock.mock_open(read_data=self.contents)
        self._orig_open = open

        def replacement_open(name, *args, **kwargs):
            if name == self.path:
                return self.mock_open(name, *args, **kwargs)
            return self._orig_open(name, *args, **kwargs)

        self._patch = mock.patch('six.moves.builtins.open',
                                 new=replacement_open)
        self._patch.start()
        self.addCleanup(self._patch.stop)


class SafeCleanupFixture(fixtures.Fixture):
    """Catch errors in daughter fixture cleanup."""

    def __init__(self, fixture):
        self.fixture = fixture

    def _setUp(self):

        def cleanUp():
            try:
                self.fixture.cleanUp()
            except Exception:
                pass

        self.fixture.setUp()
        self.addCleanup(cleanUp)


import unittest

from neutron.common import utils


def setup_mock_calls(mocked_call, expected_calls_and_values):
    """A convenient method to setup a sequence of mock calls.

    expected_calls_and_values is a list of (expected_call, return_value):

        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, '--', "--may-exist", "add-port",
                        self.BR_NAME, pname]),
             None),
            (mock.call(["ovs-vsctl", self.TO, "set", "Interface",
                        pname, "type=gre"]),
             None),
            ....
        ]

    * expected_call should be mock.call(expected_arg, ....)
    * return_value is passed to side_effect of a mocked call.
      A return value or an exception can be specified.
    """
    return_values = [call[1] for call in expected_calls_and_values]
    mocked_call.side_effect = return_values


def verify_mock_calls(mocked_call, expected_calls_and_values,
                      any_order=False):
    """A convenient method to setup a sequence of mock calls.

    expected_calls_and_values is a list of (expected_call, return_value):

        expected_calls_and_values = [
            (mock.call(["ovs-vsctl", self.TO, '--', "--may-exist", "add-port",
                        self.BR_NAME, pname]),
             None),
            (mock.call(["ovs-vsctl", self.TO, "set", "Interface",
                        pname, "type=gre"]),
             None),
            ....
        ]

    * expected_call should be mock.call(expected_arg, ....)
    * return_value is passed to side_effect of a mocked call.
      A return value or an exception can be specified.
    """
    expected_calls = [call[0] for call in expected_calls_and_values]
    mocked_call.assert_has_calls(expected_calls, any_order=any_order)


def fail(msg=None):
    """Fail immediately, with the given message.

    This method is equivalent to TestCase.fail without requiring a
    testcase instance (usefully for reducing coupling).
    """
    raise unittest.TestCase.failureException(msg)


class UnorderedList(list):
    """A list that is equals to any permutation of itself."""

    def __eq__(self, other):
        if not isinstance(other, list):
            return False
        return (sorted(self, key=utils.safe_sort_key) ==
                sorted(other, key=utils.safe_sort_key))

    def __neq__(self, other):
        return not self == other


def get_random_string(n=10):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))


def get_random_boolean():
    return bool(random.getrandbits(1))


def get_random_integer(range_begin=0, range_end=1000):
    return random.randint(range_begin, range_end)


def is_bsd():
    """Return True on BSD-based systems."""

    system = platform.system()
    if system == 'Darwin':
        return True
    if 'bsd' in system.lower():
        return True
    return False
