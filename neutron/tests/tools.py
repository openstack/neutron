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

import datetime
import os
import platform
import random
import time
import warnings

import fixtures
import mock
import netaddr
from neutron_lib import constants
from neutron_lib.utils import helpers
from neutron_lib.utils import net
from oslo_utils import netutils
from oslo_utils import timeutils
import unittest2

from neutron.common import constants as n_const
from neutron.services.logapi.common import constants as log_const


class WarningsFixture(fixtures.Fixture):
    """Filters out warnings during test runs."""

    warning_types = (
        DeprecationWarning, PendingDeprecationWarning, ImportWarning
    )

    def _setUp(self):
        self.addCleanup(warnings.resetwarnings)
        for wtype in self.warning_types:
            warnings.filterwarnings(
                "once", category=wtype, module='^neutron\\.')


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
    raise unittest2.TestCase.failureException(msg)


class UnorderedList(list):
    """A list that is equals to any permutation of itself."""

    def __eq__(self, other):
        if not isinstance(other, list):
            return False
        return (sorted(self, key=helpers.safe_sort_key) ==
                sorted(other, key=helpers.safe_sort_key))

    def __neq__(self, other):
        return not self == other


def get_random_string_list(i=3, n=5):
    return [helpers.get_random_string(n) for _ in range(0, i)]


def get_random_boolean():
    return bool(random.getrandbits(1))


def get_random_datetime(start_time=None,
                        end_time=None):
    start_time = start_time or timeutils.utcnow()
    end_time = end_time or (start_time + datetime.timedelta(days=1))
    # calculate the seconds difference between start and end time
    delta_seconds_difference = int(timeutils.delta_seconds(start_time,
                                                           end_time))
    # get a random time_delta_seconds between 0 and
    # delta_seconds_difference
    random_time_delta = random.randint(0, delta_seconds_difference)
    # generate a random datetime between start and end time
    return start_time + datetime.timedelta(seconds=random_time_delta)


def get_random_integer(range_begin=0, range_end=1000):
    return random.randint(range_begin, range_end)


def get_random_prefixlen(version=4):
    maxlen = constants.IPv4_BITS
    if version == 6:
        maxlen = constants.IPv6_BITS
    return random.randint(0, maxlen)


def get_random_port(start=n_const.PORT_RANGE_MIN):
    return random.randint(start, n_const.PORT_RANGE_MAX)


def get_random_vlan():
    return random.randint(constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG)


def get_random_ip_version():
    return random.choice(n_const.IP_ALLOWED_VERSIONS)


def get_random_cidr(version=4):
    if version == 4:
        return '10.%d.%d.0/%d' % (random.randint(3, 254),
                                  random.randint(3, 254),
                                  24)
    return '2001:db8:%x::/%d' % (random.getrandbits(16), 64)


def get_random_EUI():
    return netaddr.EUI(
        net.get_random_mac(['fe', '16', '3e', '00', '00', '00'])
    )


def get_random_ip_network(version=4):
    return netaddr.IPNetwork(get_random_cidr(version=version))


def get_random_ip_address(version=4):
    if version == 4:
        ip_string = '10.%d.%d.%d' % (random.randint(3, 254),
                                     random.randint(3, 254),
                                     random.randint(3, 254))
        return netaddr.IPAddress(ip_string)
    else:
        ip = netutils.get_ipv6_addr_by_EUI64(
            '2001:db8::/64',
            net.get_random_mac(['fe', '16', '3e', '00', '00', '00'])
        )
        return ip


def get_random_router_status():
    return random.choice(n_const.VALID_ROUTER_STATUS)


def get_random_floatingip_status():
    return random.choice(n_const.VALID_FLOATINGIP_STATUS)


def get_random_flow_direction():
    return random.choice(constants.VALID_DIRECTIONS)


def get_random_ha_states():
    return random.choice(n_const.VALID_HA_STATES)


def get_random_ether_type():
    return random.choice(n_const.VALID_ETHERTYPES)


def get_random_ipam_status():
    return random.choice(n_const.VALID_IPAM_ALLOCATION_STATUSES)


def get_random_ip_protocol():
    return random.choice(list(constants.IP_PROTOCOL_MAP.keys()))


def get_random_port_binding_statuses():
    return random.choice(n_const.PORT_BINDING_STATUSES)


def is_bsd():
    """Return True on BSD-based systems."""

    system = platform.system()
    if system == 'Darwin':
        return True
    if 'bsd' in system.lower():
        return True
    return False


def reset_random_seed():
    # reset random seed to make sure other processes extracting values from RNG
    # don't get the same results (useful especially when you then use the
    # random values to allocate system resources from global pool, like ports
    # to listen). Use both current time and pid to make sure no tests started
    # at the same time get the same values from RNG
    seed = time.time() + os.getpid()
    random.seed(seed)


def get_random_ipv6_mode():
    return random.choice(constants.IPV6_MODES)


def get_random_security_event():
    return random.choice(log_const.LOG_EVENTS)
