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
import random
import unittest

import fixtures
import netaddr
from neutron_lib import constants
from neutron_lib.services.logapi import constants as log_const
from neutron_lib.utils import helpers
from neutron_lib.utils import net
from oslo_utils import netutils
from oslo_utils import timeutils


LAST_RANDOM_PORT_RANGE_GENERATED = 1


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


def _make_magic_method(method_mock):
    # NOTE(yamahata): new environment needs to be created to keep actual
    # method_mock for each callables.
    def __call__(*args, **kwargs):
        value_mock = method_mock._orig___call__(*args, **kwargs)
        value_mock.__json__ = lambda: {}
        return value_mock

    def _get_child_mock(**kwargs):
        value_mock = method_mock._orig__get_child_mock(**kwargs)
        value_mock.__json__ = lambda: {}
        return value_mock

    return __call__, _get_child_mock


def make_mock_plugin_json_encodable(plugin_instance_mock):
    # NOTE(yamahata): Make return value of plugin method json encodable
    # e.g. the return value of plugin_instance.create_network() needs
    # to be json encodable
    # plugin instance      -> method    -> return value
    # Mock                    MagicMock    Mock
    # plugin_instance_mock    method_mock  value_mock
    #
    # From v1.3 of pecan, pecan.jsonify uses json.Encoder unconditionally.
    # pecan v1.2 uses simplejson.Encoder which accidentally encodes
    # Mock as {} due to check of '_asdict' attributes.
    # pecan.jsonify uses __json__ magic method for encoding when
    # it's defined, so add __json__ method to return {}
    for method_mock in plugin_instance_mock._mock_children.values():
        if not callable(method_mock):
            continue

        method_mock._orig___call__ = method_mock.__call__
        method_mock._orig__get_child_mock = method_mock._get_child_mock
        __call__, _get_child_mock = _make_magic_method(method_mock)
        method_mock.__call__ = __call__
        method_mock._get_child_mock = _get_child_mock


def fail(msg=None):
    """Fail immediately, with the given message.

    This method is equivalent to TestCase.fail without requiring a
    testcase instance (usefully for reducing coupling).
    """
    raise unittest.TestCase.failureException(msg)


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


def get_random_port(start=constants.PORT_RANGE_MIN):
    global LAST_RANDOM_PORT_RANGE_GENERATED
    LAST_RANDOM_PORT_RANGE_GENERATED = random.randint(
        start, constants.PORT_RANGE_MAX)
    return LAST_RANDOM_PORT_RANGE_GENERATED


def get_random_vlan():
    return random.randint(constants.MIN_VLAN_TAG, constants.MAX_VLAN_TAG)


def get_random_ip_version():
    return random.choice(constants.IP_ALLOWED_VERSIONS)


def get_random_ip_address(version=4):
    if version == 4:
        ip_string = '10.%d.%d.%d' % (random.randint(3, 254),
                                     random.randint(3, 254),
                                     random.randint(3, 254))
        return netaddr.IPAddress(ip_string)
    return netutils.get_ipv6_addr_by_EUI64(
        '2001:db8::/64',
        net.get_random_mac(['fe', '16', '3e', '00', '00', '00']))


def get_random_router_status():
    return random.choice(constants.VALID_ROUTER_STATUS)


def get_random_floatingip_status():
    return random.choice(constants.VALID_FLOATINGIP_STATUS)


def get_random_flow_direction():
    return random.choice(constants.VALID_DIRECTIONS)


def get_random_flow_direction_or_any():
    return random.choice(constants.VALID_DIRECTIONS_AND_ANY)


def get_random_ha_states():
    return random.choice(constants.VALID_HA_STATES)


def get_random_ether_type():
    return random.choice(constants.VALID_ETHERTYPES)


def get_random_ipam_status():
    return random.choice(constants.VALID_IPAM_ALLOCATION_STATUSES)


def get_random_ip_protocol():
    return random.choice(list(constants.IP_PROTOCOL_MAP.keys()))


def get_random_port_binding_statuses():
    return random.choice(constants.PORT_BINDING_STATUSES)


def get_random_network_segment_range_network_type():
    return random.choice([constants.TYPE_VLAN,
                          constants.TYPE_VXLAN,
                          constants.TYPE_GRE,
                          constants.TYPE_GENEVE])


def get_random_ipv6_mode():
    return random.choice(constants.IPV6_MODES)


def get_random_security_event():
    return random.choice(log_const.LOG_EVENTS)


def get_random_port_numa_affinity_policy():
    return random.choice(constants.PORT_NUMA_POLICIES)


def get_random_port_hardware_offload_type():
    return random.choice(constants.VALID_HWOL_TYPES)
