# Copyright 2016 OVH SAS
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

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.common import exceptions


SI_BASE = 1000
IEC_BASE = 1024

LATENCY_UNIT = "ms"
BW_LIMIT_UNIT = "kbit"  # kilobits per second in tc's notation
BURST_UNIT = "kbit"  # kilobits in tc's notation

# Those are RATES (bits per second) and SIZE (bytes) unit names from tc manual
UNITS = {
    "k": 1,
    "m": 2,
    "g": 3,
    "t": 4
}


class InvalidKernelHzValue(exceptions.NeutronException):
    message = _("Kernel HZ value %(value)s is not valid. This value must be "
                "greater than 0.")


class InvalidUnit(exceptions.NeutronException):
    message = _("Unit name '%(unit)s' is not valid.")


def convert_to_kilobits(value, base):
    value = value.lower()
    if "bit" in value:
        input_in_bits = True
        value = value.replace("bit", "")
    else:
        input_in_bits = False
        value = value.replace("b", "")
    # if it is now bare number then it is in bits, so we return it simply
    if value.isdigit():
        value = int(value)
        if input_in_bits:
            return bits_to_kilobits(value, base)
        else:
            bits_value = bytes_to_bits(value)
            return bits_to_kilobits(bits_value, base)
    unit = value[-1:]
    if unit not in UNITS.keys():
        raise InvalidUnit(unit=unit)
    val = int(value[:-1])
    if input_in_bits:
        bits_value = val * (base ** UNITS[unit])
    else:
        bits_value = bytes_to_bits(val * (base ** UNITS[unit]))
    return bits_to_kilobits(bits_value, base)


def bytes_to_bits(value):
    return value * 8


def bits_to_kilobits(value, base):
    #NOTE(slaweq): round up that even 1 bit will give 1 kbit as a result
    return int((value + (base - 1)) / base)


class TcCommand(ip_lib.IPDevice):

    def __init__(self, name, kernel_hz, namespace=None):
        if kernel_hz <= 0:
            raise InvalidKernelHzValue(value=kernel_hz)
        super(TcCommand, self).__init__(name, namespace=namespace)
        self.kernel_hz = kernel_hz

    def _execute_tc_cmd(self, cmd, **kwargs):
        cmd = ['tc'] + cmd
        ip_wrapper = ip_lib.IPWrapper(self.namespace)
        return ip_wrapper.netns.execute(cmd, run_as_root=True, **kwargs)

    def get_bw_limits(self):
        return self._get_tbf_limits()

    def set_bw_limit(self, bw_limit, burst_limit, latency_value):
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def update_bw_limit(self, bw_limit, burst_limit, latency_value):
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def delete_bw_limit(self):
        cmd = ['qdisc', 'del', 'dev', self.name, 'root']
        # Return_code=2 is fine because it means
        # "RTNETLINK answers: No such file or directory" what is fine when we
        # are trying to delete qdisc
        return self._execute_tc_cmd(cmd, extra_ok_codes=[2])

    def get_burst_value(self, bw_limit, burst_limit):
        min_burst_value = self._get_min_burst_value(bw_limit)
        return max(min_burst_value, burst_limit)

    def _get_min_burst_value(self, bw_limit):
        # bw_limit [kbit] / HZ [1/s] = burst [kbit]
        return float(bw_limit) / float(self.kernel_hz)

    def _get_tbf_limits(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        pattern = re.compile(
            r"qdisc (\w+) \w+: \w+ refcnt \d rate (\w+) burst (\w+) \w*"
        )
        m = pattern.match(cmd_result)
        if not m:
            return None, None
        qdisc_name = m.group(1)
        if qdisc_name != "tbf":
            return None, None
        #NOTE(slaweq): because tc is giving bw limit in SI units
        # we need to calculate it as 1000bit = 1kbit:
        bw_limit = convert_to_kilobits(m.group(2), SI_BASE)
        #NOTE(slaweq): because tc is giving burst limit in IEC units
        # we need to calculate it as 1024bit = 1kbit:
        burst_limit = convert_to_kilobits(m.group(3), IEC_BASE)
        return bw_limit, burst_limit

    def _replace_tbf_qdisc(self, bw_limit, burst_limit, latency_value):
        burst = "%s%s" % (
            self.get_burst_value(bw_limit, burst_limit), BURST_UNIT)
        latency = "%s%s" % (latency_value, LATENCY_UNIT)
        rate_limit = "%s%s" % (bw_limit, BW_LIMIT_UNIT)
        cmd = [
            'qdisc', 'replace', 'dev', self.name,
            'root', 'tbf',
            'rate', rate_limit,
            'latency', latency,
            'burst', burst
        ]
        return self._execute_tc_cmd(cmd)
