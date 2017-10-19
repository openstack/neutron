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

from neutron_lib import exceptions
from neutron_lib.services.qos import constants as qos_consts

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.common import constants
from neutron.common import utils


INGRESS_QDISC_ID = "ffff:"
MAX_MTU_VALUE = 65535

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

filters_pattern = re.compile(r"police \w+ rate (\w+) burst (\w+)")
tbf_pattern = re.compile(
    r"qdisc (\w+) \w+: \w+ refcnt \d rate (\w+) burst (\w+) \w*")


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
            return utils.bits_to_kilobits(value, base)
        else:
            bits_value = utils.bytes_to_bits(value)
            return utils.bits_to_kilobits(bits_value, base)
    unit = value[-1:]
    if unit not in UNITS.keys():
        raise InvalidUnit(unit=unit)
    val = int(value[:-1])
    if input_in_bits:
        bits_value = val * (base ** UNITS[unit])
    else:
        bits_value = utils.bytes_to_bits(val * (base ** UNITS[unit]))
    return utils.bits_to_kilobits(bits_value, base)


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

    @staticmethod
    def get_ingress_qdisc_burst_value(bw_limit, burst_limit):
        """Return burst value used in ingress qdisc.

        If burst value is not specified given than it will be set to default
        rate to ensure that limit for TCP traffic will work well
        """
        if not burst_limit:
            return float(bw_limit) * qos_consts.DEFAULT_BURST_RATE
        return burst_limit

    def get_filters_bw_limits(self, qdisc_id=INGRESS_QDISC_ID):
        cmd = ['filter', 'show', 'dev', self.name, 'parent', qdisc_id]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        for line in cmd_result.split("\n"):
            m = filters_pattern.match(line.strip())
            if m:
                #NOTE(slaweq): because tc is giving bw limit in SI units
                # we need to calculate it as 1000bit = 1kbit:
                bw_limit = convert_to_kilobits(m.group(1), constants.SI_BASE)
                #NOTE(slaweq): because tc is giving burst limit in IEC units
                # we need to calculate it as 1024bit = 1kbit:
                burst_limit = convert_to_kilobits(
                    m.group(2), constants.IEC_BASE)
                return bw_limit, burst_limit
        return None, None

    def get_tbf_bw_limits(self):
        cmd = ['qdisc', 'show', 'dev', self.name]
        cmd_result = self._execute_tc_cmd(cmd)
        if not cmd_result:
            return None, None
        m = tbf_pattern.match(cmd_result)
        if not m:
            return None, None
        qdisc_name = m.group(1)
        if qdisc_name != "tbf":
            return None, None
        #NOTE(slaweq): because tc is giving bw limit in SI units
        # we need to calculate it as 1000bit = 1kbit:
        bw_limit = convert_to_kilobits(m.group(2), constants.SI_BASE)
        #NOTE(slaweq): because tc is giving burst limit in IEC units
        # we need to calculate it as 1024bit = 1kbit:
        burst_limit = convert_to_kilobits(m.group(3), constants.IEC_BASE)
        return bw_limit, burst_limit

    def set_filters_bw_limit(self, bw_limit, burst_limit):
        """Set ingress qdisc and filter for police ingress traffic on device

        This will allow to police traffic incoming to interface. It
        means that it is fine to limit egress traffic from instance point of
        view.
        """
        #because replace of tc filters is not working properly and it's adding
        # new filters each time instead of replacing existing one first old
        # ingress qdisc should be deleted and then added new one so update will
        # be called to do that:
        return self.update_filters_bw_limit(bw_limit, burst_limit)

    def set_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        """Set token bucket filter qdisc on device

        This will allow to limit speed of packets going out from interface. It
        means that it is fine to limit ingress traffic from instance point of
        view.
        """
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def update_filters_bw_limit(self, bw_limit, burst_limit,
                                qdisc_id=INGRESS_QDISC_ID):
        self.delete_filters_bw_limit()
        return self._set_filters_bw_limit(bw_limit, burst_limit, qdisc_id)

    def update_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        return self._replace_tbf_qdisc(bw_limit, burst_limit, latency_value)

    def delete_filters_bw_limit(self):
        #NOTE(slaweq): For limit traffic egress from instance we need to use
        # qdisc "ingress" because it is ingress traffic from interface POV:
        self._delete_qdisc("ingress")

    def delete_tbf_bw_limit(self):
        self._delete_qdisc("root")

    def _set_filters_bw_limit(self, bw_limit, burst_limit,
                              qdisc_id=INGRESS_QDISC_ID):
        cmd = ['qdisc', 'add', 'dev', self.name, 'ingress',
               'handle', qdisc_id]
        self._execute_tc_cmd(cmd)
        return self._add_policy_filter(bw_limit, burst_limit)

    def _delete_qdisc(self, qdisc_name):
        cmd = ['qdisc', 'del', 'dev', self.name, qdisc_name]
        # Return_code=2 is fine because it means
        # "RTNETLINK answers: No such file or directory" what is fine when we
        # are trying to delete qdisc
        # Return_code=1 means "RTNETLINK answers: Cannot find device <device>".
        # If the device doesn't exist, the qdisc is already deleted.
        return self._execute_tc_cmd(cmd, extra_ok_codes=[1, 2])

    def _get_tbf_burst_value(self, bw_limit, burst_limit):
        min_burst_value = float(bw_limit) / float(self.kernel_hz)
        return max(min_burst_value, burst_limit)

    def _replace_tbf_qdisc(self, bw_limit, burst_limit, latency_value):
        burst = "%s%s" % (
            self._get_tbf_burst_value(bw_limit, burst_limit), BURST_UNIT)
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

    def _add_policy_filter(self, bw_limit, burst_limit,
                           qdisc_id=INGRESS_QDISC_ID):
        rate_limit = "%s%s" % (bw_limit, BW_LIMIT_UNIT)
        burst = "%s%s" % (
            self.get_ingress_qdisc_burst_value(bw_limit, burst_limit),
            BURST_UNIT
        )
        #NOTE(slaweq): it is made in exactly same way how openvswitch is doing
        # it when configuing ingress traffic limit on port. It can be found in
        # lib/netdev-linux.c#L4698 in openvswitch sources:
        cmd = [
            'filter', 'add', 'dev', self.name,
            'parent', qdisc_id, 'protocol', 'all',
            'prio', '49', 'basic', 'police',
            'rate', rate_limit,
            'burst', burst,
            'mtu', MAX_MTU_VALUE,
            'drop']
        return self._execute_tc_cmd(cmd)
