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

import collections
import math
import re

from neutron_lib import exceptions
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.common import constants
from neutron.services.qos import qos_consts


LOG = logging.getLogger(__name__)

ROOT_QDISC = "root"
INGRESS_QDISC = "ingress"
INGRESS_QDISC_HEX = "ffff:fff1"
INGRESS_QDISC_HANDLE = "ffff:"
QDISC_TYPE_HTB = "htb"
QDISC_TYPE_DEFAULT = "pfifo_fast"

SI_BASE = 1000
IEC_BASE = 1024

BW_LIMIT_UNIT = "kbit"  # kilobits per second in tc's notation
BURST_UNIT = "kbit"  # kilobits in tc's notation

# Those are RATES (bits per second) and SIZE (bytes) unit names from tc manual
UNITS = {
    "k": 1,
    "m": 2,
    "g": 3,
    "t": 4
}


class InvalidUnit(exceptions.NeutronException):
    message = _("Unit name '%(unit)s' is not valid.")


class InvalidPolicyClassParameters(exceptions.NeutronException):
    message = _("'rate' or 'ceil' parameters must be defined")


def kilobits_to_bits(value, base):
    return value * base


def bits_to_kilobits(value, base):
    return int(math.ceil(float(value) / base))


def bytes_to_bits(value):
    return value * 8


def bits_to_bytes(value):
    return int(value / 8)


def convert_to_kilo(value, base):
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


class TcCommand(ip_lib.IPDevice):

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
            return int(float(bw_limit) * qos_consts.DEFAULT_BURST_RATE)
        return burst_limit

    def set_bw(self, max, burst, min, direction):
        max = kilobits_to_bits(max, SI_BASE) if max else max
        burst = (bits_to_bytes(kilobits_to_bits(burst, IEC_BASE)) if burst
                 else burst)
        min = kilobits_to_bits(min, SI_BASE) if min else min
        if direction == constants.EGRESS_DIRECTION:
            return self._set_ingress_bw(max, burst, min)
        else:
            raise NotImplementedError()

    def delete_bw(self, direction):
        if direction == constants.EGRESS_DIRECTION:
            return self._delete_ingress()
        else:
            raise NotImplementedError()

    def get_limits(self, direction):
        if direction == constants.EGRESS_DIRECTION:
            return self._get_ingress_limits()
        else:
            raise NotImplementedError()

    def _set_ingress_bw(self, max, burst, min):
        self._add_policy_qdisc(INGRESS_QDISC, INGRESS_QDISC_HANDLE)
        self._configure_ifb(max=max, burst=burst, min=min)

    def _delete_ingress(self):
        ifb = self._find_mirrored_ifb()
        if ifb:
            self._del_ifb(ifb)
        self._del_policy_qdisc(INGRESS_QDISC)

    def _add_policy_qdisc(self, parent, handle, qdisc_type=None, dev=None):
        def check_qdisc(qdisc, qdisc_type, handle, parent, device):
            if not qdisc or qdisc.get('type') == QDISC_TYPE_DEFAULT:
                return False
            elif ((qdisc_type and (qdisc.get('type') != qdisc_type or
                    qdisc.get('handle') != handle)) or
                    (not qdisc_type and qdisc.get('handle') != handle)):
                self._del_policy_qdisc(parent, dev=device)
                return False
            return True

        device = str(dev) if dev else self.name
        qdisc = self._show_policy_qdisc(parent, dev=device)
        if check_qdisc(qdisc, qdisc_type, handle, parent, device):
            return
        cmd = ['qdisc', 'add', 'dev', device]
        if parent in [ROOT_QDISC, INGRESS_QDISC]:
            cmd += [parent]
        else:
            cmd += ['parent', parent]
        cmd += ['handle', handle]
        if qdisc_type:
            cmd += [qdisc_type]

        LOG.debug("Add policy qdisc cmd: %s", cmd)
        return self._execute_tc_cmd(cmd)

    def _del_policy_qdisc(self, parent, dev=None):
        device = str(dev) if dev else self.name
        if not self._show_policy_qdisc(parent, dev=device):
            return
        cmd = ['qdisc', 'del', 'dev', device]
        if parent in [ROOT_QDISC, INGRESS_QDISC]:
            cmd += [parent]
        else:
            cmd += ['parent', parent]

        LOG.debug("Delete policy qdisc cmd: %s", cmd)
        self._execute_tc_cmd(cmd)

    def _list_policy_qdisc(self, dev=None):
        device = str(dev) if dev else self.name
        cmd = ['qdisc', 'show', 'dev', device]
        LOG.debug("List policy qdisc cmd: %s", cmd)
        result = self._execute_tc_cmd(cmd)
        pat = re.compile(r'qdisc (\w+) (\w+\:) (root|parent (\w*\:\w+))')
        qdiscs = collections.defaultdict(dict)
        for match in (pat.match(line) for line in result.splitlines()
                      if pat.match(line)):
            qdisc = {}
            qdisc['type'] = match.groups()[0]
            qdisc['handle'] = match.groups()[1]
            if match.groups()[2] == ROOT_QDISC:
                qdisc['parentid'] = ROOT_QDISC
            else:
                qdisc['parentid'] = match.groups()[3]
            qdisc_ref = INGRESS_QDISC if qdisc['parentid'] == \
                INGRESS_QDISC_HEX else qdisc['parentid']
            qdiscs[qdisc_ref] = qdisc

        LOG.debug("List of policy qdiscs: %s", qdiscs)
        return qdiscs

    def _show_policy_qdisc(self, parent, dev=None):
        device = str(dev) if dev else self.name
        return self._list_policy_qdisc(device).get(parent)

    def _add_policy_class(self, parent, classid, qdisc_type, rate=None,
                          ceil=None, burst=None, dev=None):
        """Add new TC class"""
        device = str(dev) if dev else self.name
        policy = self._show_policy_class(classid, dev=device)
        if policy:
            rate = (kilobits_to_bits(policy['rate'], SI_BASE) if not rate
                    else rate)
            ceil = (kilobits_to_bits(policy['ceil'], SI_BASE) if not ceil
                    else ceil)
            burst = (bits_to_bytes(kilobits_to_bits(policy['burst'], IEC_BASE))
                     if not burst else burst)

        if not rate and not ceil:
            raise InvalidPolicyClassParameters
        if not rate:
            rate = ceil

        cmd = self._cmd_policy_class(classid, qdisc_type, rate, device, parent,
                                     ceil, burst)
        LOG.debug("Add/replace policy class cmd: %s", cmd)
        return self._execute_tc_cmd(cmd)

    def _cmd_policy_class(self, classid, qdisc_type, rate, device, parent,
                          ceil, burst):
        cmd = ['class', 'replace', 'dev', device]
        if parent:
            cmd += ['parent', parent]
        rate = 8 if rate < 8 else rate
        cmd += ['classid', classid, qdisc_type, 'rate', rate]
        if ceil:
            ceil = rate if ceil < rate else ceil
            cmd += ['ceil', ceil]
        if burst:
            cmd += ['burst', burst]
        return cmd

    def _list_policy_class(self, dev=None):
        device = str(dev) if dev else self.name
        cmd = ['class', 'show', 'dev', device]
        result = self._execute_tc_cmd(cmd, check_exit_code=False)
        if not result:
            return {}
        classes = collections.defaultdict(dict)
        pat = re.compile(r'class (\S+) ([0-9a-fA-F]+\:[0-9a-fA-F]+) '
                         r'(root|parent ([0-9a-fA-F]+\:[0-9a-fA-F]+))'
                         r'( prio ([0-9]+))* rate (\w+) ceil (\w+) burst (\w+)'
                         r' cburst (\w+)')
        for match in (pat.match(line) for line in result.splitlines()
                      if pat.match(line)):
            _class = {}
            _class['type'] = match.groups()[0]
            classid = match.groups()[1]
            if match.groups()[2] == ROOT_QDISC:
                _class['parentid'] = None
            else:
                _class['parentid'] = match.groups()[3]
            _class['prio'] = match.groups()[5]
            _class['rate'] = convert_to_kilo(match.groups()[6], SI_BASE)
            _class['ceil'] = convert_to_kilo(match.groups()[7], SI_BASE)
            _class['burst'] = convert_to_kilo(match.groups()[8], IEC_BASE)
            _class['cburst'] = convert_to_kilo(match.groups()[9], IEC_BASE)
            classes[classid] = _class
        LOG.debug("Policy classes: %s", classes)
        return classes

    def _show_policy_class(self, classid, dev=None):
        device = str(dev) if dev else self.name
        return self._list_policy_class(device).get(classid)

    def _add_policy_filter(self, parent, protocol, filter, dev=None,
                           action=None):
        """Add a new filter"""
        device = str(dev) if dev else self.name
        cmd = ['filter', 'add', 'dev', device, 'parent', parent]
        cmd += ['protocol'] + protocol
        cmd += filter
        if action:
            cmd += ['action'] + action

        LOG.debug("Add policy filter cmd: %s", cmd)
        return self._execute_tc_cmd(cmd)

    def _list_policy_filters(self, parent, dev=None):
        """Returns the output of showing the filters in a device"""
        device = dev if dev else self.name
        cmd = ['filter', 'show', 'dev', device, 'parent', parent]
        LOG.debug("List policy filter cmd: %s", cmd)
        return self._execute_tc_cmd(cmd)

    def _add_ifb(self, dev_name):
        """Create a new IFB device"""
        ns_ip = ip_lib.IPWrapper(namespace=self.namespace)
        if self._find_mirrored_ifb():
            ifb = ip_lib.IPDevice(dev_name, namespace=self.namespace)
            if not ifb.exists():
                self._del_ifb(dev_name=dev_name)
                ifb = ns_ip.add_ifb(dev_name)
        else:
            self._del_ifb(dev_name=dev_name)
            ifb = ns_ip.add_ifb(dev_name)

        ifb.disable_ipv6()
        ifb.link.set_up()
        return ifb

    def _del_ifb(self, dev_name):
        """Delete a IFB device"""
        ns_ip = ip_lib.IPWrapper(namespace=self.namespace)
        devices = ns_ip.get_devices(exclude_loopback=True)
        for device in (dev for dev in devices if dev.name == dev_name):
            ns_ip.del_ifb(device.name)

    def _find_mirrored_ifb(self):
        """Return the name of the IFB device where the traffic is mirrored"""
        ifb_name = self.name.replace("tap", "ifb")
        ifb = ip_lib.IPDevice(ifb_name, namespace=self.namespace)
        if not ifb.exists():
            return None
        return ifb_name

    def _configure_ifb(self, max=None, burst=None, min=None):
        ifb = self._find_mirrored_ifb()
        if not ifb:
            ifb = self.name.replace("tap", "ifb")
            self._add_ifb(ifb)
            protocol = ['all', 'u32']
            filter = ['match', 'u32', '0', '0']
            action = ['mirred', 'egress', 'redirect', 'dev', '%s' % ifb]
            self._add_policy_filter(INGRESS_QDISC_HANDLE, protocol, filter,
                                    dev=self.name, action=action)
        self._add_policy_qdisc(ROOT_QDISC, "1:", qdisc_type=QDISC_TYPE_HTB,
                               dev=ifb)
        self._add_policy_class("1:", "1:1", QDISC_TYPE_HTB, rate=min,
                               ceil=max, burst=burst, dev=ifb)

    def _get_ingress_limits(self):
        ifb = self._find_mirrored_ifb()
        if ifb:
            policy = self._show_policy_class("1:1", dev=ifb)
            if policy:
                return policy['ceil'], policy['burst'], policy['rate']
        return None, None, None
