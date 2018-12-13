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

import math
import re

import netaddr
from neutron_lib import exceptions
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging
from pyroute2.iproute import linux as iproute_linux
from pyroute2.netlink import rtnl
from pyroute2.netlink.rtnl.tcmsg import common as rtnl_common

from neutron._i18n import _
from neutron.agent.linux import ip_lib
from neutron.common import utils
from neutron.privileged.agent.linux import tc_lib as priv_tc_lib


LOG = logging.getLogger(__name__)

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

TC_QDISC_TYPES = ['htb', 'tbf', 'ingress']

TC_QDISC_PARENT = {'root': rtnl.TC_H_ROOT,
                   'ingress': rtnl.TC_H_INGRESS}
TC_QDISC_PARENT_NAME = {v: k for k, v in TC_QDISC_PARENT.items()}


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


def _get_attr(pyroute2_obj, attr_name):
    """Get an attribute in a pyroute object

    pyroute2 object attributes are stored under a key called 'attrs'. This key
    contains a tuple of tuples. E.g.:
      pyroute2_obj = {'attrs': (('TCA_KIND': 'htb'),
                                ('TCA_OPTIONS': {...}))}

    :param pyroute2_obj: (dict) pyroute2 object
    :param attr_name: (string) first value of the tuple we are looking for
    :return: (object) second value of the tuple, None if the tuple doesn't
             exist
    """
    rule_attrs = pyroute2_obj.get('attrs', [])
    for attr in (attr for attr in rule_attrs if attr[0] == attr_name):
        return attr[1]
    return


def _get_tbf_burst_value(rate, burst_limit, kernel_hz):
    min_burst_value = float(rate) / float(kernel_hz)
    return max(min_burst_value, burst_limit)


def _calc_burst(rate, buffer):
    """Calculate burst rate

    :param rate: (int) rate in bytes per second.
    :param buffer: (int) buffer size in bytes.
    :return: (int) burst in bytes
    """
    # NOTE(ralonsoh): this function is based in
    # pyroute2.netlink.rtnl.tcmsg.common.calc_xmittime
    return int(math.ceil(
        float(buffer * rate) /
        (rtnl_common.TIME_UNITS_PER_SEC * rtnl_common.tick_in_usec)))


def _calc_latency_ms(limit, burst, rate):
    """Calculate latency value, in ms

    :param limit: (int) pyroute2 limit value
    :param burst: (int) burst in bytes
    :param rate: (int) maximum bandwidth in kbytes per second
    :return: (int) latency, in ms
    """
    return int(math.ceil(
        float((limit - burst) * rtnl_common.TIME_UNITS_PER_SEC) /
        (rate * 1000)))


def _handle_from_hex_to_string(handle):
    """Convert TC handle from hex to string

    :param handle: (int) TC handle
    :return: (string) handle formatted to string: 0xMMMMmmmm -> "M:m"
    """
    minor = str(handle & 0xFFFF)
    major = str((handle & 0xFFFF0000) >> 16)
    return ':'.join([major, minor])


def _mac_to_pyroute2_keys(mac, offset):
    """Convert a MAC address to a list of filter keys

    For example:
      MAC: '01:23:45:67:89:0a', offset: 8
      keys: ['0x01234567/0xffffffff+8', '0x890a0000/0xffff0000+12']

    :param mac: (string) MAC address
    :param offset: (int) natural number, offset bytes number from the IP header
    """
    int_mac = int(netaddr.EUI(mac))
    high_value = int_mac >> 16
    high_mask = 0xffffffff
    high_offset = offset
    high = {'value': high_value,
            'mask': high_mask,
            'offset': high_offset,
            'key': (hex(high_value) + '/' + hex(high_mask) + '+' +
                    str(high_offset))}

    low_value = (int_mac & 0xffff) << 16
    low_mask = 0xffff0000
    low_offset = offset + 4
    low = {'value': low_value,
           'mask': low_mask,
           'offset': low_offset,
           'key': hex(low_value) + '/' + hex(low_mask) + '+' + str(low_offset)}

    return [high, low]


class TcCommand(ip_lib.IPDevice):

    def __init__(self, name, kernel_hz, namespace=None):
        if kernel_hz <= 0:
            raise InvalidKernelHzValue(value=kernel_hz)
        super(TcCommand, self).__init__(name, namespace=namespace)
        self.kernel_hz = kernel_hz

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
        filters = list_tc_filters(self.name, qdisc_id,
                                  namespace=self.namespace)
        if filters:
            return filters[0].get('rate_kbps'), filters[0].get('burst_kb')

        return None, None

    def get_tbf_bw_limits(self):
        qdiscs = list_tc_qdiscs(self.name, namespace=self.namespace)
        if not qdiscs:
            return None, None

        qdisc = qdiscs[0]
        if qdisc['qdisc_type'] != 'tbf':
            return None, None

        return qdisc['max_kbps'], qdisc['burst_kb']

    def set_filters_bw_limit(self, bw_limit, burst_limit):
        """Set ingress qdisc and filter for police ingress traffic on device

        This will allow to police traffic incoming to interface. It
        means that it is fine to limit egress traffic from instance point of
        view.
        """
        # because replace of tc filters is not working properly and it's adding
        # new filters each time instead of replacing existing one first old
        # ingress qdisc should be deleted and then added new one so update will
        # be called to do that:
        return self.update_filters_bw_limit(bw_limit, burst_limit)

    def set_tbf_bw_limit(self, bw_limit, burst_limit, latency_value):
        """Set/update token bucket filter qdisc on device

        This will allow to limit speed of packets going out from interface. It
        means that it is fine to limit ingress traffic from instance point of
        view.
        """
        return add_tc_qdisc(self.name, 'tbf', parent='root',
                            max_kbps=bw_limit, burst_kb=burst_limit,
                            latency_ms=latency_value, kernel_hz=self.kernel_hz,
                            namespace=self.namespace)

    def update_filters_bw_limit(self, bw_limit, burst_limit):
        self.delete_filters_bw_limit()
        add_tc_qdisc(self.name, 'ingress', namespace=self.namespace)
        return self._add_policy_filter(bw_limit, burst_limit)

    def delete_filters_bw_limit(self):
        # NOTE(slaweq): For limit traffic egress from instance we need to use
        # qdisc "ingress" because it is ingress traffic from interface POV:
        delete_tc_qdisc(self.name, is_ingress=True,
                        raise_interface_not_found=False,
                        raise_qdisc_not_found=False, namespace=self.namespace)

    def delete_tbf_bw_limit(self):
        delete_tc_qdisc(self.name, parent='root',
                        raise_interface_not_found=False,
                        raise_qdisc_not_found=False, namespace=self.namespace)

    def _add_policy_filter(self, bw_limit, burst_limit,
                           qdisc_id=INGRESS_QDISC_ID):
        # NOTE(slaweq): it is made in exactly same way how openvswitch is doing
        # it when configuing ingress traffic limit on port. It can be found in
        # lib/netdev-linux.c#L4698 in openvswitch sources:
        add_tc_filter_policy(self.name, qdisc_id, bw_limit, burst_limit,
                             MAX_MTU_VALUE, 'drop', priority=49)


def add_tc_qdisc(device, qdisc_type, parent=None, handle=None, latency_ms=None,
                 max_kbps=None, burst_kb=None, kernel_hz=None,
                 namespace=None):
    """Add/replace a TC qdisc on a device

    pyroute2 input parameters:
      - rate (min bw): bytes/second
      - burst: bytes
      - latency: us

    :param device: (string) device name
    :param qdisc_type: (string) qdisc type (TC_QDISC_TYPES)
    :param parent: (string) qdisc parent class ('root', '2:10')
    :param handle: (string, int) (required for HTB) major handler identifier
                   (0xffff0000, '1', '1:', '1:0') [1]
    :param latency_ms: (string, int) (required for TBF) latency time in ms
    :param max_kbps: (string, int) (required for TBF) maximum bandwidth in
                     kbits per second.
    :param burst_kb: (string, int) (required for TBF) maximum bandwidth in
                     kbits.
    :param kernel_hz: (string, int) (required for TBF) kernel HZ.
    :param namespace: (string) (optional) namespace name

    [1] https://lartc.org/howto/lartc.qdisc.classful.html
    """
    if qdisc_type and qdisc_type not in TC_QDISC_TYPES:
        raise qos_exc.TcLibQdiscTypeError(
            qdisc_type=qdisc_type, supported_qdisc_types=TC_QDISC_TYPES)

    args = {'kind': qdisc_type}
    if qdisc_type in ['htb', 'ingress']:
        if handle:
            args['handle'] = str(handle).split(':')[0] + ':0'
    elif qdisc_type == 'tbf':
        if not latency_ms or not max_kbps or not kernel_hz:
            raise qos_exc.TcLibQdiscNeededArguments(
                qdisc_type=qdisc_type,
                needed_arguments=['latency_ms', 'max_kbps', 'kernel_hz'])
        args['burst'] = int(
            _get_tbf_burst_value(max_kbps, burst_kb, kernel_hz) * 1024 / 8)
        args['rate'] = int(max_kbps * 1024 / 8)
        args['latency'] = latency_ms * 1000
    if parent:
        args['parent'] = rtnl.TC_H_ROOT if parent == 'root' else parent
    priv_tc_lib.add_tc_qdisc(device, namespace=namespace, **args)


def list_tc_qdiscs(device, namespace=None):
    """List all TC qdiscs of a device

    :param device: (string) device name
    :param namespace: (string) (optional) namespace name
    :return: (list) TC qdiscs
    """
    qdiscs = priv_tc_lib.list_tc_qdiscs(device, namespace=namespace)
    retval = []
    for qdisc in qdiscs:
        qdisc_attrs = {
            'qdisc_type': _get_attr(qdisc, 'TCA_KIND'),
            'parent': TC_QDISC_PARENT_NAME.get(
                qdisc['parent'], _handle_from_hex_to_string(qdisc['parent'])),
            'handle': _handle_from_hex_to_string(qdisc['handle'])}
        if qdisc_attrs['qdisc_type'] == 'tbf':
            tca_options = _get_attr(qdisc, 'TCA_OPTIONS')
            tca_tbf_parms = _get_attr(tca_options, 'TCA_TBF_PARMS')
            qdisc_attrs['max_kbps'] = int(tca_tbf_parms['rate'] * 8 / 1024)
            burst_bytes = _calc_burst(tca_tbf_parms['rate'],
                                      tca_tbf_parms['buffer'])
            qdisc_attrs['burst_kb'] = int(burst_bytes * 8 / 1024)
            qdisc_attrs['latency_ms'] = _calc_latency_ms(
                tca_tbf_parms['limit'], burst_bytes, tca_tbf_parms['rate'])
        retval.append(qdisc_attrs)

    return retval


def delete_tc_qdisc(device, parent=None, is_ingress=False,
                    raise_interface_not_found=True, raise_qdisc_not_found=True,
                    namespace=None):
    """Delete a TC qdisc of a device

    :param device: (string) device name
    :param parent: (string) (optional) qdisc parent class ('root', '2:10')
    :param is_ingress: (bool) (optional) if qdisc type is 'ingress'
    :param raise_interface_not_found: (bool) (optional) raise exception if the
                                      interface doesn't exist
    :param raise_qdisc_not_found: (bool) (optional) raise exception if the
                                  qdisc doesn't exist
    :param namespace: (string) (optional) namespace name
    """
    qdisc_type = 'ingress' if is_ingress else None
    if parent:
        parent = rtnl.TC_H_ROOT if parent == 'root' else parent
    priv_tc_lib.delete_tc_qdisc(
        device, parent=parent, kind=qdisc_type,
        raise_interface_not_found=raise_interface_not_found,
        raise_qdisc_not_found=raise_qdisc_not_found, namespace=namespace)


def add_tc_policy_class(device, parent, classid, qdisc_type,
                        min_kbps=None, max_kbps=None, burst_kb=None,
                        namespace=None):
    """Add a TC policy class

    :param device: (string) device name
    :param parent: (string) qdisc parent class ('root', 'ingress', '2:10')
    :param classid: (string) major:minor handler identifier ('10:20')
    :param qdisc_type: (string) qdisc type ("sfq", "htb", "u32", etc)
    :param min_kbps: (int) (optional) minimum bandwidth in kbps
    :param max_kbps: (int) (optional) maximum bandwidth in kbps
    :param burst_kb: (int) (optional) burst size in kb
    :param namespace: (string) (optional) namespace name
    :return:
    """
    parent = TC_QDISC_PARENT.get(parent, parent)
    args = {}
    # NOTE(ralonsoh): pyroute2 input parameters and units [1]:
    #   - rate (min bw): bytes/second
    #   - ceil (max bw): bytes/second
    #   - burst: bytes
    # [1] https://www.systutorials.com/docs/linux/man/8-tc/
    if min_kbps:
        args['rate'] = int(min_kbps * 1024 / 8)
    if max_kbps:
        args['ceil'] = int(max_kbps * 1024 / 8)
    if burst_kb:
        args['burst'] = int(burst_kb * 1024 / 8)
    priv_tc_lib.add_tc_policy_class(device, parent, classid, qdisc_type,
                                    namespace=namespace, **args)


def list_tc_policy_class(device, namespace=None):
    """List all TC policy classes of a device

    :param device: (string) device name
    :param namespace: (string) (optional) namespace name
    :return: (list) TC policy classes
    """
    def get_params(tca_options, qdisc_type):
        if qdisc_type not in TC_QDISC_TYPES:
            return None, None, None

        tca_params = _get_attr(tca_options,
                               'TCA_' + qdisc_type.upper() + '_PARMS')
        burst_kb = int(
            _calc_burst(tca_params['rate'], tca_params['buffer']) * 8 / 1024)
        max_kbps = int(tca_params['ceil'] * 8 / 1024)
        min_kbps = int(tca_params['rate'] * 8 / 1024)
        return max_kbps, min_kbps, burst_kb

    tc_classes = priv_tc_lib.list_tc_policy_classes(device,
                                                    namespace=namespace)
    classes = []
    for tc_class in tc_classes:
        index = tc_class['index']
        parent = TC_QDISC_PARENT_NAME.get(
            tc_class['parent'], _handle_from_hex_to_string(tc_class['parent']))
        classid = _handle_from_hex_to_string(tc_class['handle'])
        qdisc_type = _get_attr(tc_class, 'TCA_KIND')
        tca_options = _get_attr(tc_class, 'TCA_OPTIONS')
        max_kbps, min_kbps, burst_kb = get_params(tca_options, qdisc_type)
        classes.append({'device': device,
                        'index': index,
                        'namespace': namespace,
                        'parent': parent,
                        'classid': classid,
                        'qdisc_type': qdisc_type,
                        'min_kbps': min_kbps,
                        'max_kbps': max_kbps,
                        'burst_kb': burst_kb})

    return classes


def delete_tc_policy_class(device, parent, classid, namespace=None):
    """Delete a TC policy class of a device.

    :param device: (string) device name
    :param parent: (string) qdisc parent class ('root', 'ingress', '2:10')
    :param classid: (string) major:minor handler identifier ('10:20')
    :param namespace: (string) (optional) namespace name
    """
    priv_tc_lib.delete_tc_policy_class(device, parent, classid,
                                       namespace=namespace)


def add_tc_filter_match_mac(device, parent, classid, mac, offset=0, priority=0,
                            protocol=None, namespace=None):
    """Add a TC filter in a device to match a MAC address.

    :param device: (string) device name
    :param parent: (string) qdisc parent class ('root', 'ingress', '2:10')
    :param classid: (string) major:minor handler identifier ('10:20')
    :param mac: (string) MAC address to match
    :param offset: (int) (optional) match offset, starting from the outer
                   packet IP header
    :param priority: (int) (optional) filter priority (lower priority, higher
                     preference)
    :param protocol: (int) (optional) traffic filter protocol; if None, all
                     will be matched.
    :param namespace: (string) (optional) namespace name

    """
    keys = [key['key'] for key in _mac_to_pyroute2_keys(mac, offset)]
    priv_tc_lib.add_tc_filter_match32(device, parent, priority, classid, keys,
                                      protocol=protocol, namespace=namespace)


def add_tc_filter_policy(device, parent, rate_kbps, burst_kb, mtu, action,
                         priority=0, protocol=None, namespace=None):
    """Add a TC filter in a device to set a policy.

    :param device: (string) device name
    :param parent: (string) qdisc parent class ('root', 'ingress', '2:10')
    :param rate_kbps: (int) rate in kbits/second
    :param burst_kb: (int) burst in kbits
    :param mtu: (int) MTU size (bytes)
    :param action: (string) filter policy action
    :param priority: (int) (optional) filter priority (lower priority, higher
                     preference)
    :param protocol: (int) (optional) traffic filter protocol; if None, all
                     will be matched.
    :param namespace: (string) (optional) namespace name

    """
    rate = int(rate_kbps * 1024 / 8)
    burst = int(burst_kb * 1024 / 8)
    priv_tc_lib.add_tc_filter_policy(device, parent, priority, rate, burst,
                                     mtu, action, protocol=protocol,
                                     namespace=namespace)


def list_tc_filters(device, parent, namespace=None):
    """List TC filter in a device

    :param device: (string) device name
    :param parent: (string) qdisc parent class ('root', 'ingress', '2:10')
    :param namespace: (string) (optional) namespace name

    """
    parent = iproute_linux.transform_handle(parent)
    filters = priv_tc_lib.list_tc_filters(device, parent, namespace=namespace)
    retval = []
    for filter in filters:
        tca_options = _get_attr(filter, 'TCA_OPTIONS')
        if not tca_options:
            continue
        tca_u32_sel = _get_attr(tca_options, 'TCA_U32_SEL')
        if not tca_u32_sel:
            continue
        keys = []
        for key in tca_u32_sel['keys']:
            key_off = key['key_off']
            value = 0
            for i in range(4):
                value = (value << 8) + (key_off & 0xff)
                key_off = key_off >> 8
            keys.append({'value': value,
                         'mask': key['key_val'],
                         'offset': key['key_offmask']})

        value = {'keys': keys}

        tca_u32_police = _get_attr(tca_options, 'TCA_U32_POLICE')
        if tca_u32_police:
            tca_police_tbf = _get_attr(tca_u32_police, 'TCA_POLICE_TBF')
            if tca_police_tbf:
                value['rate_kbps'] = int(tca_police_tbf['rate'] * 8 / 1024)
                value['burst_kb'] = int(
                    _calc_burst(tca_police_tbf['rate'],
                                tca_police_tbf['burst']) * 8 / 1024)
                value['mtu'] = tca_police_tbf['mtu']

        retval.append(value)

    return retval
