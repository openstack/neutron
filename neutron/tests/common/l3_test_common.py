# Copyright (c) 2015 Openstack Foundation
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

import copy
import netaddr
from oslo_utils import uuidutils
from six import moves

from neutron.common import constants as l3_constants

_uuid = uuidutils.generate_uuid


class FakeDev(object):
    def __init__(self, name):
        self.name = name


def get_ha_interface(ip='169.254.192.1', mac='12:34:56:78:2b:5d'):
    subnet_id = _uuid()
    return {'admin_state_up': True,
            'device_id': _uuid(),
            'device_owner': 'network:router_ha_interface',
            'fixed_ips': [{'ip_address': ip,
                           'prefixlen': 18,
                           'subnet_id': subnet_id}],
            'id': _uuid(),
            'mac_address': mac,
            'name': u'L3 HA Admin port 0',
            'network_id': _uuid(),
            'status': u'ACTIVE',
            'subnets': [{'cidr': '169.254.192.0/18',
                         'gateway_ip': '169.254.255.254',
                         'id': subnet_id}],
            'tenant_id': '',
            'agent_id': _uuid(),
            'agent_host': 'aaa',
            'priority': 1}


def prepare_router_data(ip_version=4, enable_snat=None, num_internal_ports=1,
                        enable_floating_ip=False, enable_ha=False,
                        extra_routes=False, dual_stack=False,
                        v6_ext_gw_with_sub=True, **kwargs):
    fixed_ips = []
    subnets = []
    gateway_mac = kwargs.get('gateway_mac', 'ca:fe:de:ad:be:ee')
    extra_subnets = []
    for loop_version in (4, 6):
        if loop_version == 4 and (ip_version == 4 or dual_stack):
            ip_address = kwargs.get('ip_address', '19.4.4.4')
            prefixlen = 24
            subnet_cidr = kwargs.get('subnet_cidr', '19.4.4.0/24')
            gateway_ip = kwargs.get('gateway_ip', '19.4.4.1')
            _extra_subnet = {'cidr': '9.4.5.0/24'}
        elif (loop_version == 6 and (ip_version == 6 or dual_stack) and
              v6_ext_gw_with_sub):
            ip_address = kwargs.get('ip_address', 'fd00::4')
            prefixlen = 64
            subnet_cidr = kwargs.get('subnet_cidr', 'fd00::/64')
            gateway_ip = kwargs.get('gateway_ip', 'fd00::1')
            _extra_subnet = {'cidr': 'fd01::/64'}
        else:
            continue
        subnet_id = _uuid()
        fixed_ips.append({'ip_address': ip_address,
                          'subnet_id': subnet_id,
                          'prefixlen': prefixlen})
        subnets.append({'id': subnet_id,
                        'cidr': subnet_cidr,
                        'gateway_ip': gateway_ip})
        extra_subnets.append(_extra_subnet)
    if not fixed_ips and v6_ext_gw_with_sub:
        raise ValueError("Invalid ip_version: %s" % ip_version)

    router_id = _uuid()
    ex_gw_port = {'id': _uuid(),
                  'mac_address': gateway_mac,
                  'network_id': _uuid(),
                  'fixed_ips': fixed_ips,
                  'subnets': subnets,
                  'extra_subnets': extra_subnets}

    routes = []
    if extra_routes:
        routes = [{'destination': '8.8.8.0/24', 'nexthop': '19.4.4.4'}]

    router = {
        'id': router_id,
        'distributed': False,
        l3_constants.INTERFACE_KEY: [],
        'routes': routes,
        'gw_port': ex_gw_port}

    if enable_floating_ip:
        router[l3_constants.FLOATINGIP_KEY] = [{
            'id': _uuid(),
            'port_id': _uuid(),
            'status': 'DOWN',
            'floating_ip_address': '19.4.4.2',
            'fixed_ip_address': '10.0.0.1'}]

    router_append_interface(router, count=num_internal_ports,
                            ip_version=ip_version, dual_stack=dual_stack)
    if enable_ha:
        router['ha'] = True
        router['ha_vr_id'] = 1
        router[l3_constants.HA_INTERFACE_KEY] = (get_ha_interface())

    if enable_snat is not None:
        router['enable_snat'] = enable_snat
    return router


def get_subnet_id(port):
    return port['fixed_ips'][0]['subnet_id']


def router_append_interface(router, count=1, ip_version=4, ra_mode=None,
                            addr_mode=None, dual_stack=False):
    interfaces = router[l3_constants.INTERFACE_KEY]
    current = sum(
        [netaddr.IPNetwork(subnet['cidr']).version == ip_version
         for p in interfaces for subnet in p['subnets']])

    mac_address = netaddr.EUI('ca:fe:de:ad:be:ef')
    mac_address.dialect = netaddr.mac_unix
    for i in range(current, current + count):
        fixed_ips = []
        subnets = []
        for loop_version in (4, 6):
            if loop_version == 4 and (ip_version == 4 or dual_stack):
                ip_pool = '35.4.%i.4'
                cidr_pool = '35.4.%i.0/24'
                prefixlen = 24
                gw_pool = '35.4.%i.1'
            elif loop_version == 6 and (ip_version == 6 or dual_stack):
                ip_pool = 'fd01:%x:1::6'
                cidr_pool = 'fd01:%x:1::/64'
                prefixlen = 64
                gw_pool = 'fd01:%x:1::1'
            else:
                continue
            subnet_id = _uuid()
            fixed_ips.append({'ip_address': ip_pool % i,
                              'subnet_id': subnet_id,
                              'prefixlen': prefixlen})
            subnets.append({'id': subnet_id,
                            'cidr': cidr_pool % i,
                            'gateway_ip': gw_pool % i,
                            'ipv6_ra_mode': ra_mode,
                            'ipv6_address_mode': addr_mode})
        if not fixed_ips:
            raise ValueError("Invalid ip_version: %s" % ip_version)

        interfaces.append(
            {'id': _uuid(),
             'network_id': _uuid(),
             'admin_state_up': True,
             'fixed_ips': fixed_ips,
             'mac_address': str(mac_address),
             'subnets': subnets})
        mac_address.value += 1


def router_append_subnet(router, count=1, ip_version=4,
                         ipv6_subnet_modes=None, interface_id=None):
    if ip_version == 6:
        subnet_mode_none = {'ra_mode': None, 'address_mode': None}
        if not ipv6_subnet_modes:
            ipv6_subnet_modes = [subnet_mode_none] * count
        elif len(ipv6_subnet_modes) != count:
            ipv6_subnet_modes.extend([subnet_mode_none for i in
                                      moves.range(len(ipv6_subnet_modes),
                                                  count)])

    if ip_version == 4:
        ip_pool = '35.4.%i.4'
        cidr_pool = '35.4.%i.0/24'
        prefixlen = 24
        gw_pool = '35.4.%i.1'
    elif ip_version == 6:
        ip_pool = 'fd01:%x::6'
        cidr_pool = 'fd01:%x::/64'
        prefixlen = 64
        gw_pool = 'fd01:%x::1'
    else:
        raise ValueError("Invalid ip_version: %s" % ip_version)

    interfaces = copy.deepcopy(router.get(l3_constants.INTERFACE_KEY, []))
    if interface_id:
        try:
            interface = next(i for i in interfaces
                         if i['id'] == interface_id)
        except StopIteration:
            raise ValueError("interface_id not found")

        fixed_ips, subnets = interface['fixed_ips'], interface['subnets']
    else:
        interface = None
        fixed_ips, subnets = [], []

    num_existing_subnets = len(subnets)
    for i in moves.range(count):
        subnet_id = _uuid()
        fixed_ips.append(
                {'ip_address': ip_pool % (i + num_existing_subnets),
                 'subnet_id': subnet_id,
                 'prefixlen': prefixlen})
        subnets.append(
                {'id': subnet_id,
                 'cidr': cidr_pool % (i + num_existing_subnets),
                 'gateway_ip': gw_pool % (i + num_existing_subnets),
                 'ipv6_ra_mode': ipv6_subnet_modes[i]['ra_mode'],
                 'ipv6_address_mode': ipv6_subnet_modes[i]['address_mode']})

    if interface:
        # Update old interface
        index = interfaces.index(interface)
        interfaces[index].update({'fixed_ips': fixed_ips, 'subnets': subnets})
    else:
        # New interface appended to interfaces list
        mac_address = netaddr.EUI('ca:fe:de:ad:be:ef')
        mac_address.dialect = netaddr.mac_unix
        interfaces.append(
            {'id': _uuid(),
             'network_id': _uuid(),
             'admin_state_up': True,
             'mac_address': str(mac_address),
             'fixed_ips': fixed_ips,
             'subnets': subnets})

    router[l3_constants.INTERFACE_KEY] = interfaces


def prepare_ext_gw_test(context, ri, dual_stack=False):
    subnet_id = _uuid()
    fixed_ips = [{'subnet_id': subnet_id,
                  'ip_address': '20.0.0.30',
                  'prefixlen': 24}]
    subnets = [{'id': subnet_id,
                'cidr': '20.0.0.0/24',
                'gateway_ip': '20.0.0.1'}]
    if dual_stack:
        subnet_id_v6 = _uuid()
        fixed_ips.append({'subnet_id': subnet_id_v6,
                          'ip_address': '2001:192:168:100::2',
                          'prefixlen': 64})
        subnets.append({'id': subnet_id_v6,
                        'cidr': '2001:192:168:100::/64',
                        'gateway_ip': '2001:192:168:100::1'})
    ex_gw_port = {'fixed_ips': fixed_ips,
                  'subnets': subnets,
                  'extra_subnets': [{'cidr': '172.16.0.0/24'}],
                  'id': _uuid(),
                  'network_id': _uuid(),
                  'mac_address': 'ca:fe:de:ad:be:ef'}
    interface_name = ri.get_external_device_name(ex_gw_port['id'])

    context.device_exists.return_value = True

    return interface_name, ex_gw_port
