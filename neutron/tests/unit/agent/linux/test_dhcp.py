# Copyright 2012 OpenStack Foundation
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

import os

import mock
import netaddr
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import config
from neutron.agent.dhcp import config as dhcp_config
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.common import config as base_config
from neutron.common import constants
from neutron.common import utils
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.tests import base

LOG = logging.getLogger(__name__)


class FakeIPAllocation(object):
    def __init__(self, address, subnet_id=None):
        self.ip_address = address
        self.subnet_id = subnet_id


class DhcpOpt(object):
    def __init__(self, **kwargs):
        self.__dict__.update(ip_version=4)
        self.__dict__.update(kwargs)

    def __str__(self):
        return str(self.__dict__)


class FakeDhcpPort(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa'
    admin_state_up = True
    device_owner = 'network:dhcp'
    fixed_ips = [FakeIPAllocation('192.168.0.1',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:80:aa:bb:ee'
    device_id = 'fake_dhcp_port'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort1(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    admin_state_up = True
    device_owner = 'foo1'
    fixed_ips = [FakeIPAllocation('192.168.0.2',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:80:aa:bb:cc'
    device_id = 'fake_port1'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort2(object):
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    admin_state_up = False
    device_owner = 'foo2'
    fixed_ips = [FakeIPAllocation('192.168.0.3',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:f3:aa:bb:cc'
    device_id = 'fake_port2'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort3(object):
    id = '44444444-4444-4444-4444-444444444444'
    admin_state_up = True
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('192.168.0.4',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd'),
                 FakeIPAllocation('192.168.1.2',
                                  'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
    mac_address = '00:00:0f:aa:bb:cc'
    device_id = 'fake_port3'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort4(object):

    id = 'gggggggg-gggg-gggg-gggg-gggggggggggg'
    admin_state_up = False
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('192.168.0.4',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd'),
                 FakeIPAllocation('ffda:3ba5:a17a:4ba3:0216:3eff:fec2:771d',
                                  'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
    mac_address = '00:16:3E:C2:77:1D'
    device_id = 'fake_port4'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePort5(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeee'
    admin_state_up = True
    device_owner = 'foo5'
    fixed_ips = [FakeIPAllocation('192.168.0.5',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:aa:bb:55'
    device_id = 'fake_port5'

    def __init__(self):
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name=edo_ext.CLIENT_ID,
                    opt_value='test5')]


class FakePort6(object):
    id = 'ccccccccc-cccc-cccc-cccc-ccccccccc'
    admin_state_up = True
    device_owner = 'foo6'
    fixed_ips = [FakeIPAllocation('192.168.0.6',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:aa:bb:66'
    device_id = 'fake_port6'

    def __init__(self):
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name=edo_ext.CLIENT_ID,
                    opt_value='test6',
                    ip_version=4),
            DhcpOpt(opt_name='dns-server',
                    opt_value='123.123.123.45',
                    ip_version=4)]


class FakeV6Port(object):
    id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
    admin_state_up = True
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('fdca:3ba5:a17a:4ba3::2',
                                  'ffffffff-ffff-ffff-ffff-ffffffffffff')]
    mac_address = '00:00:f3:aa:bb:cc'
    device_id = 'fake_port6'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakeV6PortExtraOpt(object):
    id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
    admin_state_up = True
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('ffea:3ba5:a17a:4ba3:0216:3eff:fec2:771d',
                                  'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
    mac_address = '00:16:3e:c2:77:1d'
    device_id = 'fake_port6'

    def __init__(self):
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name='dns-server',
                    opt_value='ffea:3ba5:a17a:4ba3::100',
                    ip_version=6)]


class FakeDualPortWithV6ExtraOpt(object):
    id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
    admin_state_up = True
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('192.168.0.3',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd'),
                 FakeIPAllocation('ffea:3ba5:a17a:4ba3:0216:3eff:fec2:771d',
                                  'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
    mac_address = '00:16:3e:c2:77:1d'
    device_id = 'fake_port6'

    def __init__(self):
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name='dns-server',
                    opt_value='ffea:3ba5:a17a:4ba3::100',
                    ip_version=6)]


class FakeDualPort(object):
    id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
    admin_state_up = True
    device_owner = 'foo3'
    fixed_ips = [FakeIPAllocation('192.168.0.3',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd'),
                 FakeIPAllocation('fdca:3ba5:a17a:4ba3::3',
                                  'ffffffff-ffff-ffff-ffff-ffffffffffff')]
    mac_address = '00:00:0f:aa:bb:cc'
    device_id = 'fake_dual_port'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakeRouterPort(object):
    id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_ROUTER_INTF
    mac_address = '00:00:0f:rr:rr:rr'
    device_id = 'fake_router_port'

    def __init__(self, dev_owner=constants.DEVICE_OWNER_ROUTER_INTF,
                 ip_address='192.168.0.1'):
        self.extra_dhcp_opts = []
        self.device_owner = dev_owner
        self.fixed_ips = [FakeIPAllocation(
            ip_address, 'dddddddd-dddd-dddd-dddd-dddddddddddd')]


class FakeRouterPort2(object):
    id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_ROUTER_INTF
    fixed_ips = [FakeIPAllocation('192.168.1.1',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:rr:rr:r2'
    device_id = 'fake_router_port2'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePortMultipleAgents1(object):
    id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_DHCP
    fixed_ips = [FakeIPAllocation('192.168.0.5',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:dd:dd:dd'
    device_id = 'fake_multiple_agents_port'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakePortMultipleAgents2(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    admin_state_up = True
    device_owner = constants.DEVICE_OWNER_DHCP
    fixed_ips = [FakeIPAllocation('192.168.0.6',
                                  'dddddddd-dddd-dddd-dddd-dddddddddddd')]
    mac_address = '00:00:0f:ee:ee:ee'
    device_id = 'fake_multiple_agents_port2'

    def __init__(self):
        self.extra_dhcp_opts = []


class FakeV4HostRoute(object):
    destination = '20.0.0.1/24'
    nexthop = '20.0.0.1'


class FakeV4HostRouteGateway(object):
    destination = constants.IPv4_ANY
    nexthop = '10.0.0.1'


class FakeV6HostRoute(object):
    destination = '2001:0200:feed:7ac0::/64'
    nexthop = '2001:0200:feed:7ac0::1'


class FakeV4Subnet(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    host_routes = [FakeV4HostRoute]
    dns_nameservers = ['8.8.8.8']


class FakeV4Subnet2(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = '192.168.1.1'
    enable_dhcp = True
    host_routes = []
    dns_nameservers = ['8.8.8.8']


class FakeV4MetadataSubnet(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '169.254.169.254/30'
    gateway_ip = '169.254.169.253'
    enable_dhcp = True
    host_routes = []
    dns_nameservers = []


class FakeV4SubnetGatewayRoute(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    host_routes = [FakeV4HostRouteGateway]
    dns_nameservers = ['8.8.8.8']


class FakeV4SubnetMultipleAgentsWithoutDnsProvided(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    dns_nameservers = []
    host_routes = []


class FakeV4MultipleAgentsWithoutDnsProvided(object):
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    subnets = [FakeV4SubnetMultipleAgentsWithoutDnsProvided()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
             FakePortMultipleAgents1(), FakePortMultipleAgents2()]
    namespace = 'qdhcp-ns'


class FakeV4SubnetMultipleAgentsWithDnsProvided(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    ip_version = 4
    cidr = '192.168.0.0/24'
    gateway_ip = '192.168.0.1'
    enable_dhcp = True
    dns_nameservers = ['8.8.8.8']
    host_routes = []


class FakeV4MultipleAgentsWithDnsProvided(object):
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    subnets = [FakeV4SubnetMultipleAgentsWithDnsProvided()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
             FakePortMultipleAgents1(), FakePortMultipleAgents2()]
    namespace = 'qdhcp-ns'


class FakeV6Subnet(object):
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    ip_version = 6
    cidr = 'fdca:3ba5:a17a:4ba3::/64'
    gateway_ip = 'fdca:3ba5:a17a:4ba3::1'
    enable_dhcp = True
    host_routes = [FakeV6HostRoute]
    dns_nameservers = ['2001:0200:feed:7ac0::1']
    ipv6_ra_mode = None
    ipv6_address_mode = None


class FakeV4SubnetNoDHCP(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = '192.168.1.1'
    enable_dhcp = False
    host_routes = []
    dns_nameservers = []


class FakeV6SubnetDHCPStateful(object):
    id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
    ip_version = 6
    cidr = 'fdca:3ba5:a17a:4ba3::/64'
    gateway_ip = 'fdca:3ba5:a17a:4ba3::1'
    enable_dhcp = True
    host_routes = [FakeV6HostRoute]
    dns_nameservers = ['2001:0200:feed:7ac0::1']
    ipv6_ra_mode = None
    ipv6_address_mode = constants.DHCPV6_STATEFUL


class FakeV6SubnetSlaac(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 6
    cidr = 'ffda:3ba5:a17a:4ba3::/64'
    gateway_ip = 'ffda:3ba5:a17a:4ba3::1'
    enable_dhcp = True
    host_routes = [FakeV6HostRoute]
    ipv6_address_mode = constants.IPV6_SLAAC
    ipv6_ra_mode = None


class FakeV6SubnetStateless(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 6
    cidr = 'ffea:3ba5:a17a:4ba3::/64'
    gateway_ip = 'ffea:3ba5:a17a:4ba3::1'
    enable_dhcp = True
    dns_nameservers = []
    host_routes = []
    ipv6_address_mode = constants.DHCPV6_STATELESS
    ipv6_ra_mode = None


class FakeV4SubnetNoGateway(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = None
    enable_dhcp = True
    host_routes = []
    dns_nameservers = []


class FakeV4SubnetNoRouter(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
    ip_version = 4
    cidr = '192.168.1.0/24'
    gateway_ip = '192.168.1.1'
    enable_dhcp = True
    host_routes = []
    dns_nameservers = []


class FakeV4Network(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1()]
    namespace = 'qdhcp-ns'


class FakeV4NetworkClientId(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakePort5(), FakePort6()]
    namespace = 'qdhcp-ns'


class FakeV6Network(object):
    id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    subnets = [FakeV6Subnet()]
    ports = [FakePort2()]
    namespace = 'qdhcp-ns'


class FakeDualNetwork(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV6SubnetDHCPStateful()]
    ports = [FakePort1(), FakeV6Port(), FakeDualPort(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class FakeNetworkDhcpPort(object):
    id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakeDhcpPort()]
    namespace = 'qdhcp-ns'


class FakeDualNetworkGatewayRoute(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetGatewayRoute(), FakeV6SubnetDHCPStateful()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class FakeDualNetworkSingleDHCP(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class FakeDualNetworkDualDHCP(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV4Subnet2()]
    ports = [FakePort1(), FakeRouterPort(), FakeRouterPort2()]
    namespace = 'qdhcp-ns'


class FakeV4NoGatewayNetwork(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoGateway()]
    ports = [FakePort1()]


class FakeV4NetworkNoRouter(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4SubnetNoRouter()]
    ports = [FakePort1()]


class FakeV4MetadataNetwork(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4MetadataSubnet()]
    ports = [FakeRouterPort(ip_address='169.254.169.253')]


class FakeV4NetworkDistRouter(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(),
             FakeRouterPort(dev_owner=constants.DEVICE_OWNER_DVR_INTERFACE)]


class FakeDualV4Pxe3Ports(object):
    id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self, port_detail="portsSame"):
        if port_detail == "portsSame":
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux2.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux3.0')]
        else:
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux2.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux3.0')]


class FakeV4NetworkPxe2Ports(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakePort2(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self, port_detail="portsSame"):
        if port_detail == "portsSame":
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
        else:
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]


class FakeV4NetworkPxe3Ports(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self, port_detail="portsSame"):
        if port_detail == "portsSame":
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.1.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.1.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
        else:
            self.ports[0].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0')]
            self.ports[1].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.5'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux2.0')]
            self.ports[2].extra_dhcp_opts = [
                DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.7'),
                DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux3.0')]


class FakeV6NetworkPxePort(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV6SubnetDHCPStateful()]
    ports = [FakeV6Port()]
    namespace = 'qdhcp-ns'

    def __init__(self):
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tftp-server', opt_value='2001:192:168::1',
                    ip_version=6),
            DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0',
                    ip_version=6)]


class FakeV6NetworkPxePortWrongOptVersion(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV6SubnetDHCPStateful()]
    ports = [FakeV6Port()]
    namespace = 'qdhcp-ns'

    def __init__(self):
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.7',
                    ip_version=4),
            DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0',
                    ip_version=6)]


class FakeDualStackNetworkSingleDHCP(object):
    id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'

    subnets = [FakeV4Subnet(), FakeV6SubnetSlaac()]
    ports = [FakePort1(), FakePort4(), FakeRouterPort()]


class FakeV4NetworkMultipleTags(object):
    id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
    subnets = [FakeV4Subnet()]
    ports = [FakePort1(), FakeRouterPort()]
    namespace = 'qdhcp-ns'

    def __init__(self):
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tag:ipxe,bootfile-name', opt_value='pxelinux.0')]


class FakeV6NetworkStatelessDHCP(object):
    id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'

    subnets = [FakeV6SubnetStateless()]
    ports = [FakeV6PortExtraOpt()]
    namespace = 'qdhcp-ns'


class FakeNetworkWithV6SatelessAndV4DHCPSubnets(object):
    id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'

    subnets = [FakeV6SubnetStateless(), FakeV4Subnet()]
    ports = [FakeDualPortWithV6ExtraOpt(), FakeRouterPort()]
    namespace = 'qdhcp-ns'


class LocalChild(dhcp.DhcpLocalProcess):
    PORTS = {4: [4], 6: [6]}

    def __init__(self, *args, **kwargs):
        self.process_monitor = mock.Mock()
        kwargs['process_monitor'] = self.process_monitor
        super(LocalChild, self).__init__(*args, **kwargs)
        self.called = []

    def reload_allocations(self):
        self.called.append('reload')

    def restart(self):
        self.called.append('restart')

    def spawn_process(self):
        self.called.append('spawn')


class TestBase(base.BaseTestCase):
    def setUp(self):
        super(TestBase, self).setUp()
        self.conf = config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(dhcp_config.DHCP_OPTS)
        self.conf.register_opts(dhcp_config.DNSMASQ_OPTS)
        self.conf.register_opts(external_process.OPTS)
        config.register_interface_driver_opts_helper(self.conf)
        config.register_use_namespaces_opts_helper(self.conf)
        instance = mock.patch("neutron.agent.linux.dhcp.DeviceManager")
        self.mock_mgr = instance.start()
        self.conf.register_opt(cfg.BoolOpt('enable_isolated_metadata',
                                           default=True))
        self.conf.register_opt(cfg.BoolOpt('enable_metadata_network',
                                           default=False))
        self.config_parse(self.conf)
        self.conf.set_override('state_path', '')

        self.replace_p = mock.patch('neutron.agent.linux.utils.replace_file')
        self.execute_p = mock.patch('neutron.agent.common.utils.execute')
        self.safe = self.replace_p.start()
        self.execute = self.execute_p.start()

        self.makedirs = mock.patch('os.makedirs').start()
        self.rmtree = mock.patch('shutil.rmtree').start()

        self.external_process = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager').start()


class TestDhcpBase(TestBase):

    def test_existing_dhcp_networks_abstract_error(self):
        self.assertRaises(NotImplementedError,
                          dhcp.DhcpBase.existing_dhcp_networks,
                          None)

    def test_check_version_abstract_error(self):
        self.assertRaises(NotImplementedError,
                          dhcp.DhcpBase.check_version)

    def test_base_abc_error(self):
        self.assertRaises(TypeError, dhcp.DhcpBase, None)

    def test_restart(self):
        class SubClass(dhcp.DhcpBase):
            def __init__(self):
                dhcp.DhcpBase.__init__(self, cfg.CONF, FakeV4Network(),
                                       mock.Mock(), None)
                self.called = []

            def enable(self):
                self.called.append('enable')

            def disable(self, retain_port=False):
                self.called.append('disable %s' % retain_port)

            def reload_allocations(self):
                pass

            @property
            def active(self):
                return True

        c = SubClass()
        c.restart()
        self.assertEqual(c.called, ['disable True', 'enable'])


class TestDhcpLocalProcess(TestBase):

    def test_get_conf_file_name(self):
        tpl = '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/dev'
        lp = LocalChild(self.conf, FakeV4Network())
        self.assertEqual(lp.get_conf_file_name('dev'), tpl)

    @mock.patch.object(utils, 'ensure_dir')
    def test_ensure_dir_called(self, ensure_dir):
        LocalChild(self.conf, FakeV4Network())
        ensure_dir.assert_called_once_with(
            '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')

    def test_enable_already_active(self):
        with mock.patch.object(LocalChild, 'active') as patched:
            patched.__get__ = mock.Mock(return_value=True)
            lp = LocalChild(self.conf, FakeV4Network())
            lp.enable()

            self.assertEqual(lp.called, ['restart'])
            self.assertFalse(self.mock_mgr.return_value.setup.called)

    @mock.patch.object(utils, 'ensure_dir')
    def test_enable(self, ensure_dir):
        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
                ['active', 'interface_name']]
        )

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['interface_name'].__set__ = mock.Mock()
            lp = LocalChild(self.conf,
                            FakeDualNetwork())
            lp.enable()

            self.mock_mgr.assert_has_calls(
                [mock.call(self.conf, None),
                 mock.call().setup(mock.ANY)])
            self.assertEqual(lp.called, ['spawn'])
            self.assertTrue(mocks['interface_name'].__set__.called)
            ensure_dir.assert_called_with(
                '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc')

    def _assert_disabled(self, lp):
        self.assertTrue(lp.process_monitor.unregister.called)
        self.assertTrue(self.external_process().disable.called)

    def test_disable_not_active(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name']])
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            network = FakeDualNetwork()
            lp = LocalChild(self.conf, network)
            lp.device_manager = mock.Mock()
            lp.disable()
            lp.device_manager.destroy.assert_called_once_with(
                network, 'tap0')
            self._assert_disabled(lp)

    def test_disable_retain_port(self):
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name']])
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network)
            lp.disable(retain_port=True)
            self._assert_disabled(lp)

    def test_disable(self):
        self.conf.set_override('dhcp_delete_namespaces', False)
        attrs_to_mock = dict([(a, mock.DEFAULT) for a in
                              ['active', 'interface_name']])
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network)
            with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip:
                lp.disable()

            self._assert_disabled(lp)

        self.mock_mgr.assert_has_calls([mock.call(self.conf, None),
                                        mock.call().destroy(network, 'tap0')])

        self.assertEqual(ip.return_value.netns.delete.call_count, 0)

    def test_disable_delete_ns(self):
        attrs_to_mock = {'active': mock.DEFAULT}

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch('neutron.agent.linux.ip_lib.IPWrapper') as ip:
                lp.disable()

            self._assert_disabled(lp)

        ip.return_value.netns.delete.assert_called_with('qdhcp-ns')

    def test_disable_config_dir_removed_after_destroy(self):
        parent = mock.MagicMock()
        parent.attach_mock(self.rmtree, 'rmtree')
        parent.attach_mock(self.mock_mgr, 'DeviceManager')

        lp = LocalChild(self.conf, FakeDualNetwork())
        lp.disable(retain_port=False)

        expected = [mock.call.DeviceManager().destroy(mock.ANY, mock.ANY),
                    mock.call.rmtree(mock.ANY, ignore_errors=True)]
        parent.assert_has_calls(expected)

    def test_get_interface_name(self):
        with mock.patch('six.moves.builtins.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.read.return_value = 'tap0'
            lp = LocalChild(self.conf, FakeDualNetwork())
            self.assertEqual(lp.interface_name, 'tap0')

    def test_set_interface_name(self):
        with mock.patch('neutron.agent.linux.utils.replace_file') as replace:
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch.object(lp, 'get_conf_file_name') as conf_file:
                conf_file.return_value = '/interface'
                lp.interface_name = 'tap0'
                conf_file.assert_called_once_with('interface')
                replace.assert_called_once_with(mock.ANY, 'tap0')


class TestDnsmasq(TestBase):

    def _get_dnsmasq(self, network, process_monitor=None):
        process_monitor = process_monitor or mock.Mock()
        return dhcp.Dnsmasq(self.conf, network,
                            process_monitor=process_monitor)

    def _test_spawn(self, extra_options, network=FakeDualNetwork(),
                    max_leases=16777216, lease_duration=86400,
                    has_static=True):
        def mock_get_conf_file_name(kind):
            return '/dhcp/%s/%s' % (network.id, kind)

        # if you need to change this path here, think twice,
        # that means pid files will move around, breaking upgrades
        # or backwards-compatibility
        expected_pid_file = '/dhcp/%s/pid' % network.id

        expected = [
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=tap0',
            '--except-interface=lo',
            '--pid-file=%s' % expected_pid_file,
            '--dhcp-hostsfile=/dhcp/%s/host' % network.id,
            '--addn-hosts=/dhcp/%s/addn_hosts' % network.id,
            '--dhcp-optsfile=/dhcp/%s/opts' % network.id,
            '--dhcp-leasefile=/dhcp/%s/leases' % network.id,
            '--dhcp-match=set:ipxe,175']

        seconds = ''
        if lease_duration == -1:
            lease_duration = 'infinite'
        else:
            seconds = 's'
        if has_static:
            prefix = '--dhcp-range=set:tag%d,%s,static,%s%s'
            prefix6 = '--dhcp-range=set:tag%d,%s,static,%s,%s%s'
        else:
            prefix = '--dhcp-range=set:tag%d,%s,%s%s'
            prefix6 = '--dhcp-range=set:tag%d,%s,%s,%s%s'
        possible_leases = 0
        for i, s in enumerate(network.subnets):
            if (s.ip_version != 6
                or s.ipv6_address_mode == constants.DHCPV6_STATEFUL):
                if s.ip_version == 4:
                    expected.extend([prefix % (
                        i, s.cidr.split('/')[0], lease_duration, seconds)])
                else:
                    expected.extend([prefix6 % (
                        i, s.cidr.split('/')[0], s.cidr.split('/')[1],
                        lease_duration, seconds)])
                possible_leases += netaddr.IPNetwork(s.cidr).size

        if cfg.CONF.advertise_mtu:
            expected.append('--dhcp-option-force=option:mtu,%s' % network.mtu)

        expected.append('--dhcp-lease-max=%d' % min(
            possible_leases, max_leases))
        expected.extend(extra_options)

        self.execute.return_value = ('', '')

        attrs_to_mock = dict(
            [(a, mock.DEFAULT) for a in
                ['_output_opts_file', 'get_conf_file_name', 'interface_name']]
        )

        test_pm = mock.Mock()

        with mock.patch.multiple(dhcp.Dnsmasq, **attrs_to_mock) as mocks:
            mocks['get_conf_file_name'].side_effect = mock_get_conf_file_name
            mocks['_output_opts_file'].return_value = (
                '/dhcp/%s/opts' % network.id
            )
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')

            dm = self._get_dnsmasq(network, test_pm)
            dm.spawn_process()
            self.assertTrue(mocks['_output_opts_file'].called)

            self.assertTrue(test_pm.register.called)
            self.external_process().enable.assert_called_once_with(
                reload_cfg=False)
            call_kwargs = self.external_process.mock_calls[0][2]
            cmd_callback = call_kwargs['default_cmd_callback']

            result_cmd = cmd_callback(expected_pid_file)

            self.assertEqual(expected, result_cmd)

    def test_spawn(self):
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'])

    def test_spawn_infinite_lease_duration(self):
        self.conf.set_override('dhcp_lease_duration', -1)
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         FakeDualNetwork(), 16777216, -1)

    def test_spawn_cfg_config_file(self):
        self.conf.set_override('dnsmasq_config_file', '/foo')
        self._test_spawn(['--conf-file=/foo', '--domain=openstacklocal'])

    def test_spawn_no_dhcp_domain(self):
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data) = self._test_no_dhcp_domain_alloc_data
        self.conf.set_override('dhcp_domain', '')
        self._test_spawn(['--conf-file='])
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_addn_name, exp_addn_data)])

    def test_spawn_no_dhcp_range(self):
        network = FakeV6Network()
        subnet = FakeV6SubnetSlaac()
        network.subnets = [subnet]
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         network, has_static=False)

    def test_spawn_cfg_dns_server(self):
        self.conf.set_override('dnsmasq_dns_servers', ['8.8.8.8'])
        self._test_spawn(['--conf-file=',
                          '--server=8.8.8.8',
                          '--domain=openstacklocal'])

    def test_spawn_cfg_multiple_dns_server(self):
        self.conf.set_override('dnsmasq_dns_servers', ['8.8.8.8',
                                                       '9.9.9.9'])
        self._test_spawn(['--conf-file=',
                          '--server=8.8.8.8',
                          '--server=9.9.9.9',
                          '--domain=openstacklocal'])

    def test_spawn_max_leases_is_smaller_than_cap(self):
        self._test_spawn(
            ['--conf-file=', '--domain=openstacklocal'],
            network=FakeV4Network(),
            max_leases=256)

    def test_spawn_cfg_broadcast(self):
        self.conf.set_override('dhcp_broadcast_reply', True)
        self._test_spawn(['--conf-file=', '--domain=openstacklocal',
                          '--dhcp-broadcast'])

    def test_spawn_cfg_advertise_mtu(self):
        cfg.CONF.set_override('advertise_mtu', True)
        network = FakeV4Network()
        network.mtu = 1500
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         network)

    def _test_output_init_lease_file(self, timestamp):
        expected = [
            '00:00:80:aa:bb:cc 192.168.0.2 * *',
            '00:00:f3:aa:bb:cc [fdca:3ba5:a17a:4ba3::2] * *',
            '00:00:0f:aa:bb:cc 192.168.0.3 * *',
            '00:00:0f:aa:bb:cc [fdca:3ba5:a17a:4ba3::3] * *',
            '00:00:0f:rr:rr:rr 192.168.0.1 * *\n']
        expected = "\n".join(['%s %s' % (timestamp, l) for l in expected])
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/leases'
            dm = self._get_dnsmasq(FakeDualNetwork())
            dm._output_init_lease_file()
        self.safe.assert_called_once_with('/foo/leases', expected)

    @mock.patch('time.time')
    def test_output_init_lease_file(self, tmock):
        self.conf.set_override('dhcp_lease_duration', 500)
        tmock.return_value = 1000000
        # lease duration should be added to current time
        timestamp = 1000000 + 500
        self._test_output_init_lease_file(timestamp)

    def test_output_init_lease_file_infinite_duration(self):
        self.conf.set_override('dhcp_lease_duration', -1)
        # when duration is infinite, lease db timestamp should be 0
        timestamp = 0
        self._test_output_init_lease_file(timestamp)

    def _test_output_opts_file(self, expected, network, ipm_retval=None):
        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = self._get_dnsmasq(network)
            if ipm_retval:
                with mock.patch.object(
                        dm, '_make_subnet_interface_ip_map') as ipm:
                    ipm.return_value = ipm_retval
                    dm._output_opts_file()
                    self.assertTrue(ipm.called)
            else:
                dm._output_opts_file()
        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file(self):
        fake_v6 = '2001:0200:feed:7ac0::1'
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:tag1,option6:dns-server,%s\n'
            'tag:tag1,option6:domain-search,openstacklocal').lstrip() % (
                '[' + fake_v6 + ']')

        self._test_output_opts_file(expected, FakeDualNetwork())

    def test_output_opts_file_gateway_route(self):
        fake_v6 = '2001:0200:feed:7ac0::1'
        expected = ('tag:tag0,option:dns-server,8.8.8.8\n'
                    'tag:tag0,option:classless-static-route,'
                    '169.254.169.254/32,192.168.0.1,0.0.0.0/0,'
                    '192.168.0.1\ntag:tag0,249,169.254.169.254/32,'
                    '192.168.0.1,0.0.0.0/0,192.168.0.1\n'
                    'tag:tag0,option:router,192.168.0.1\n'
                    'tag:tag1,option6:dns-server,%s\n'
                    'tag:tag1,option6:domain-search,'
                    'openstacklocal').lstrip() % ('[' + fake_v6 + ']')

        self._test_output_opts_file(expected, FakeDualNetworkGatewayRoute())

    def test_output_opts_file_multiple_agents_without_dns_provided(self):
        expected = ('tag:tag0,option:classless-static-route,'
                    '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
                    'tag:tag0,249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,'
                    '192.168.0.1\ntag:tag0,option:router,192.168.0.1\n'
                    'tag:tag0,option:dns-server,192.168.0.5,'
                    '192.168.0.6').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4MultipleAgentsWithoutDnsProvided())

    def test_output_opts_file_multiple_agents_with_dns_provided(self):
        expected = ('tag:tag0,option:dns-server,8.8.8.8\n'
                    'tag:tag0,option:classless-static-route,'
                    '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
                    'tag:tag0,249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,'
                    '192.168.0.1\n'
                    'tag:tag0,option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4MultipleAgentsWithDnsProvided())

    def test_output_opts_file_single_dhcp(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,'
            '192.168.1.0/24,0.0.0.0,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,192.168.1.0/24,0.0.0.0,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected, FakeDualNetworkSingleDHCP())

    def test_output_opts_file_dual_dhcp_rfc3442(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,'
            '192.168.1.0/24,0.0.0.0,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,192.168.1.0/24,0.0.0.0,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:tag1,option:dns-server,8.8.8.8\n'
            'tag:tag1,option:classless-static-route,'
            '169.254.169.254/32,192.168.1.1,'
            '192.168.0.0/24,0.0.0.0,0.0.0.0/0,192.168.1.1\n'
            'tag:tag1,249,169.254.169.254/32,192.168.1.1,'
            '192.168.0.0/24,0.0.0.0,0.0.0.0/0,192.168.1.1\n'
            'tag:tag1,option:router,192.168.1.1').lstrip()

        self._test_output_opts_file(expected, FakeDualNetworkDualDHCP())

    def test_output_opts_file_no_gateway(self):
        expected = (
            'tag:tag0,option:classless-static-route,'
            '169.254.169.254/32,192.168.1.1\n'
            'tag:tag0,249,169.254.169.254/32,192.168.1.1\n'
            'tag:tag0,option:router').lstrip()

        ipm_retval = {FakeV4SubnetNoGateway.id: '192.168.1.1'}
        self._test_output_opts_file(expected, FakeV4NoGatewayNetwork(),
                                    ipm_retval=ipm_retval)

    def test_output_opts_file_no_neutron_router_on_subnet(self):
        expected = (
            'tag:tag0,option:classless-static-route,'
            '169.254.169.254/32,192.168.1.2,0.0.0.0/0,192.168.1.1\n'
            'tag:tag0,249,169.254.169.254/32,192.168.1.2,'
            '0.0.0.0/0,192.168.1.1\n'
            'tag:tag0,option:router,192.168.1.1').lstrip()

        ipm_retval = {FakeV4SubnetNoRouter.id: '192.168.1.2'}
        self._test_output_opts_file(expected, FakeV4NetworkNoRouter(),
                                    ipm_retval=ipm_retval)

    def test_output_opts_file_dist_neutron_router_on_subnet(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1').lstrip()

        ipm_retval = {FakeV4Subnet.id: '192.168.0.1'}
        self._test_output_opts_file(expected, FakeV4NetworkDistRouter(),
                                    ipm_retval=ipm_retval)

    def test_output_opts_file_pxe_2port_1net(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:tftp-server,192.168.0.3\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:bootfile-name,pxelinux.0').lstrip()

        self._test_output_opts_file(expected, FakeV4NetworkPxe2Ports())

    def test_output_opts_file_pxe_2port_1net_diff_details(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:tftp-server,192.168.0.5\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:server-ip-address,192.168.0.5\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:bootfile-name,pxelinux.0').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4NetworkPxe2Ports("portsDiff"))

    def test_output_opts_file_pxe_3port_2net(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,'
            '192.168.1.0/24,0.0.0.0,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,192.168.1.0/24,0.0.0.0,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:tftp-server,192.168.1.3\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:server-ip-address,192.168.1.2\n'
            'tag:ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:bootfile-name,pxelinux2.0\n'
            'tag:44444444-4444-4444-4444-444444444444,'
            'option:tftp-server,192.168.1.3\n'
            'tag:44444444-4444-4444-4444-444444444444,'
            'option:server-ip-address,192.168.1.2\n'
            'tag:44444444-4444-4444-4444-444444444444,'
            'option:bootfile-name,pxelinux3.0').lstrip()

        self._test_output_opts_file(expected, FakeDualV4Pxe3Ports())

    def test_output_opts_file_multiple_tags(self):
        expected = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'tag:ipxe,option:bootfile-name,pxelinux.0')
        expected = expected.lstrip()

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/opts'
            dm = self._get_dnsmasq(FakeV4NetworkMultipleTags())
            dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    @mock.patch('neutron.agent.linux.dhcp.Dnsmasq.get_conf_file_name',
                return_value='/foo/opts')
    def test_output_opts_file_pxe_ipv6_port_with_ipv6_opt(self,
                                                          mock_get_conf_fn):
        expected = (
            'tag:tag0,option6:dns-server,[2001:0200:feed:7ac0::1]\n'
            'tag:tag0,option6:domain-search,openstacklocal\n'
            'tag:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:tftp-server,2001:192:168::1\n'
            'tag:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:bootfile-name,pxelinux.0')
        expected = expected.lstrip()

        dm = self._get_dnsmasq(FakeV6NetworkPxePort())
        dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    @mock.patch('neutron.agent.linux.dhcp.Dnsmasq.get_conf_file_name',
                return_value='/foo/opts')
    def test_output_opts_file_pxe_ipv6_port_with_ipv4_opt(self,
                                                          mock_get_conf_fn):
        expected = (
            'tag:tag0,option6:dns-server,[2001:0200:feed:7ac0::1]\n'
            'tag:tag0,option6:domain-search,openstacklocal\n'
            'tag:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:bootfile-name,pxelinux.0')
        expected = expected.lstrip()

        dm = self._get_dnsmasq(FakeV6NetworkPxePortWrongOptVersion())
        dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    @property
    def _test_no_dhcp_domain_alloc_data(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--2,'
                         '[fdca:3ba5:a17a:4ba3::2]\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-3,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--3,'
                         '[fdca:3ba5:a17a:4ba3::3]\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1,'
                         '192.168.0.1\n').lstrip()
        exp_addn_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/addn_hosts'
        exp_addn_data = (
            '192.168.0.2\t'
            'host-192-168-0-2 host-192-168-0-2\n'
            'fdca:3ba5:a17a:4ba3::2\t'
            'host-fdca-3ba5-a17a-4ba3--2 '
            'host-fdca-3ba5-a17a-4ba3--2\n'
            '192.168.0.3\thost-192-168-0-3 '
            'host-192-168-0-3\n'
            'fdca:3ba5:a17a:4ba3::3\t'
            'host-fdca-3ba5-a17a-4ba3--3 '
            'host-fdca-3ba5-a17a-4ba3--3\n'
            '192.168.0.1\t'
            'host-192-168-0-1 '
            'host-192-168-0-1\n'
        ).lstrip()
        return (exp_host_name, exp_host_data,
                exp_addn_name, exp_addn_data)

    @property
    def _test_reload_allocation_data(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--2.'
                         'openstacklocal,[fdca:3ba5:a17a:4ba3::2]\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-3.openstacklocal,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--3.'
                         'openstacklocal,[fdca:3ba5:a17a:4ba3::3]\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal,'
                         '192.168.0.1\n').lstrip()
        exp_addn_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/addn_hosts'
        exp_addn_data = (
            '192.168.0.2\t'
            'host-192-168-0-2.openstacklocal host-192-168-0-2\n'
            'fdca:3ba5:a17a:4ba3::2\t'
            'host-fdca-3ba5-a17a-4ba3--2.openstacklocal '
            'host-fdca-3ba5-a17a-4ba3--2\n'
            '192.168.0.3\thost-192-168-0-3.openstacklocal '
            'host-192-168-0-3\n'
            'fdca:3ba5:a17a:4ba3::3\t'
            'host-fdca-3ba5-a17a-4ba3--3.openstacklocal '
            'host-fdca-3ba5-a17a-4ba3--3\n'
            '192.168.0.1\t'
            'host-192-168-0-1.openstacklocal '
            'host-192-168-0-1\n'
        ).lstrip()
        exp_opt_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
        fake_v6 = '2001:0200:feed:7ac0::1'
        exp_opt_data = (
            'tag:tag0,option:dns-server,8.8.8.8\n'
            'tag:tag0,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag0,option:router,192.168.0.1\n'
            'tag:tag1,option6:dns-server,%s\n'
            'tag:tag1,option6:domain-search,openstacklocal').lstrip() % (
            '[' + fake_v6 + ']')
        return (exp_host_name, exp_host_data,
                exp_addn_name, exp_addn_data,
                exp_opt_name, exp_opt_data,)

    def test_reload_allocations(self):
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data,
         exp_opt_name, exp_opt_data,) = self._test_reload_allocation_data

        with mock.patch('six.moves.builtins.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            mock_open.return_value.readline.return_value = None

            test_pm = mock.Mock()
            dm = self._get_dnsmasq(FakeDualNetwork(), test_pm)
            dm.reload_allocations()
            self.assertTrue(test_pm.register.called)
            self.external_process().enable.assert_called_once_with(
                reload_cfg=True)

            self.safe.assert_has_calls([
                mock.call(exp_host_name, exp_host_data),
                mock.call(exp_addn_name, exp_addn_data),
                mock.call(exp_opt_name, exp_opt_data),
            ])

    def test_release_unused_leases(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.1.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.1.3'
        mac2 = '00:00:80:cc:bb:aa'

        old_leases = set([(ip1, mac1, None), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = []
        dnsmasq.device_manager.driver.unplug = mock.Mock()

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_has_calls([mock.call(mac1, ip1, None),
                                                 mock.call(mac2, ip2, None)],
                                                any_order=True)
        dnsmasq.device_manager.driver.unplug.assert_has_calls(
            [mock.call(dnsmasq.interface_name,
                       namespace=dnsmasq.network.namespace)])

    def test_release_unused_leases_with_dhcp_port(self):
        dnsmasq = self._get_dnsmasq(FakeNetworkDhcpPort())
        ip1 = '192.168.1.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.1.3'
        mac2 = '00:00:80:cc:bb:aa'

        old_leases = set([(ip1, mac1, None), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.device_manager.get_device_id = mock.Mock(
            return_value='fake_dhcp_port')
        dnsmasq._release_unused_leases()
        self.assertFalse(
            dnsmasq.device_manager.driver.unplug.called)

    def test_release_unused_leases_with_client_id(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.1.2'
        mac1 = '00:00:80:aa:bb:cc'
        client_id1 = 'client1'
        ip2 = '192.168.1.3'
        mac2 = '00:00:80:cc:bb:aa'
        client_id2 = 'client2'

        old_leases = set([(ip1, mac1, client_id1), (ip2, mac2, client_id2)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = []

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_has_calls(
            [mock.call(mac1, ip1, client_id1),
             mock.call(mac2, ip2, client_id2)],
            any_order=True)

    def test_release_unused_leases_one_lease(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.0.3'
        mac2 = '00:00:80:cc:bb:aa'

        old_leases = set([(ip1, mac1, None), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort1()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_called_once_with(
            mac2, ip2, None)

    def test_release_unused_leases_one_lease_with_client_id(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        client_id1 = 'client1'
        ip2 = '192.168.0.5'
        mac2 = '00:00:0f:aa:bb:55'
        client_id2 = 'test5'

        old_leases = set([(ip1, mac1, client_id1), (ip2, mac2, client_id2)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort5()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_called_once_with(
            mac1, ip1, client_id1)

    def test_read_hosts_file_leases(self):
        filename = '/path/to/file'
        with mock.patch('six.moves.builtins.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            lines = ["00:00:80:aa:bb:cc,inst-name,192.168.0.1",
                     "00:00:80:aa:bb:cc,inst-name,[fdca:3ba5:a17a::1]"]
            mock_open.return_value.readlines.return_value = lines

            dnsmasq = self._get_dnsmasq(FakeDualNetwork())
            leases = dnsmasq._read_hosts_file_leases(filename)

        self.assertEqual(set([("192.168.0.1", "00:00:80:aa:bb:cc", None),
                              ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc",
                               None)]), leases)
        mock_open.assert_called_once_with(filename)

    def test_read_hosts_file_leases_with_client_id(self):
        filename = '/path/to/file'
        with mock.patch('six.moves.builtins.open') as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = mock.Mock()
            lines = ["00:00:80:aa:bb:cc,id:client1,inst-name,192.168.0.1",
                     "00:00:80:aa:bb:cc,id:client2,inst-name,"
                     "[fdca:3ba5:a17a::1]"]
            mock_open.return_value.readlines.return_value = lines

            dnsmasq = self._get_dnsmasq(FakeDualNetwork())
            leases = dnsmasq._read_hosts_file_leases(filename)

        self.assertEqual(set([("192.168.0.1", "00:00:80:aa:bb:cc", 'client1'),
                              ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc",
                               'client2')]), leases)
        mock_open.assert_called_once_with(filename)

    def test_read_hosts_file_leases_with_stateless_IPv6_tag(self):
        filename = self.get_temp_file_path('leases')
        with open(filename, "w") as leasesfile:
            lines = [
                "00:00:80:aa:bb:cc,id:client1,inst-name,192.168.0.1\n",
                "00:00:80:aa:bb:cc,set:ccccccccc-cccc-cccc-cccc-cccccccc\n",
                "00:00:80:aa:bb:cc,id:client2,inst-name,[fdca:3ba5:a17a::1]\n"]
            for line in lines:
                leasesfile.write(line)

        dnsmasq = self._get_dnsmasq(FakeDualNetwork())
        leases = dnsmasq._read_hosts_file_leases(filename)

        self.assertEqual(set([("192.168.0.1", "00:00:80:aa:bb:cc", 'client1'),
                              ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc",
                              'client2')]), leases)

    def test_make_subnet_interface_ip_map(self):
        with mock.patch('neutron.agent.linux.ip_lib.IPDevice') as ip_dev:
            ip_dev.return_value.addr.list.return_value = [
                {'cidr': '192.168.0.1/24'}
            ]

            dm = self._get_dnsmasq(FakeDualNetwork())

            self.assertEqual(
                dm._make_subnet_interface_ip_map(),
                {FakeV4Subnet.id: '192.168.0.1'}
            )

    def test_remove_config_files(self):
        net = FakeV4Network()
        path = '/opt/data/neutron/dhcp'
        self.conf.dhcp_confs = path
        lp = LocalChild(self.conf, net)
        lp._remove_config_files()
        self.rmtree.assert_called_once_with(os.path.join(path, net.id),
                                            ignore_errors=True)

    def test_existing_dhcp_networks(self):
        path = '/opt/data/neutron/dhcp'
        self.conf.dhcp_confs = path

        cases = {
            # network_uuid --> is_dhcp_alive?
            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa': True,
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb': False,
            'not_uuid_like_name': True
        }

        def active_fake(self, instance, cls):
            return cases[instance.network.id]

        with mock.patch('os.listdir') as mock_listdir:
            with mock.patch.object(dhcp.Dnsmasq, 'active') as mock_active:
                mock_active.__get__ = active_fake
                mock_listdir.return_value = cases.keys()

                result = dhcp.Dnsmasq.existing_dhcp_networks(self.conf)

                mock_listdir.assert_called_once_with(path)
                self.assertEqual(['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                  'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'],
                                 sorted(result))

    def test__output_hosts_file_log_only_twice(self):
        dm = self._get_dnsmasq(FakeDualStackNetworkSingleDHCP())
        with mock.patch.object(dhcp, 'LOG') as logger:
            logger.process.return_value = ('fake_message', {})
            dm._output_hosts_file()
        # The method logs twice, at the start of and the end. There should be
        # no other logs, no matter how many hosts there are to dump in the
        # file.
        self.assertEqual(2, len(logger.method_calls))

    def test_only_populates_dhcp_enabled_subnets(self):
        exp_host_name = '/dhcp/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal,'
                         '192.168.0.2\n'
                         '00:16:3E:C2:77:1D,host-192-168-0-4.openstacklocal,'
                         '192.168.0.4\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal,'
                         '192.168.0.1\n').lstrip()
        dm = self._get_dnsmasq(FakeDualStackNetworkSingleDHCP())
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name,
                                              exp_host_data)])

    def test_only_populates_dhcp_client_id(self):
        exp_host_name = '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal,'
                         '192.168.0.2\n'
                         '00:00:0f:aa:bb:55,id:test5,'
                         'host-192-168-0-5.openstacklocal,'
                         '192.168.0.5\n'
                         '00:00:0f:aa:bb:66,id:test6,'
                         'host-192-168-0-6.openstacklocal,192.168.0.6,'
                         'set:ccccccccc-cccc-cccc-cccc-ccccccccc\n').lstrip()

        dm = self._get_dnsmasq(FakeV4NetworkClientId)
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name,
                                              exp_host_data)])

    def test_only_populates_dhcp_enabled_subnet_on_a_network(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,host-192-168-0-3.openstacklocal,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-4.openstacklocal,'
                         '192.168.0.4\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal,'
                         '192.168.0.1\n').lstrip()
        dm = self._get_dnsmasq(FakeDualNetworkSingleDHCP())
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name,
                                              exp_host_data)])

    def test_host_and_opts_file_on_stateless_dhcpv6_network(self):
        exp_host_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/host'
        exp_host_data = ('00:16:3e:c2:77:1d,'
                         'set:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n').lstrip()
        exp_opt_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/opts'
        exp_opt_data = ('tag:tag0,option6:domain-search,openstacklocal\n'
                        'tag:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
                        'option6:dns-server,ffea:3ba5:a17a:4ba3::100').lstrip()
        dm = self._get_dnsmasq(FakeV6NetworkStatelessDHCP())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

    def test_host_and_opts_file_on_net_with_V6_stateless_and_V4_subnets(
                                                                    self):
        exp_host_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/host'
        exp_host_data = (
            '00:16:3e:c2:77:1d,set:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n'
            '00:16:3e:c2:77:1d,host-192-168-0-3.openstacklocal,'
            '192.168.0.3,set:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n'
            '00:00:0f:rr:rr:rr,'
            'host-192-168-0-1.openstacklocal,192.168.0.1\n').lstrip()
        exp_opt_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/opts'
        exp_opt_data = (
            'tag:tag0,option6:domain-search,openstacklocal\n'
            'tag:tag1,option:dns-server,8.8.8.8\n'
            'tag:tag1,option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag1,249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,'
            '192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:tag1,option:router,192.168.0.1\n'
            'tag:hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:dns-server,ffea:3ba5:a17a:4ba3::100').lstrip()

        dm = self._get_dnsmasq(FakeNetworkWithV6SatelessAndV4DHCPSubnets())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

    def test_should_enable_metadata_namespaces_disabled_returns_false(self):
        self.conf.set_override('use_namespaces', False)
        self.assertFalse(dhcp.Dnsmasq.should_enable_metadata(self.conf,
                                                             mock.ANY))

    def test_should_enable_metadata_isolated_network_returns_true(self):
        self.assertTrue(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4NetworkNoRouter()))

    def test_should_enable_metadata_non_isolated_network_returns_false(self):
        self.assertFalse(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4NetworkDistRouter()))

    def test_should_enable_metadata_isolated_meta_disabled_returns_false(self):
        self.conf.set_override('enable_isolated_metadata', False)
        self.assertFalse(dhcp.Dnsmasq.should_enable_metadata(self.conf,
                                                             mock.ANY))

    def test_should_enable_metadata_with_metadata_network_returns_true(self):
        self.conf.set_override('enable_metadata_network', True)
        self.assertTrue(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4MetadataNetwork()))
