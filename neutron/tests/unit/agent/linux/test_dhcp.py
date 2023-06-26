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

import copy
import os
from unittest import mock

import netaddr
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib import fixture as lib_fixtures
from oslo_config import cfg
import oslo_messaging
from oslo_utils import fileutils
from oslo_utils import netutils
from oslo_utils import uuidutils
import testtools

from neutron.agent.linux import dhcp
from neutron.agent.linux import ip_lib
from neutron.cmd import runtime_checks as checks
from neutron.common import _constants as common_constants
from neutron.conf.agent import common as config
from neutron.conf.agent import dhcp as dhcp_config
from neutron.conf import common as base_config
from neutron.privileged.agent.linux import dhcp as priv_dhcp
from neutron.tests import base


class FakeIPAllocation(object):
    def __init__(self, address, subnet_id=None):
        self.ip_address = address
        self.subnet_id = subnet_id


class FakeDNSAssignment(object):
    def __init__(self, ip_address, dns_name='', domain='openstacklocal'):
        if dns_name:
            self.hostname = dns_name
        else:
            self.hostname = 'host-%s' % ip_address.replace(
                '.', '-').replace(':', '-')
        self.ip_address = ip_address
        self.fqdn = self.hostname
        if domain:
            self.fqdn = '%s.%s.' % (self.hostname, domain)


class DhcpOpt(object):
    def __init__(self, **kwargs):
        self.__dict__.update(ip_version=constants.IP_VERSION_4)
        self.__dict__.update(kwargs)

    def __str__(self):
        return str(self.__dict__)


# A base class where class attributes can also be accessed by treating
# an instance as a dict.
class Dictable(object):
    def __getitem__(self, k):
        return self.__class__.__dict__.get(k)


class FakeDhcpPort(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_DHCP
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.1',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.mac_address = '00:00:80:aa:bb:ee'
        self.device_id = 'fake_dhcp_port'
        self.extra_dhcp_opts = []


class FakeOvnMetadataPort(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_DISTRIBUTED
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.10',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.mac_address = '00:00:80:aa:bb:ee'
        self.device_id = 'ovnmeta-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.extra_dhcp_opts = []


class FakeReservedPort(object):
    def __init__(self, id='reserved-aaaa-aaaa-aaaa-aaaaaaaaaaa'):
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_DHCP
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.6',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd'),
            FakeIPAllocation('fdca:3ba5:a17a:4ba3::2',
                             'ffffffff-ffff-ffff-ffff-ffffffffffff')]
        self.mac_address = '00:00:80:aa:bb:ee'
        self.device_id = constants.DEVICE_ID_RESERVED_DHCP_PORT
        self.extra_dhcp_opts = []
        self.id = id


class FakePort1(object):
    def __init__(self, domain='openstacklocal'):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.admin_state_up = True
        self.device_owner = 'foo1'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.2',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.mac_address = '00:00:80:aa:bb:cc'
        self.device_id = 'fake_port1'
        self.extra_dhcp_opts = []
        self.dns_assignment = [FakeDNSAssignment('192.168.0.2', domain=domain)]


class FakePort2(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.admin_state_up = False
        self.device_owner = 'foo2'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.3',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.mac_address = '00:00:f3:aa:bb:cc'
        self.device_id = 'fake_port2'
        self.dns_assignment = [FakeDNSAssignment('192.168.0.3')]
        self.extra_dhcp_opts = []


class FakePort3(object):
    def __init__(self):
        self.id = '44444444-4444-4444-4444-444444444444'
        self.admin_state_up = True
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.4',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd'),
            FakeIPAllocation('192.168.1.2',
                             'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
        self.dns_assignment = [FakeDNSAssignment('192.168.0.4'),
                               FakeDNSAssignment('192.168.1.2')]
        self.mac_address = '00:00:0f:aa:bb:cc'
        self.device_id = 'fake_port3'
        self.extra_dhcp_opts = []


class FakePort4(object):
    def __init__(self):
        self.id = 'gggggggg-gggg-gggg-gggg-gggggggggggg'
        self.admin_state_up = False
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.4',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd'),
            FakeIPAllocation('ffda:3ba5:a17a:4ba3:0216:3eff:fec2:771d',
                             'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
        self.dns_assignment = [
            FakeDNSAssignment('192.168.0.4'),
            FakeDNSAssignment('ffda:3ba5:a17a:4ba3:0216:3eff:fec2:771d')]
        self.mac_address = '00:16:3E:C2:77:1D'
        self.device_id = 'fake_port4'
        self.extra_dhcp_opts = []


class FakePort5(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeee'
        self.admin_state_up = True
        self.device_owner = 'foo5'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.5',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.dns_assignment = [FakeDNSAssignment('192.168.0.5')]
        self.mac_address = '00:00:0f:aa:bb:55'
        self.device_id = 'fake_port5'
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name=edo_ext.DHCP_OPT_CLIENT_ID,
                    opt_value='test5')]


class FakePort6(object):
    def __init__(self):
        self.id = 'ccccccccc-cccc-cccc-cccc-ccccccccc'
        self.admin_state_up = True
        self.device_owner = 'foo6'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.6',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.dns_assignment = [FakeDNSAssignment('192.168.0.6')]
        self.mac_address = '00:00:0f:aa:bb:66'
        self.device_id = 'fake_port6'
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name=edo_ext.DHCP_OPT_CLIENT_ID,
                    opt_value='test6',
                    ip_version=constants.IP_VERSION_4),
            DhcpOpt(opt_name='dns-server',
                    opt_value='123.123.123.45',
                    ip_version=constants.IP_VERSION_4)]


class FakeV6Port(object):
    def __init__(self, domain='openstacklocal'):
        self.id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
        self.admin_state_up = True
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('fdca:3ba5:a17a:4ba3::2',
                             'ffffffff-ffff-ffff-ffff-ffffffffffff')]
        self.mac_address = '00:00:f3:aa:bb:cc'
        self.device_id = 'fake_port6'
        self.extra_dhcp_opts = []
        self.dns_assignment = [FakeDNSAssignment('fdca:3ba5:a17a:4ba3::2',
                               domain=domain)]


class FakeV6PortExtraOpt(object):
    def __init__(self):
        self.id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
        self.admin_state_up = True
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('ffea:3ba5:a17a:4ba3:0216:3eff:fec2:771d',
                             'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
        self.dns_assignment = [
            FakeDNSAssignment('ffea:3ba5:a17a:4ba3:0216:3eff:fec2:771d')]
        self.mac_address = '00:16:3e:c2:77:1d'
        self.device_id = 'fake_port6'
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name='dns-server',
                    opt_value='ffea:3ba5:a17a:4ba3::100',
                    ip_version=constants.IP_VERSION_6),
            DhcpOpt(opt_name='malicious-option\nwith-new-line',
                    opt_value='aaa\nbbb.ccc\n',
                    ip_version=constants.IP_VERSION_6)]


class FakeV6PortMultipleFixedIpsSameSubnet(object):
    def __init__(self, domain='openstacklocal'):
        self.id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
        self.admin_state_up = True
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('fdca:3ba5:a17a:4ba3::2',
                             'ffffffff-ffff-ffff-ffff-ffffffffffff'),
            FakeIPAllocation('fdca:3ba5:a17a:4ba3::4',
                             'ffffffff-ffff-ffff-ffff-ffffffffffff')]
        self.mac_address = '00:00:f3:aa:bb:cc'
        self.device_id = 'fake_port6'
        self.extra_dhcp_opts = []
        self.dns_assignment = [FakeDNSAssignment('fdca:3ba5:a17a:4ba3::2',
                                                 domain=domain),
                               FakeDNSAssignment('fdca:3ba5:a17a:4ba3::4',
                                                 domain=domain)]


class FakeDualPortWithV6ExtraOpt(object):
    def __init__(self):
        self.id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
        self.admin_state_up = True
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.3',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd'),
            FakeIPAllocation('ffea:3ba5:a17a:4ba3:0216:3eff:fec2:771d',
                             'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
        self.dns_assignment = [
            FakeDNSAssignment('192.168.0.3'),
            FakeDNSAssignment('ffea:3ba5:a17a:4ba3:0216:3eff:fec2:771d')]
        self.mac_address = '00:16:3e:c2:77:1d'
        self.device_id = 'fake_port6'
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name='dns-server',
                    opt_value='ffea:3ba5:a17a:4ba3::100',
                    ip_version=constants.IP_VERSION_6)]


class FakeDualPort(object):
    def __init__(self, domain='openstacklocal'):
        self.id = 'hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh'
        self.admin_state_up = True
        self.device_owner = 'foo3'
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.3',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd'),
            FakeIPAllocation('fdca:3ba5:a17a:4ba3::3',
                             'ffffffff-ffff-ffff-ffff-ffffffffffff')]
        self.mac_address = '00:00:0f:aa:bb:cc'
        self.device_id = 'fake_dual_port'
        self.extra_dhcp_opts = []
        self.dns_assignment = [FakeDNSAssignment('192.168.0.3', domain=domain),
                               FakeDNSAssignment('fdca:3ba5:a17a:4ba3::3',
                                                 domain=domain)]


class FakeRouterPort(object):
    def __init__(self, dev_owner=constants.DEVICE_OWNER_ROUTER_INTF,
                 ip_address='192.168.0.1', domain='openstacklocal'):
        self.id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
        self.admin_state_up = True
        self.mac_address = '00:00:0f:rr:rr:rr'
        self.device_id = 'fake_router_port'
        self.dns_assignment = []
        self.extra_dhcp_opts = []
        self.device_owner = dev_owner
        self.fixed_ips = [FakeIPAllocation(
            ip_address, 'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.dns_assignment = [FakeDNSAssignment(ip.ip_address, domain=domain)
                               for ip in self.fixed_ips]


class FakeRouterHAPort(object):
    def __init__(self):
        self.id = 'hahahaha-haha-haha-haha-hahahahahaha'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_ROUTER_HA_INTF
        self.mac_address = '00:00:0f:aa:aa:aa'
        self.device_id = 'fake_router_ha_port'
        self.dns_assignment = []
        self.extra_dhcp_opts = []
        self.fixed_ips = [FakeIPAllocation(
            '169.254.169.20', 'dddddddd-dddd-dddd-dddd-dddddddddddd')]


class FakeRouterPortNoDHCP(object):
    def __init__(self, dev_owner=constants.DEVICE_OWNER_ROUTER_INTF,
                 ip_address='192.168.0.1', domain='openstacklocal'):
        self.id = 'ssssssss-ssss-ssss-ssss-ssssssssssss'
        self.admin_state_up = True
        self.mac_address = '00:00:0f:rr:rr:rr'
        self.device_id = 'fake_router_port_no_dhcp'
        self.dns_assignment = []
        self.extra_dhcp_opts = []
        self.device_owner = dev_owner
        self.fixed_ips = [FakeIPAllocation(
            ip_address, 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')]
        self.dns_assignment = [FakeDNSAssignment(ip.ip_address, domain=domain)
                               for ip in self.fixed_ips]


class FakeRouterPort2(object):
    def __init__(self):
        self.id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_ROUTER_INTF
        self.fixed_ips = [
            FakeIPAllocation('192.168.1.1',
                             'cccccccc-cccc-cccc-cccc-cccccccccccc')]
        self.dns_assignment = [FakeDNSAssignment('192.168.1.1')]
        self.mac_address = '00:00:0f:rr:rr:r2'
        self.device_id = 'fake_router_port2'
        self.extra_dhcp_opts = []


class FakeRouterPortSegmentID(object):
    def __init__(self):
        self.id = 'qqqqqqqq-qqqq-qqqq-qqqq-qqqqqqqqqqqq'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_ROUTER_INTF
        self.fixed_ips = [
            FakeIPAllocation('192.168.2.1',
                             'iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii')]
        self.dns_assignment = [FakeDNSAssignment('192.168.2.1')]
        self.mac_address = '00:00:0f:rr:rr:r3'
        self.device_id = 'fake_router_port3'
        self.extra_dhcp_opts = []


class FakePortMultipleAgents1(object):
    def __init__(self):
        self.id = 'rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_DHCP
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.5',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.dns_assignment = [FakeDNSAssignment('192.168.0.5')]
        self.mac_address = '00:00:0f:dd:dd:dd'
        self.device_id = 'fake_multiple_agents_port'
        self.extra_dhcp_opts = []


class FakePortMultipleAgents2(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.admin_state_up = True
        self.device_owner = constants.DEVICE_OWNER_DHCP
        self.fixed_ips = [
            FakeIPAllocation('192.168.0.6',
                             'dddddddd-dddd-dddd-dddd-dddddddddddd')]
        self.dns_assignment = [FakeDNSAssignment('192.168.0.6')]
        self.mac_address = '00:00:0f:ee:ee:ee'
        self.device_id = 'fake_multiple_agents_port2'
        self.extra_dhcp_opts = []


class FakePortWithClientIdNum(object):
    def __init__(self):
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name=dhcp.DHCP_OPT_CLIENT_ID_NUM,
                    opt_value='test_client_id_num')]


class FakePortWithClientIdNumStr(object):
    def __init__(self):
        self.extra_dhcp_opts = [
            DhcpOpt(opt_name=str(dhcp.DHCP_OPT_CLIENT_ID_NUM),
                    opt_value='test_client_id_num')]


class FakeV4HostRoute(object):
    def __init__(self):
        self.destination = '20.0.0.1/24'
        self.nexthop = '20.0.0.1'


class FakeV4HostRouteGateway(object):
    def __init__(self):
        self.destination = constants.IPv4_ANY
        self.nexthop = '10.0.0.1'


class FakeV6HostRoute(object):
    def __init__(self):
        self.destination = '2001:0200:feed:7ac0::/64'
        self.nexthop = '2001:0200:feed:7ac0::1'


class FakeV4Subnet(Dictable):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.ip_version = constants.IP_VERSION_4
        self.cidr = '192.168.0.0/24'
        self.gateway_ip = '192.168.0.1'
        self.enable_dhcp = True
        self.host_routes = [FakeV4HostRoute()]
        self.dns_nameservers = ['8.8.8.8']
        self.subnetpool_id = 'kkkkkkkk-kkkk-kkkk-kkkk-kkkkkkkkkkkk'


class FakeV4Subnet2(FakeV4Subnet):
    def __init__(self):
        super(FakeV4Subnet2, self).__init__()
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.cidr = '192.168.1.0/24'
        self.gateway_ip = '192.168.1.1'
        self.host_routes = []


class FakeV4SubnetSegmentID(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetSegmentID, self).__init__()
        self.id = 'iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii'
        self.cidr = '192.168.2.0/24'
        self.gateway_ip = '192.168.2.1'
        self.host_routes = []
        self.segment_id = 1


class FakeV4SubnetSegmentID2(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetSegmentID2, self).__init__()
        self.id = 'jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj'
        self.host_routes = []
        self.segment_id = 2


class FakeV4MetadataSubnet(FakeV4Subnet):
    def __init__(self):
        super(FakeV4MetadataSubnet, self).__init__()
        self.cidr = '169.254.169.254/30'
        self.gateway_ip = '169.254.169.253'
        self.host_routes = []
        self.dns_nameservers = []


class FakeV4SubnetGatewayRoute(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetGatewayRoute, self).__init__()
        self.host_routes = [FakeV4HostRouteGateway()]


class FakeV4SubnetMultipleAgentsWithoutDnsProvided(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetMultipleAgentsWithoutDnsProvided, self).__init__()
        self.dns_nameservers = []
        self.host_routes = []


class FakeV4SubnetAgentWithManyDnsProvided(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetAgentWithManyDnsProvided, self).__init__()
        self.dns_nameservers = ['2.2.2.2', '9.9.9.9', '1.1.1.1', '3.3.3.3']
        self.host_routes = []


class FakeV4SubnetAgentWithNoDnsProvided(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetAgentWithNoDnsProvided, self).__init__()
        self.dns_nameservers = ['0.0.0.0']
        self.host_routes = []


class FakeV4MultipleAgentsWithoutDnsProvided(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.subnets = [FakeV4SubnetMultipleAgentsWithoutDnsProvided()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
                      FakePortMultipleAgents1(), FakePortMultipleAgents2()]
        self.namespace = 'qdhcp-ns'


class FakeV4AgentWithoutDnsProvided(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.subnets = [FakeV4SubnetMultipleAgentsWithoutDnsProvided()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
                      FakePortMultipleAgents1()]
        self.namespace = 'qdhcp-ns'


class FakeV4AgentWithManyDnsProvided(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.subnets = [FakeV4SubnetAgentWithManyDnsProvided()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
                      FakePortMultipleAgents1()]
        self.namespace = 'qdhcp-ns'


class FakeV4AgentWithNoDnsProvided(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.subnets = [FakeV4SubnetAgentWithNoDnsProvided()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
                      FakePortMultipleAgents1()]
        self.namespace = 'qdhcp-ns'


class FakeV4SubnetMultipleAgentsWithDnsProvided(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetMultipleAgentsWithDnsProvided, self).__init__()
        self.host_routes = []


class FakeV4MultipleAgentsWithDnsProvided(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.subnets = [FakeV4SubnetMultipleAgentsWithDnsProvided()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort(),
                      FakePortMultipleAgents1(), FakePortMultipleAgents2()]
        self.namespace = 'qdhcp-ns'


class FakeV6Subnet(object):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.ip_version = constants.IP_VERSION_6
        self.cidr = 'fdca:3ba5:a17a:4ba3::/64'
        self.gateway_ip = 'fdca:3ba5:a17a:4ba3::1'
        self.enable_dhcp = True
        self.host_routes = [FakeV6HostRoute()]
        self.dns_nameservers = ['2001:0200:feed:7ac0::1']
        self.ipv6_ra_mode = None
        self.ipv6_address_mode = None
        self.subnetpool_id = 'jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj'


class FakeV4SubnetNoDHCP(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.ip_version = constants.IP_VERSION_4
        self.cidr = '192.168.1.0/24'
        self.gateway_ip = '192.168.1.1'
        self.enable_dhcp = False
        self.host_routes = []
        self.dns_nameservers = []


class FakeV6SubnetDHCPStateful(Dictable):
    def __init__(self):
        self.id = 'ffffffff-ffff-ffff-ffff-ffffffffffff'
        self.ip_version = constants.IP_VERSION_6
        self.cidr = 'fdca:3ba5:a17a:4ba3::/64'
        self.gateway_ip = 'fdca:3ba5:a17a:4ba3::1'
        self.enable_dhcp = True
        self.host_routes = [FakeV6HostRoute()]
        self.dns_nameservers = ['2001:0200:feed:7ac0::1']
        self.ipv6_ra_mode = None
        self.ipv6_address_mode = constants.DHCPV6_STATEFUL
        self.subnetpool_id = 'mmmmmmmm-mmmm-mmmm-mmmm-mmmmmmmmmmmm'


class FakeV6SubnetSlaac(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.ip_version = constants.IP_VERSION_6
        self.cidr = 'ffda:3ba5:a17a:4ba3::/64'
        self.gateway_ip = 'ffda:3ba5:a17a:4ba3::1'
        self.enable_dhcp = True
        self.host_routes = [FakeV6HostRoute()]
        self.ipv6_address_mode = constants.IPV6_SLAAC
        self.ipv6_ra_mode = None


class FakeV6SubnetStateless(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.ip_version = constants.IP_VERSION_6
        self.cidr = 'ffea:3ba5:a17a:4ba3::/64'
        self.gateway_ip = 'ffea:3ba5:a17a:4ba3::1'
        self.enable_dhcp = True
        self.dns_nameservers = []
        self.host_routes = []
        self.ipv6_address_mode = constants.DHCPV6_STATELESS
        self.ipv6_ra_mode = None


class FakeV6SubnetStatelessNoDnsProvided(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.ip_version = constants.IP_VERSION_6
        self.cidr = 'ffea:3ba5:a17a:4ba3::/64'
        self.gateway_ip = 'ffea:3ba5:a17a:4ba3::1'
        self.enable_dhcp = True
        self.dns_nameservers = ['::']
        self.host_routes = []
        self.ipv6_address_mode = constants.DHCPV6_STATELESS
        self.ipv6_ra_mode = None


class FakeV6SubnetStatelessBadPrefixLength(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.ip_version = constants.IP_VERSION_6
        self.cidr = 'ffeb:3ba5:a17a:4ba3::/56'
        self.gateway_ip = 'ffeb:3ba5:a17a:4ba3::1'
        self.enable_dhcp = True
        self.dns_nameservers = []
        self.host_routes = []
        self.ipv6_address_mode = constants.DHCPV6_STATELESS
        self.ipv6_ra_mode = None


class FakeV4SubnetNoGateway(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetNoGateway, self).__init__()
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.cidr = '192.168.1.0/24'
        self.gateway_ip = None
        self.enable_dhcp = True
        self.host_routes = []
        self.dns_nameservers = []


class FakeV4SubnetNoRouter(FakeV4Subnet):
    def __init__(self):
        super(FakeV4SubnetNoRouter, self).__init__()
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.cidr = '192.168.1.0/24'
        self.gateway_ip = '192.168.1.1'
        self.host_routes = []
        self.dns_nameservers = []


class FakeV4Network(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1()]
        self.namespace = 'qdhcp-ns'


class FakeV4NetworkClientId(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakePort5(), FakePort6()]
        self.namespace = 'qdhcp-ns'


class FakeV4NetworkClientIdNum(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePortWithClientIdNum()]
        self.namespace = 'qdhcp-ns'


class FakeV4NetworkClientIdNumStr(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePortWithClientIdNumStr()]
        self.namespace = 'qdhcp-ns'


class FakeV6Network(object):
    def __init__(self):
        self.id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.subnets = [FakeV6Subnet()]
        self.ports = [FakePort2()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetwork(object):
    def __init__(self, domain='openstacklocal'):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV6SubnetDHCPStateful()]
        self.namespace = 'qdhcp-ns'
        self.ports = [FakePort1(domain=domain), FakeV6Port(domain=domain),
                      FakeDualPort(domain=domain),
                      FakeRouterHAPort(),
                      FakeRouterPort(domain=domain)]


class FakeDeviceManagerNetwork(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV6SubnetDHCPStateful()]
        self.ports = [FakePort1(),
                      FakeV6Port(),
                      FakeDualPort(),
                      FakeRouterPort()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkReserved(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV6SubnetDHCPStateful()]
        self.ports = [FakePort1(), FakeV6Port(), FakeDualPort(),
                      FakeRouterPort(), FakeReservedPort()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkReserved2(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV6SubnetDHCPStateful()]
        self.ports = [FakePort1(), FakeV6Port(), FakeDualPort(),
                      FakeRouterPort(), FakeReservedPort(),
                      FakeReservedPort(id='reserved-2')]
        self.namespace = 'qdhcp-ns'


class FakeNetworkDhcpPort(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakeDhcpPort()]
        self.namespace = 'qdhcp-ns'


class FakeNetworkDhcpandOvnMetadataPort(object):
    def __init__(self):
        self.id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakeDhcpPort(), FakeOvnMetadataPort()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkGatewayRoute(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4SubnetGatewayRoute(), FakeV6SubnetDHCPStateful()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkSingleDHCP(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkSingleDHCPBothAttaced(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        # dhcp-agent actually can't get the subnet with dhcp disabled
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakeRouterPortNoDHCP(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkDualDHCP(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV4Subnet2()]
        self.ports = [FakePort1(), FakeRouterPort(), FakeRouterPort2()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkDualDHCPOnLinkSubnetRoutesDisabled(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV4SubnetSegmentID()]
        self.ports = [FakePort1(), FakeRouterPort(), FakeRouterPortSegmentID()]
        self.namespace = 'qdhcp-ns'


class FakeNonLocalSubnets(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4SubnetSegmentID2()]
        self.non_local_subnets = [FakeV4SubnetSegmentID()]
        self.ports = [FakePort1(), FakeRouterPort(), FakeRouterPortSegmentID()]
        self.namespace = 'qdhcp-ns'


class FakeDualNetworkTriDHCPOneOnLinkSubnetRoute(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV4Subnet2(),
                        FakeV4SubnetSegmentID()]
        self.ports = [FakePort1(), FakeRouterPort(), FakeRouterPort2(),
                      FakeRouterPortSegmentID()]
        self.namespace = 'qdhcp-ns'


class FakeV4NoGatewayNetwork(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4SubnetNoGateway()]
        self.ports = [FakePort1()]


class FakeV4NetworkNoRouter(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4SubnetNoRouter()]
        self.ports = [FakePort1()]


class FakeV4MetadataNetwork(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4MetadataSubnet()]
        self.ports = [FakeRouterPort(ip_address='169.254.169.253')]


class FakeV4NetworkDistRouter(object):
    def __init__(self):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(),
                      FakeRouterPort(
                          dev_owner=constants.DEVICE_OWNER_DVR_INTERFACE)]


class FakeDualV4Pxe3Ports(object):
    def __init__(self, port_detail="portsSame"):
        self.id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
        self.subnets = [FakeV4Subnet(), FakeV4SubnetNoDHCP()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'
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
    def __init__(self, port_detail="portsSame"):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakePort2(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'
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
    def __init__(self, port_detail="portsSame"):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakePort2(), FakePort3(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'
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


class FakeV4NetworkPxePort(object):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1()]
        self.namespace = 'qdhcp-ns'
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.3',
                    ip_version=constants.IP_VERSION_4),
            DhcpOpt(opt_name='server-ip-address', opt_value='192.168.0.2',
                    ip_version=constants.IP_VERSION_4),
            DhcpOpt(opt_name='nd98', opt_value='option-nondigit-98',
                    ip_version=constants.IP_VERSION_4),
            DhcpOpt(opt_name='99', opt_value='option-99',
                    ip_version=constants.IP_VERSION_4),
            DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0',
                    ip_version=constants.IP_VERSION_4)]


class FakeV6NetworkPxePort(object):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV6SubnetDHCPStateful()]
        self.ports = [FakeV6Port()]
        self.namespace = 'qdhcp-ns'
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tftp-server', opt_value='2001:192:168::1',
                    ip_version=constants.IP_VERSION_6),
            DhcpOpt(opt_name='nd98', opt_value='option-nondigit-98',
                    ip_version=constants.IP_VERSION_6),
            DhcpOpt(opt_name='99', opt_value='option-99',
                    ip_version=constants.IP_VERSION_6),
            DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0',
                    ip_version=constants.IP_VERSION_6)]


class FakeV6NetworkPxePortWrongOptVersion(object):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV6SubnetDHCPStateful()]
        self.ports = [FakeV6Port()]
        self.namespace = 'qdhcp-ns'
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tftp-server', opt_value='192.168.0.7',
                    ip_version=constants.IP_VERSION_4),
            DhcpOpt(opt_name='bootfile-name', opt_value='pxelinux.0',
                    ip_version=constants.IP_VERSION_6)]


class FakeDualStackNetworkSingleDHCP(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.subnets = [FakeV4Subnet(), FakeV6SubnetSlaac()]
        self.ports = [FakePort1(), FakePort4(), FakeRouterPort()]


class FakeDualStackNetworkingSingleDHCPTags(object):
    def __init__(self):
        self.id = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        self.subnets = [FakeV4Subnet(), FakeV6SubnetSlaac()]
        self.ports = [FakePort1(), FakePort4(), FakeRouterPort()]
        for port in self.ports:
            port.extra_dhcp_opts = [
                DhcpOpt(opt_name='tag:ipxe,bootfile-name',
                        opt_value='pxelinux.0')]


class FakeV4NetworkMultipleTags(object):
    def __init__(self):
        self.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
        self.subnets = [FakeV4Subnet()]
        self.ports = [FakePort1(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'
        self.ports[0].extra_dhcp_opts = [
            DhcpOpt(opt_name='tag:ipxe,bootfile-name', opt_value='pxelinux.0')]


class FakeV6NetworkStatelessDHCP(object):
    def __init__(self):
        self.id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.subnets = [FakeV6SubnetStateless()]
        self.ports = [FakeV6PortExtraOpt()]
        self.namespace = 'qdhcp-ns'


class FakeV6NetworkStatelessDHCPNoDnsProvided(object):
    def __init__(self):
        self.id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.subnets = [FakeV6SubnetStatelessNoDnsProvided()]
        self.ports = [FakeV6Port()]
        self.namespace = 'qdhcp-ns'


class FakeV6NetworkStatelessDHCPBadPrefixLength(object):
    def __init__(self):
        self.id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.subnets = [FakeV6SubnetStatelessBadPrefixLength()]
        self.ports = [FakeV6PortExtraOpt()]
        self.namespace = 'qdhcp-ns'


class FakeNetworkWithV6SatelessAndV4DHCPSubnets(object):
    def __init__(self):
        self.id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.subnets = [FakeV6SubnetStateless(), FakeV4Subnet()]
        self.ports = [FakeDualPortWithV6ExtraOpt(), FakeRouterPort()]
        self.namespace = 'qdhcp-ns'


class FakeV6NetworkStatefulDHCPSameSubnetFixedIps(object):
    def __init__(self):
        self.id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        self.subnets = [FakeV6SubnetDHCPStateful()]
        self.ports = [FakeV6PortMultipleFixedIpsSameSubnet()]
        self.namespace = 'qdhcp-ns'


class LocalChild(dhcp.DhcpLocalProcess):
    PORTS = {4: [4], 6: [6]}

    def __init__(self, *args, **kwargs):
        self.process_monitor = mock.Mock()
        kwargs['process_monitor'] = self.process_monitor
        super(LocalChild, self).__init__(*args, **kwargs)
        self.called = []

    def reload_allocations(self):
        self.called.append('reload')

    def spawn_process(self):
        self.called.append('spawn')


class TestConfBase(base.BaseTestCase):
    def setUp(self):
        super(TestConfBase, self).setUp()
        self.conf = config.setup_conf()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(dhcp_config.DHCP_OPTS)
        self.conf.register_opts(dhcp_config.DNSMASQ_OPTS)
        self.conf.register_opts(config.DHCP_PROTOCOL_OPTS)
        config.register_external_process_opts(self.conf)
        config.register_interface_driver_opts_helper(self.conf)


class TestBase(TestConfBase):
    def setUp(self):
        super(TestBase, self).setUp()
        instance = mock.patch("neutron.agent.linux.dhcp.DeviceManager")
        self.mock_mgr = instance.start()
        self.conf.register_opt(cfg.BoolOpt('enable_isolated_metadata',
                                           default=True))
        self.conf.register_opt(cfg.BoolOpt("force_metadata",
                                           default=False))
        self.conf.register_opt(cfg.BoolOpt('enable_metadata_network',
                                           default=False))
        self.config_parse(self.conf)
        self.conf.set_override('state_path', '')

        self.replace_p = mock.patch('neutron_lib.utils.file.replace_file')
        self.execute_p = mock.patch('neutron.agent.common.utils.execute')
        mock.patch('neutron.agent.linux.utils.execute').start()
        self.safe = self.replace_p.start()
        self.execute = self.execute_p.start()

        self.makedirs = mock.patch('os.makedirs').start()
        self.rmtree = mock.patch('shutil.rmtree').start()

        self.external_process = mock.patch(
            'neutron.agent.linux.external_process.ProcessManager').start()

        self.mock_mgr.return_value.driver.bridged = True


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

            def disable(self, retain_port=False, block=False):
                self.called.append('disable %s %s' % (retain_port, block))

            def reload_allocations(self):
                pass

            @property
            def active(self):
                return True

        c = SubClass()
        c.restart()
        self.assertEqual(c.called, ['disable True True', 'enable'])


class TestDhcpLocalProcess(TestBase):

    def test_get_conf_file_name(self):
        tpl = '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/dev'
        lp = LocalChild(self.conf, FakeV4Network())
        self.assertEqual(lp.get_conf_file_name('dev'), tpl)

    @mock.patch.object(fileutils, 'ensure_tree')
    def test_ensure_dir_called(self, ensure_dir):
        LocalChild(self.conf, FakeV4Network())
        ensure_dir.assert_called_once_with(
            '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', mode=0o755)

    def test_enable_already_active(self):
        with mock.patch.object(LocalChild, 'active') as patched:
            patched.__get__ = mock.Mock(side_effect=[True, False])
            lp = LocalChild(self.conf, FakeV4Network())
            with mock.patch.object(ip_lib, 'delete_network_namespace'):
                lp.enable()

            self.assertEqual(lp.called, ['spawn'])
            self.assertTrue(self.mock_mgr.return_value.setup.called)

    @mock.patch.object(fileutils, 'ensure_tree')
    def test_enable(self, ensure_dir):
        attrs_to_mock = dict(
            (a, mock.DEFAULT) for a in
            ['active', 'interface_name', 'spawn_process']
        )

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['interface_name'].__set__ = mock.Mock()
            mocks['spawn_process'].side_effect = [
                exceptions.ProcessExecutionError(
                    returncode=2, message="Test dnsmasq start failed"),
                None]
            lp = LocalChild(self.conf,
                            FakeDualNetwork())

            lp.enable()

            self.mock_mgr.assert_has_calls(
                [mock.call(self.conf, None),
                 mock.call().setup(mock.ANY)])
            self.assertEqual(2, mocks['interface_name'].__set__.call_count)
            ensure_dir.assert_has_calls([
                mock.call(
                    '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc', mode=0o755),
                mock.call(
                    '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc', mode=0o755)])

    def _assert_disabled(self, lp):
        self.assertTrue(lp.process_monitor.unregister.called)
        self.assertTrue(self.external_process().disable.called)

    def test_disable_not_active(self):
        attrs_to_mock = dict((a, mock.DEFAULT) for a in
                             ['active', 'interface_name'])
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            network = FakeDualNetwork()
            lp = LocalChild(self.conf, network)
            lp.device_manager = mock.Mock()
            with mock.patch('neutron.agent.linux.ip_lib.'
                            'delete_network_namespace') as delete_ns:
                lp.disable()
            lp.device_manager.destroy.assert_called_once_with(
                network, 'tap0')
            self._assert_disabled(lp)

        delete_ns.assert_called_with('qdhcp-ns')

    def test_disable_retain_port(self):
        attrs_to_mock = dict((a, mock.DEFAULT) for a in
                             ['active', 'interface_name'])
        network = FakeDualNetwork()
        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=True)
            mocks['interface_name'].__get__ = mock.Mock(return_value='tap0')
            lp = LocalChild(self.conf, network)
            lp.disable(retain_port=True)
            self.rmtree.assert_not_called()
            self._assert_disabled(lp)

    def test_disable(self):
        attrs_to_mock = {'active': mock.DEFAULT}

        with mock.patch.multiple(LocalChild, **attrs_to_mock) as mocks:
            mocks['active'].__get__ = mock.Mock(return_value=False)
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch('neutron.agent.linux.ip_lib.'
                            'delete_network_namespace') as delete_ns:
                lp.disable()
                self.rmtree.assert_called_once()

            self._assert_disabled(lp)

        delete_ns.assert_called_with('qdhcp-ns')

    def test_disable_config_dir_removed_after_destroy(self):
        parent = mock.MagicMock()
        parent.attach_mock(self.rmtree, 'rmtree')
        parent.attach_mock(self.mock_mgr, 'DeviceManager')

        lp = LocalChild(self.conf, FakeDualNetwork())
        with mock.patch('neutron.agent.linux.ip_lib.'
                        'delete_network_namespace') as delete_ns:
            lp.disable(retain_port=False)

        expected = [mock.call.DeviceManager().destroy(mock.ANY, mock.ANY),
                    mock.call.rmtree(mock.ANY, ignore_errors=True)]
        parent.assert_has_calls(expected)
        delete_ns.assert_called_with('qdhcp-ns')

    def test_get_interface_name(self):
        net = FakeDualNetwork()
        path = '/dhcp/%s/interface' % net.id
        self.useFixture(lib_fixtures.OpenFixture(path, 'tap0'))
        lp = LocalChild(self.conf, net)
        self.assertEqual(lp.interface_name, 'tap0')

    def test_set_interface_name(self):
        with mock.patch('neutron_lib.utils.file.replace_file') as replace:
            lp = LocalChild(self.conf, FakeDualNetwork())
            with mock.patch.object(lp, 'get_conf_file_name') as conf_file:
                conf_file.return_value = '/interface'
                lp.interface_name = 'tap0'
                conf_file.assert_called_once_with('interface')
                replace.assert_called_once_with(mock.ANY, 'tap0')


class TestDnsmasq(TestBase):

    def setUp(self):
        super(TestDnsmasq, self).setUp()
        self._mock_get_devices_with_ip = mock.patch.object(
            ip_lib, 'get_devices_with_ip')
        self.mock_get_devices_with_ip = self._mock_get_devices_with_ip.start()
        self.addCleanup(self._stop_mocks)

    def _stop_mocks(self):
        self._mock_get_devices_with_ip.stop()

    def _get_dnsmasq(self, network, process_monitor=None):
        process_monitor = process_monitor or mock.Mock()
        return dhcp.Dnsmasq(self.conf, network,
                            process_monitor=process_monitor)

    def _test_spawn(self, extra_options, network=FakeDualNetwork(),
                    max_leases=16777216, lease_duration=86400,
                    has_static=True, no_resolv='--no-resolv',
                    has_stateless=True, dhcp_t1=0, dhcp_t2=0,
                    bridged=True):
        def mock_get_conf_file_name(kind):
            return '/dhcp/%s/%s' % (network.id, kind)

        # Empty string passed to --conf-file in dnsmasq is invalid
        # we must force '' to '/dev/null' because the dhcp agent
        # does the same. Therefore we allow empty string to
        # be passed to neutron but not to dnsmasq.
        def check_conf_file_empty(cmd_list):
            for i in cmd_list:
                conf_file = ''
                value = ''
                if i.startswith('--conf-file='):
                    conf_file = i
                    value = i[12:].strip()
                    if not value:
                        idx = cmd_list.index(conf_file)
                        cmd_list[idx] = '--conf-file=/dev/null'

        # if you need to change this path here, think twice,
        # that means pid files will move around, breaking upgrades
        # or backwards-compatibility
        expected_pid_file = '/dhcp/%s/pid' % network.id

        expected = [
            'dnsmasq',
            '--no-hosts',
            no_resolv,
            '--pid-file=%s' % expected_pid_file,
            '--dhcp-hostsfile=/dhcp/%s/host' % network.id,
            '--addn-hosts=/dhcp/%s/addn_hosts' % network.id,
            '--dhcp-optsfile=/dhcp/%s/opts' % network.id,
            '--dhcp-leasefile=/dhcp/%s/leases' % network.id,
            '--dhcp-match=set:ipxe,175',
            '--dhcp-userclass=set:ipxe6,iPXE',
            '--local-service',
            '--bind-dynamic',
        ]
        if not bridged:
            expected += [
                '--bridge-interface=tap0,tap*'
            ]

        seconds = ''
        if lease_duration == -1:
            lease_duration = 'infinite'
        else:
            seconds = 's'
        if has_static:
            prefix = '--dhcp-range=set:subnet-%s,%s,static,%s,%s%s'
            prefix6 = '--dhcp-range=set:subnet-%s,%s,static,%s,%s%s'
        elif has_stateless:
            prefix = '--dhcp-range=set:subnet-%s,%s,%s,%s%s'
            prefix6 = '--dhcp-range=set:subnet-%s,%s,%s,%s%s'
        possible_leases = 0
        for s in network.subnets:
            if (s.ip_version != constants.IP_VERSION_6 or
                    s.ipv6_address_mode == constants.DHCPV6_STATEFUL):
                if s.ip_version == constants.IP_VERSION_4:
                    expected.extend([prefix % (
                        s.id, s.cidr.split('/')[0],
                        netaddr.IPNetwork(s.cidr).netmask, lease_duration,
                        seconds)])
                else:
                    expected.extend([prefix6 % (
                        s.id, s.cidr.split('/')[0], s.cidr.split('/')[1],
                        lease_duration, seconds)])
                possible_leases += netaddr.IPNetwork(s.cidr).size

        if hasattr(network, 'mtu'):
            expected.append(
                '--dhcp-option-force=option:mtu,%s' % network.mtu)

        expected.append('--dhcp-lease-max=%d' % min(
            possible_leases, max_leases))

        if dhcp_t1:
            expected.append('--dhcp-option-force=option:T1,%ds' % dhcp_t1)
        if dhcp_t2:
            expected.append('--dhcp-option-force=option:T2,%ds' % dhcp_t2)

        expected.extend(extra_options)
        check_conf_file_empty(expected)

        self.execute.return_value = ('', '')

        attrs_to_mock = dict(
            (a, mock.DEFAULT) for a in
            ['_output_opts_file', 'get_conf_file_name', 'interface_name']
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
                ensure_active=True, reload_cfg=False)
            call_kwargs = self.external_process.mock_calls[0][2]
            cmd_callback = call_kwargs['default_cmd_callback']

            result_cmd = cmd_callback(expected_pid_file)

            self.assertEqual(expected, result_cmd)

    def test_spawn(self):
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'])

    def test_spawn_not_bridged(self):
        self.mock_mgr.return_value.driver.bridged = False
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         bridged=False)

    def test_spawn_infinite_lease_duration(self):
        self.conf.set_override('dhcp_lease_duration', -1)
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         FakeDualNetwork(), 16777216, -1)

    def test_spawn_cfg_config_file(self):
        self.conf.set_override('dnsmasq_config_file', '/foo')
        self._test_spawn(['--conf-file=/foo', '--domain=openstacklocal'])

    @mock.patch.object(checks, 'dnsmasq_host_tag_support', autospec=True)
    def test_spawn_no_dns_domain(self, mock_tag_support):
        mock_tag_support.return_value = False
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data) = self._test_no_dns_domain_alloc_data()
        self.conf.set_override('dns_domain', '')
        network = FakeDualNetwork(domain=self.conf.dns_domain)
        self._test_spawn(['--conf-file='], network=network)
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_addn_name, exp_addn_data)])

    @mock.patch.object(checks, 'dnsmasq_host_tag_support', autospec=True)
    def test_spawn_no_dns_domain_tag_support(self, mock_tag_support):
        mock_tag_support.return_value = True
        (exp_host_name, exp_host_data, exp_addn_name,
         exp_addn_data) = self._test_no_dns_domain_alloc_data(
            tag=dhcp.HOST_DHCPV6_TAG)
        self.conf.set_override('dns_domain', '')
        network = FakeDualNetwork(domain=self.conf.dns_domain)
        self._test_spawn(['--conf-file='], network=network)
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_addn_name, exp_addn_data)])

    def test_spawn_no_dhcp_range(self):
        network = FakeV6Network()
        subnet = FakeV6SubnetSlaac()
        network.subnets = [subnet]
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         network, has_static=False)

    def test_spawn_no_dhcp_range_bad_prefix_length(self):
        network = FakeV6NetworkStatelessDHCPBadPrefixLength()
        subnet = FakeV6SubnetStatelessBadPrefixLength()
        network.subnets = [subnet]
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         network, has_static=False, has_stateless=False)

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

    def test_spawn_cfg_enable_dnsmasq_log(self):
        self.conf.set_override('dnsmasq_base_log_dir', '/tmp')
        network = FakeV4Network()
        dhcp_dns_log = \
            '/tmp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/dhcp_dns_log'

        self._test_spawn(['--conf-file=',
                          '--domain=openstacklocal',
                          '--log-queries',
                          '--log-dhcp',
                          ('--log-facility=%s' % dhcp_dns_log)],
                         network)
        self.makedirs.assert_called_with(os.path.join('/tmp', network.id))

    def test_spawn_cfg_with_local_resolv(self):
        self.conf.set_override('dnsmasq_local_resolv', True)

        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         no_resolv='')

    def test_spawn_cfg_with_local_resolv_overridden(self):
        self.conf.set_override('dnsmasq_local_resolv', True)
        self.conf.set_override('dnsmasq_dns_servers', ['8.8.8.8'])

        self._test_spawn(['--conf-file=',
                          '--server=8.8.8.8',
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
        network = FakeV4Network()
        network.mtu = 1500
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         network)

    def test_spawn_cfg_advertise_mtu_plugin_doesnt_pass_mtu_value(self):
        network = FakeV4Network()
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         network)

    def test_spawn_cfg_with_dhcp_timers(self):
        self.conf.set_override('dhcp_renewal_time', 30)
        self.conf.set_override('dhcp_rebinding_time', 100)
        self._test_spawn(['--conf-file=', '--domain=openstacklocal'],
                         dhcp_t1=30, dhcp_t2=100)

    def _test_output_init_lease_file(self, timestamp):
        expected = [
            '00:00:80:aa:bb:cc 192.168.0.2 * *',
            '00:00:0f:aa:bb:cc 192.168.0.3 * *',
            '00:00:0f:rr:rr:rr 192.168.0.1 * *\n']
        expected = "\n".join(['%s %s' % (timestamp, le) for le in expected])
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

    @mock.patch('time.time')
    @mock.patch('os.path.isfile', return_value=True)
    def test_output_init_lease_file_existing(self, isfile, tmock):

        duid = 'duid 00:01:00:01:27:da:58:97:fa:16:3e:6c:ad:c1'
        ipv4_leases = (
            '1623162161 00:00:80:aa:bb:cc 192.168.0.2 host-192-168-0-2 *\n'
            '1623147425 00:00:0f:aa:bb:cc 192.168.0.3 host-192-168-0-3 '
            'ff:b5:5e:67:ff:00:02:00:00:ab:11:43:e5:86:52:f3:d7:2c:97\n'
            '1623138717 00:00:0f:rr:rr:rr 192.168.0.1 host-192-168-0-1 '
            'ff:b5:5e:67:ff:00:02:00:00:ab:11:f6:f2:aa:cb:94:c1:b4:86'
        )
        ipv6_lease_v6_port = (
            '1623083263 755752236 fdca:3ba5:a17a:4ba3::2 '
            'host-fdca-3ba5-a17a-4ba3--2 '
            '00:01:00:01:28:50:e8:31:5a:42:2d:0b:dd:2c'
        )
        additional_ipv6_leases = (
            '1623143299 3042863103 2001:db8::45 host-2001-db8--45 '
            '00:02:00:00:ab:11:fa:c9:0e:0f:3d:90:73:f0\n'
            '1623134168 3042863103 2001:db8::12 host-2001-db8--12 '
            '00:02:00:00:ab:11:f6:f2:aa:cb:94:c1:b4:86'
        )
        existing_leases = '\n'.join((ipv4_leases, duid, ipv6_lease_v6_port,
                                     additional_ipv6_leases))

        # lease duration should be added to current time
        timestamp = 1000000 + 500
        # The expected lease file contains:
        # * The DHCPv6 servers DUID
        # * A lease for all IPv4 addresses
        # * A lease for the IPv6 addresses present in the existing lease file
        #   (IPv6 of FakeV6Port)
        # * No lease for the IPv6 addresses NOT present in the existing lease
        #   file (IPv6 of FakeDualPort)
        # * No lease for the IPv6 addresses present in the existing lease file
        #   which are no longer assigned to any port
        expected = (
            '%s\n'
            '%s 00:00:80:aa:bb:cc 192.168.0.2 * *\n'
            '%s\n'
            '%s 00:00:0f:aa:bb:cc 192.168.0.3 * *\n'
            '%s 00:00:0f:rr:rr:rr 192.168.0.1 * *\n'
        ) % (duid, timestamp, ipv6_lease_v6_port, timestamp, timestamp)

        self.conf.set_override('dhcp_lease_duration', 500)
        tmock.return_value = 1000000

        with mock.patch.object(dhcp.Dnsmasq, 'get_conf_file_name') as conf_fn:
            conf_fn.return_value = '/foo/leases'
            dm = self._get_dnsmasq(FakeDualNetwork())

            # Patch __iter__ into mock for Python < 3.8 compatibility
            open_mock = mock.mock_open(read_data=existing_leases)
            open_mock.return_value.__iter__ = lambda s: iter(s.readline, '')

            with mock.patch('builtins.open', open_mock):
                dm._output_init_lease_file()

        # Assert the lease file contains the existing ipv6_leases
        self.safe.assert_called_once_with('/foo/leases', expected)

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
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,%s\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal'
        ).lstrip() % ('[' + fake_v6 + ']')

        self._test_output_opts_file(expected, FakeDualNetwork())

    def test_output_opts_file_gateway_route(self):
        fake_v6 = '2001:0200:feed:7ac0::1'
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,%s\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal'
        ).lstrip() % ('[' + fake_v6 + ']')

        self._test_output_opts_file(expected, FakeDualNetworkGatewayRoute())

    def test_output_opts_file_multiple_agents_without_dns_provided(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,192.168.0.5,192.168.0.6').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4MultipleAgentsWithoutDnsProvided())

    def test_output_opts_file_agent_dns_provided(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4AgentWithoutDnsProvided())

    def test_output_opts_file_agent_with_many_dns_provided(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,2.2.2.2,9.9.9.9,1.1.1.1,3.3.3.3\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4AgentWithManyDnsProvided())

    def test_output_opts_file_agent_with_no_dns_provided(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4AgentWithNoDnsProvided())

    def test_output_opts_file_multiple_agents_with_dns_provided(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4MultipleAgentsWithDnsProvided())

    def test_output_opts_file_single_dhcp(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,192.168.1.0/24,0.0.0.0,'
            '20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,192.168.1.0/24,0.0.0.0,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected, FakeDualNetworkSingleDHCP())

    def test_output_opts_file_single_dhcp_both_not_isolated(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        self._test_output_opts_file(expected,
                                    FakeDualNetworkSingleDHCPBothAttaced())

    def test_output_opts_file_dual_dhcp_rfc3442(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,192.168.1.0/24,0.0.0.0,'
            '20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,192.168.1.0/24,0.0.0.0,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            'option:classless-static-route,192.168.0.0/24,0.0.0.0,'
            '169.254.169.254/32,192.168.1.1,0.0.0.0/0,192.168.1.1\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            '249,192.168.0.0/24,0.0.0.0,169.254.169.254/32,192.168.1.1,'
            '0.0.0.0/0,192.168.1.1\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            'option:router,192.168.1.1').lstrip()

        self._test_output_opts_file(expected, FakeDualNetworkDualDHCP())

    def test_output_opts_file_dual_dhcp_rfc3442_no_on_link_subnet_routes(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:classless-static-route,169.254.169.254/32,192.168.2.1,'
            '0.0.0.0/0,192.168.2.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            '249,169.254.169.254/32,192.168.2.1,0.0.0.0/0,192.168.2.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:router,192.168.2.1').lstrip()

        self._test_output_opts_file(expected,
            FakeDualNetworkDualDHCPOnLinkSubnetRoutesDisabled())

    def test_output_opts_file_dual_dhcp_rfc3442_one_on_link_subnet_route(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,192.168.1.0/24,0.0.0.0,'
            '20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,192.168.1.0/24,0.0.0.0,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            'option:classless-static-route,192.168.0.0/24,0.0.0.0,'
            '169.254.169.254/32,192.168.1.1,0.0.0.0/0,192.168.1.1\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            '249,192.168.0.0/24,0.0.0.0,169.254.169.254/32,192.168.1.1,'
            '0.0.0.0/0,192.168.1.1\n'
            'tag:subnet-cccccccc-cccc-cccc-cccc-cccccccccccc,'
            'option:router,192.168.1.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:classless-static-route,169.254.169.254/32,192.168.2.1,'
            '0.0.0.0/0,192.168.2.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            '249,169.254.169.254/32,192.168.2.1,0.0.0.0/0,192.168.2.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:router,192.168.2.1').lstrip()

        self._test_output_opts_file(expected,
            FakeDualNetworkTriDHCPOneOnLinkSubnetRoute())

    def test_output_opts_file_no_gateway(self):
        expected = (
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:classless-static-route,169.254.169.254/32,192.168.1.1\n'
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            '249,169.254.169.254/32,192.168.1.1\n'
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:router').lstrip()

        ipm_retval = {FakeV4SubnetNoGateway().id: '192.168.1.1'}
        self._test_output_opts_file(expected, FakeV4NoGatewayNetwork(),
                                    ipm_retval=ipm_retval)

    def test_non_local_subnets(self):
        expected = (
            'tag:subnet-jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj,'
            'option:classless-static-route,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj,'
            '249,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj,'
            'option:router,192.168.0.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:classless-static-route,169.254.169.254/32,192.168.2.1,'
            '0.0.0.0/0,192.168.2.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            '249,169.254.169.254/32,192.168.2.1,0.0.0.0/0,192.168.2.1\n'
            'tag:subnet-iiiiiiii-iiii-iiii-iiii-iiiiiiiiiiii,'
            'option:router,192.168.2.1').lstrip()
        ipm_retval = {FakeV4SubnetSegmentID2().id: '192.168.0.1'}
        self._test_output_opts_file(expected, FakeNonLocalSubnets(),
                                    ipm_retval=ipm_retval)

    def test_output_opts_file_no_neutron_router_on_subnet(self):
        expected = (
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:classless-static-route,'
            '169.254.169.254/32,192.168.1.2,0.0.0.0/0,192.168.1.1\n'
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            '249,169.254.169.254/32,192.168.1.2,0.0.0.0/0,192.168.1.1\n'
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:router,192.168.1.1').lstrip()

        ipm_retval = {FakeV4SubnetNoRouter().id: '192.168.1.2'}
        self._test_output_opts_file(expected, FakeV4NetworkNoRouter(),
                                    ipm_retval=ipm_retval)

    def test_output_opts_file_dist_neutron_router_on_subnet(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1').lstrip()

        ipm_retval = {FakeV4Subnet().id: '192.168.0.1'}
        self._test_output_opts_file(expected, FakeV4NetworkDistRouter(),
                                    ipm_retval=ipm_retval)

    def test_output_opts_file_pxe_2port_1net(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:tftp-server,192.168.0.3\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:bootfile-name,pxelinux.0').lstrip()

        self._test_output_opts_file(expected, FakeV4NetworkPxe2Ports())

    def test_output_opts_file_pxe_2port_1net_diff_details(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,192.168.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:tftp-server,192.168.0.5\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:server-ip-address,192.168.0.5\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:bootfile-name,pxelinux.0').lstrip()

        self._test_output_opts_file(expected,
                                    FakeV4NetworkPxe2Ports("portsDiff"))

    def test_output_opts_file_pxe_3port_2net(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,192.168.1.0/24,0.0.0.0,20.0.0.1/24,'
            '20.0.0.1,169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,192.168.1.0/24,0.0.0.0,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:tftp-server,192.168.1.3\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:server-ip-address,192.168.1.2\n'
            'tag:port-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option:bootfile-name,pxelinux2.0\n'
            'tag:port-44444444-4444-4444-4444-444444444444,'
            'option:tftp-server,192.168.1.3\n'
            'tag:port-44444444-4444-4444-4444-444444444444,'
            'option:server-ip-address,192.168.1.2\n'
            'tag:port-44444444-4444-4444-4444-444444444444,'
            'option:bootfile-name,pxelinux3.0').lstrip()

        self._test_output_opts_file(expected, FakeDualV4Pxe3Ports())

    def test_output_opts_file_pxe_port(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:tftp-server,192.168.0.3\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:server-ip-address,192.168.0.2\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:nd98,option-nondigit-98\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            '99,option-99\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option:bootfile-name,pxelinux.0').lstrip()

        self._test_output_opts_file(expected, FakeV4NetworkPxePort())

    def test_output_opts_file_multiple_tags(self):
        expected = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
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
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,[2001:0200:feed:7ac0::1]\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal\n'
            'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:tftp-server,2001:192:168::1\n'
            'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:nd98,option-nondigit-98\n'
            'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:99,option-99\n'
            'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
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
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,[2001:0200:feed:7ac0::1]\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal\n'
            'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:bootfile-name,pxelinux.0')
        expected = expected.lstrip()

        dm = self._get_dnsmasq(FakeV6NetworkPxePortWrongOptVersion())
        dm._output_opts_file()

        self.safe.assert_called_once_with('/foo/opts', expected)

    def test_output_opts_file_ipv6_address_mode_unset(self):
        fake_v6 = '2001:0200:feed:7ac0::1'
        expected = (
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,%s\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal').lstrip() % (
                '[' + fake_v6 + ']')

        self._test_output_opts_file(expected, FakeV6Network())

    def test_output_opts_file_ipv6_address_force_metadata(self):
        fake_v6 = '2001:0200:feed:7ac0::1'
        expected = (
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,%s\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal').lstrip() % (
                '[' + fake_v6 + ']')
        self.conf.force_metadata = True
        self._test_output_opts_file(expected, FakeV6Network())

    def _test_no_dns_domain_alloc_data(self, tag=''):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,{tag}host-fdca-3ba5-a17a-4ba3--2,'
                         '[fdca:3ba5:a17a:4ba3::2]\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-3,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,{tag}host-fdca-3ba5-a17a-4ba3--3,'
                         '[fdca:3ba5:a17a:4ba3::3]\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1,'
                         '192.168.0.1\n').format(tag=tag).lstrip()
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

    def _test_reload_allocation_data(self, tag=''):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal.,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,{tag}host-fdca-3ba5-a17a-4ba3--2.'
                         'openstacklocal.,[fdca:3ba5:a17a:4ba3::2]\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-3.openstacklocal.,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,{tag}host-fdca-3ba5-a17a-4ba3--3.'
                         'openstacklocal.,[fdca:3ba5:a17a:4ba3::3]\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal.,'
                         '192.168.0.1\n').format(tag=tag).lstrip()
        exp_addn_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/addn_hosts'
        exp_addn_data = (
            '192.168.0.2\t'
            'host-192-168-0-2.openstacklocal. host-192-168-0-2\n'
            'fdca:3ba5:a17a:4ba3::2\t'
            'host-fdca-3ba5-a17a-4ba3--2.openstacklocal. '
            'host-fdca-3ba5-a17a-4ba3--2\n'
            '192.168.0.3\thost-192-168-0-3.openstacklocal. '
            'host-192-168-0-3\n'
            'fdca:3ba5:a17a:4ba3::3\t'
            'host-fdca-3ba5-a17a-4ba3--3.openstacklocal. '
            'host-fdca-3ba5-a17a-4ba3--3\n'
            '192.168.0.1\t'
            'host-192-168-0-1.openstacklocal. '
            'host-192-168-0-1\n'
        ).lstrip()
        exp_opt_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/opts'
        fake_v6 = '2001:0200:feed:7ac0::1'
        exp_opt_data = (
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:dns-server,%s\n'
            'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
            'option6:domain-search,openstacklocal').lstrip() % (
            '[' + fake_v6 + ']')
        return (exp_host_name, exp_host_data,
                exp_addn_name, exp_addn_data,
                exp_opt_name, exp_opt_data,)

    def test_reload_allocations_no_interface(self):
        net = FakeDualNetwork()
        ipath = '/dhcp/%s/interface' % net.id
        self.useFixture(lib_fixtures.OpenFixture(ipath))
        test_pm = mock.Mock()
        dm = self._get_dnsmasq(net, test_pm)
        dm.reload_allocations()
        self.assertFalse(test_pm.register.called)

    @mock.patch.object(checks, 'dnsmasq_host_tag_support', autospec=True)
    def test_reload_allocations(self, mock_tag_support):
        mock_tag_support.return_value = False
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data,
         exp_opt_name, exp_opt_data,) = self._test_reload_allocation_data()

        net = FakeDualNetwork()
        hpath = '/dhcp/%s/host' % net.id
        ipath = '/dhcp/%s/interface' % net.id
        self.useFixture(lib_fixtures.OpenFixture(hpath))
        self.useFixture(lib_fixtures.OpenFixture(ipath, 'tapdancingmice'))
        test_pm = mock.Mock()
        dm = self._get_dnsmasq(net, test_pm)
        dm.reload_allocations()
        self.assertTrue(test_pm.register.called)
        self.external_process().enable.assert_called_once_with(
            ensure_active=True, reload_cfg=True)

        self.safe.assert_has_calls([
            mock.call(exp_host_name, exp_host_data),
            mock.call(exp_addn_name, exp_addn_data),
            mock.call(exp_opt_name, exp_opt_data),
        ])

        mock_tag_support.return_value = True
        (exp_host_name, exp_host_data,
         exp_addn_name, exp_addn_data,
         exp_opt_name, exp_opt_data,) = self._test_reload_allocation_data(
            tag=dhcp.HOST_DHCPV6_TAG)
        test_pm.reset_mock()
        dm = self._get_dnsmasq(net, test_pm)
        dm.reload_allocations()
        self.assertTrue(test_pm.register.called)

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
        ip3 = '0001:0002:0003:0004:0005:0006:0007:0008'
        mac3 = '00:00:80:bb:aa:cc'

        old_leases = {(ip1, mac1, None), (ip2, mac2, None), (ip3, mac3, None)}
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip1: {'iaid': mac1,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip3: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'}
                          },
                         {}])

        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = []
        dnsmasq.device_manager.unplug = mock.Mock()

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_has_calls([mock.call(mac1, ip1,
                                                     constants.IP_VERSION_4,
                                                     None, 'server_id', mac1),
                                                 mock.call(mac2, ip2,
                                                     constants.IP_VERSION_4,
                                                     None, 'server_id', mac2),
                                                 mock.call(mac3, ip3,
                                                     constants.IP_VERSION_6,
                                                     'client_id', 'server_id',
                                                     0xff),
                                                 ],
                                                any_order=True)

    def test_release_for_ipv6_lease(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = 'fdca:3ba5:a17a::1'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.1.3'
        mac2 = '00:00:80:cc:bb:aa'

        old_leases = set([(ip1, mac1, 'client_id'), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip1: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': None,
                                'server_id': 'server_id'}
                          },
                         {}])
        mock_dhcp_release = mock.patch.object(priv_dhcp,
                                              'dhcp_release').start()
        mock_dhcp_release6 = mock.patch.object(priv_dhcp,
                                               'dhcp_release6').start()
        mock_dhcp_release6_supported = mock.patch.object(
            priv_dhcp, 'dhcp_release6_supported').start()
        dnsmasq._release_unused_leases()
        # Verify that dhcp_release is called both for ipv4 and ipv6 addresses.
        self.assertEqual(1, mock_dhcp_release.call_count)
        self.assertEqual(1, mock_dhcp_release6.call_count)
        mock_dhcp_release.assert_called_once_with(
            interface_name=None, ip_address=ip2, mac_address=mac2,
            client_id=None, namespace=dnsmasq.network.namespace)
        mock_dhcp_release6.assert_called_once_with(
            interface_name=None, ip_address=ip1, client_id='client_id',
            server_id='server_id', iaid=0xff,
            namespace=dnsmasq.network.namespace)
        mock_dhcp_release6_supported.assert_called_once_with()

    def test_release_for_ipv6_lease_no_dhcp_release6(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = 'fdca:3ba5:a17a::1'
        mac1 = '00:00:80:aa:bb:cc'

        old_leases = set([(ip1, mac1, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._read_leases_file_leases = mock.Mock(
            return_value={'fdca:3ba5:a17a::1': {'iaid': 0xff,
                                                'client_id': 'client_id',
                                                'server_id': 'server_id'}
                          })
        ipw = mock.patch(
            'neutron.agent.linux.ip_lib.IpNetnsCommand.execute').start()
        dnsmasq._IS_DHCP_RELEASE6_SUPPORTED = False
        dnsmasq._release_unused_leases()
        # Verify that dhcp_release6 is not called when it is not present
        ipw.assert_not_called()

    def test_release_unused_leases_with_dhcp_port(self):
        dnsmasq = self._get_dnsmasq(FakeNetworkDhcpPort())
        ip1 = '192.168.1.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.1.3'
        mac2 = '00:00:80:cc:bb:aa'
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, None), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._read_leases_file_leases = mock.Mock(
            return_value={ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'}
                          })
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.device_manager.get_device_id = mock.Mock(
            return_value='fake_dhcp_port')
        dnsmasq._release_unused_leases()
        self.assertFalse(
            dnsmasq.device_manager.unplug.called)
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
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, client_id1), (ip2, mac2, client_id2)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip1: {'iaid': mac1,
                                'client_id': client_id1,
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': client_id2,
                                'server_id': 'server_id'}
                          },
                         {ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'}
                          }])
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = []

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_has_calls(
            [mock.call(mac1, ip1, constants.IP_VERSION_4, client_id1,
                       'server_id', mac1),
             mock.call(mac2, ip2, constants.IP_VERSION_4, client_id2,
                       'server_id', mac2)],
            any_order=True)

    def test_release_unused_leases_one_lease(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.0.3'
        mac2 = '00:00:80:cc:bb:aa'
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, None), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': None,
                                'server_id': 'server_id'}
                          },
                         {ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'}
                          }])
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort1()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_called_once_with(
            mac2, ip2, constants.IP_VERSION_4, None, 'server_id', mac2)

    def test_release_unused_leases_one_lease_with_client_id(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        client_id1 = 'client1'
        ip2 = '192.168.0.5'
        mac2 = '00:00:0f:aa:bb:55'
        client_id2 = 'test5'
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, client_id1), (ip2, mac2, client_id2)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip1: {'iaid': mac1,
                                'client_id': client_id1,
                                'server_id': 'server_id'}
                          },
                         {ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'}
                          }])
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort5()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_called_once_with(
            mac1, ip1, constants.IP_VERSION_4, client_id1, 'server_id', mac1)

    def test_release_unused_leases_one_lease_with_client_id_none(self):
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        client_id1 = 'client1'
        ip2 = '192.168.0.4'
        mac2 = '00:16:3E:C2:77:1D'
        client_id2 = 'test4'
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, client_id1), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        dnsmasq._output_hosts_file = mock.Mock()
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip1: {'iaid': mac1,
                                'client_id': client_id1,
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': client_id2,
                                'server_id': 'server_id'}
                          },
                         {ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': client_id2,
                                'server_id': 'server_id'}
                          }])
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort4()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_called_once_with(
            mac1, ip1, constants.IP_VERSION_4, client_id1, 'server_id', mac1)

    def test_release_unused_leases_one_lease_from_leases_file(self):
        # leases file has a stale entry that is not in the host file
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.0.3'
        mac2 = '00:00:80:cc:bb:aa'
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        # Because the lease release code could fire multiple times, the
        # second read of the lease file must not have the entries that
        # would have been released.
        dnsmasq._read_leases_file_leases = mock.Mock(
            side_effect=[{ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'},
                          ip2: {'iaid': mac2,
                                'client_id': None,
                                'server_id': 'server_id'}
                          },
                         {ip6: {'iaid': 0xff,
                                'client_id': 'client_id',
                                'server_id': 'server_id'}
                          }])
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort1()]

        dnsmasq._release_unused_leases()

        dnsmasq._release_lease.assert_called_once_with(
            mac2, ip2, constants.IP_VERSION_4, None, 'server_id', mac2)

    @mock.patch.object(dhcp.LOG, 'warn')
    def _test_release_unused_leases_one_lease_mult_times(self, mock_log_warn,
                                                         removed):
        # Simulate a dhcp_release failure where the lease remains in the
        # lease file despite multiple dhcp_release calls
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())

        ip1 = '192.168.0.2'
        mac1 = '00:00:80:aa:bb:cc'
        ip2 = '192.168.0.3'
        mac2 = '00:00:80:cc:bb:aa'
        ip6 = '2001:0db8:11a3:09d7:1f34:8a2e:07a0:765d'

        old_leases = set([(ip1, mac1, None), (ip2, mac2, None)])
        dnsmasq._read_hosts_file_leases = mock.Mock(return_value=old_leases)
        # Because the lease release code could fire multiple times, the
        # second and subsequent reads of the lease file must have the
        # entries that were not released.
        side_effect = [{ip6: {'iaid': 0xff,
                              'client_id': 'client_id',
                              'server_id': 'server_id'},
                        ip2: {'iaid': mac2,
                              'client_id': None,
                              'server_id': 'server_id'}
                        },
                       {ip6: {'iaid': 0xff,
                              'client_id': 'client_id',
                              'server_id': 'server_id'},
                        ip2: {'iaid': mac2,
                              'client_id': None,
                              'server_id': 'server_id'}
                        },
                       {ip6: {'iaid': 0xff,
                              'client_id': 'client_id',
                              'server_id': 'server_id'},
                        ip2: {'iaid': mac2,
                              'client_id': None,
                              'server_id': 'server_id'}
                        }]
        # entry did/didn't go away after final dhcp_release try
        if not removed:
            side_effect.append(
                     {ip6: {'iaid': 0xff,
                            'client_id': 'client_id',
                            'server_id': 'server_id'},
                      ip2: {'iaid': mac2,
                            'client_id': None,
                            'server_id': 'server_id'}
                      })
        else:
            side_effect.append({})

        dnsmasq._read_leases_file_leases = mock.Mock(side_effect=side_effect)
        dnsmasq._output_hosts_file = mock.Mock()
        dnsmasq._release_lease = mock.Mock()
        dnsmasq.network.ports = [FakePort1()]

        dnsmasq._release_unused_leases()

        self.assertEqual(dhcp.DHCP_RELEASE_TRIES,
                         dnsmasq._release_lease.call_count)

        self.assertEqual(dhcp.DHCP_RELEASE_TRIES + 1,
                         dnsmasq._read_leases_file_leases.call_count)

        if not removed:
            self.assertTrue(mock_log_warn.called)

    def test_release_unused_leases_one_lease_mult_times_not_removed(self):
        self._test_release_unused_leases_one_lease_mult_times(False)

    def test_release_unused_leases_one_lease_mult_times_removed(self):
        self._test_release_unused_leases_one_lease_mult_times(True)

    def test__parse_ip_addresses(self):
        ip_list = ['192.168.0.1', '[fdca:3ba5:a17a::1]', 'no_ip_address']
        self.assertEqual(['192.168.0.1', 'fdca:3ba5:a17a::1'],
                         dhcp.Dnsmasq._parse_ip_addresses(ip_list))

    def _test_read_hosts_file_leases(self, lines, expected_result):
        filename = '/path/to/file'
        mock_open = self.useFixture(
            lib_fixtures.OpenFixture(filename, '\n'.join(lines))).mock_open
        dnsmasq = self._get_dnsmasq(FakeDualNetwork())
        leases = dnsmasq._read_hosts_file_leases(filename)
        self.assertEqual(expected_result, leases)
        mock_open.assert_called_once_with(filename)

    def test_read_hosts_file_leases(self):
        lines = ["00:00:80:aa:bb:cc,inst-name,192.168.0.1",
                 "00:00:80:aa:bb:cc,inst-name,[fdca:3ba5:a17a::1]"]
        result = {("192.168.0.1", "00:00:80:aa:bb:cc", None),
                  ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc", None)}
        self._test_read_hosts_file_leases(lines, result)

    def test_read_hosts_file_leases_with_client_id(self):
        lines = ["00:00:80:aa:bb:cc,id:client1,inst-name,192.168.0.1",
                 "00:00:80:aa:bb:cc,id:client2,inst-name,"
                 "[fdca:3ba5:a17a::1]"]
        result = {("192.168.0.1", "00:00:80:aa:bb:cc", 'client1'),
                  ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc", 'client2')}
        self._test_read_hosts_file_leases(lines, result)

    def test_read_hosts_file_leases_with_stateless_IPv6_tag(self):
        lines = [
            "00:00:80:aa:bb:cc,id:client1,inst-name,192.168.0.1",
            "00:00:80:aa:bb:cc,set:ccccccccc-cccc-cccc-cccc-cccccccc",
            "00:00:80:aa:bb:cc,id:client2,inst-name,[fdca:3ba5:a17a::1]"]
        result = {("192.168.0.1", "00:00:80:aa:bb:cc", 'client1'),
                  ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc", 'client2')}
        self._test_read_hosts_file_leases(lines, result)

    def test_read_hosts_file_leases_with_IPv6_tag_and_multiple_ips(self):
        lines = [
            "00:00:80:aa:bb:cc,id:client1,inst-name,192.168.0.1",
            "00:00:80:aa:bb:cc,set:ccccccccc-cccc-cccc-cccc-cccccccc",
            "00:00:80:aa:bb:cc,tag:dhcpv6,inst-name,[fdca:3ba5:a17a::1],"
            "[fdca:3ba5:a17a::2],[fdca:3ba5:a17a::3],[fdca:3ba5:a17a::4],"
            "set:port-fe2baee9-aba9-4b67-be03-be4aeee40cca"]
        result = {("192.168.0.1", "00:00:80:aa:bb:cc", 'client1'),
                  ("fdca:3ba5:a17a::1", "00:00:80:aa:bb:cc", None),
                  ("fdca:3ba5:a17a::2", "00:00:80:aa:bb:cc", None),
                  ("fdca:3ba5:a17a::3", "00:00:80:aa:bb:cc", None),
                  ("fdca:3ba5:a17a::4", "00:00:80:aa:bb:cc", None)}
        self._test_read_hosts_file_leases(lines, result)

    def _test_read_leases_file_leases(self, add_bad_line=False):
        filename = '/path/to/file'
        lines = [
                "1472673289 aa:bb:cc:00:00:02 192.168.1.2 host-192-168-1-2 *",
                "1472673289 aa:bb:cc:00:00:03 192.168.1.3 host-192-168-1-3 *",
                "1472673289 aa:bb:cc:00:00:04 192.168.1.4 host-192-168-1-4 *",
                "duid 00:01:00:01:02:03:04:05:06:07:08:09:0a:0b",
                "1472597740 1044800001 [2001:DB8::a] host-2001-db8--a "
                "00:04:4a:d0:d2:34:19:2b:49:08:84:e8:34:bd:0c:dc:b9:3b",
                "1472597823 1044800002 [2001:DB8::b] host-2001-db8--b "
                "00:04:ce:96:53:3d:f2:c2:4c:4c:81:7d:db:c9:8d:d2:74:22:3b:0a",
                "1472599048 1044800003 [2001:DB8::c] host-2001-db8--c "
                "00:04:4f:f0:cd:ca:5e:77:41:bc:9d:7f:5c:33:31:37:5d:80:77:b4"
                 ]
        bad_line = '1472673289 aa:bb:cc:00:00:05 192.168.1.5 host-192.168-1-5'
        if add_bad_line:
            lines.append(bad_line)

        mock_open = self.useFixture(
            lib_fixtures.OpenFixture(filename, '\n'.join(lines))).mock_open

        dnsmasq = self._get_dnsmasq(FakeDualNetwork())
        with mock.patch('os.path.exists', return_value=True), \
                mock.patch.object(dhcp.LOG, 'warning') as mock_log_warn:
            leases = dnsmasq._read_leases_file_leases(filename)
        server_id = '00:01:00:01:02:03:04:05:06:07:08:09:0a:0b'
        entry1 = {'iaid': '1044800001',
                  'client_id': '00:04:4a:d0:d2:34:19:2b:49:08:84:'
                               'e8:34:bd:0c:dc:b9:3b',
                  'server_id': server_id
                  }
        entry2 = {'iaid': '1044800002',
                  'client_id': '00:04:ce:96:53:3d:f2:c2:4c:4c:81:'
                               '7d:db:c9:8d:d2:74:22:3b:0a',
                  'server_id': server_id
                  }
        entry3 = {'iaid': '1044800003',
                  'client_id': '00:04:4f:f0:cd:ca:5e:77:41:bc:9d:'
                               '7f:5c:33:31:37:5d:80:77:b4',
                  'server_id': server_id
                  }
        entry4 = {'iaid': 'aa:bb:cc:00:00:02',
                  'client_id': '*',
                  'server_id': None
                  }
        entry5 = {'iaid': 'aa:bb:cc:00:00:03',
                  'client_id': '*',
                  'server_id': None
                  }
        entry6 = {'iaid': 'aa:bb:cc:00:00:04',
                  'client_id': '*',
                  'server_id': None
                  }
        expected = {'2001:DB8::a': entry1,
                    '2001:DB8::b': entry2,
                    '2001:DB8::c': entry3,
                    '192.168.1.2': entry4,
                    '192.168.1.3': entry5,
                    '192.168.1.4': entry6
                    }

        mock_open.assert_called_once_with(filename)
        self.assertEqual(expected, leases)
        if add_bad_line:
            self.assertTrue(mock_log_warn.called)

    def test_read_all_leases_file_leases(self):
        self._test_read_leases_file_leases()

    def test_read_all_leases_file_leases_with_bad_line(self):
        self._test_read_leases_file_leases(add_bad_line=True)

    def test_make_subnet_interface_ip_map(self):
        with mock.patch('neutron.agent.linux.ip_lib.'
                        'get_devices_with_ip') as list_mock:
            list_mock.return_value = [{'cidr': '192.168.0.1/24'}]

            dm = self._get_dnsmasq(FakeDualNetwork())

            self.assertEqual(
                dm._make_subnet_interface_ip_map(),
                {FakeV4Subnet().id: '192.168.0.1'}
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
                mock_listdir.return_value = list(cases)

                result = dhcp.Dnsmasq.existing_dhcp_networks(self.conf)

                mock_listdir.assert_called_once_with(path)
                self.assertCountEqual(['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                       'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'],
                                      result)

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
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal.,'
                         '192.168.0.2\n'
                         '00:16:3E:C2:77:1D,host-192-168-0-4.openstacklocal.,'
                         '192.168.0.4\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal.,'
                         '192.168.0.1\n').lstrip()
        dm = self._get_dnsmasq(FakeDualStackNetworkSingleDHCP())
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name,
                                              exp_host_data)])

    def test_only_populates_dhcp_client_id(self):
        exp_host_name = '/dhcp/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/host'
        exp_host_data = (
            '00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal.,'
            '192.168.0.2\n'
            '00:00:0f:aa:bb:55,id:test5,'
            'host-192-168-0-5.openstacklocal.,'
            '192.168.0.5\n'
            '00:00:0f:aa:bb:66,id:test6,'
            'host-192-168-0-6.openstacklocal.,192.168.0.6,'
            'set:port-ccccccccc-cccc-cccc-cccc-ccccccccc\n').lstrip()

        dm = self._get_dnsmasq(FakeV4NetworkClientId())
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name,
                                              exp_host_data)])

    def test_only_populates_dhcp_enabled_subnet_on_a_network(self):
        exp_host_name = '/dhcp/cccccccc-cccc-cccc-cccc-cccccccccccc/host'
        exp_host_data = ('00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal.,'
                         '192.168.0.2\n'
                         '00:00:f3:aa:bb:cc,host-192-168-0-3.openstacklocal.,'
                         '192.168.0.3\n'
                         '00:00:0f:aa:bb:cc,host-192-168-0-4.openstacklocal.,'
                         '192.168.0.4\n'
                         '00:00:0f:rr:rr:rr,host-192-168-0-1.openstacklocal.,'
                         '192.168.0.1\n').lstrip()
        dm = self._get_dnsmasq(FakeDualNetworkSingleDHCP())
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name,
                                              exp_host_data)])

    @mock.patch.object(checks, 'dnsmasq_host_tag_support', autospec=True)
    def test_host_and_opts_file_on_stateless_dhcpv6_network(
            self, mock_tag_support):
        mock_tag_support.return_value = False
        exp_host_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/host'
        exp_host_data = (
            '00:16:3e:c2:77:1d,'
            'set:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n').lstrip()
        exp_opt_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/opts'
        exp_opt_data = ('tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
                        'option6:domain-search,openstacklocal\n'
                        'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
                        'option6:dns-server,ffea:3ba5:a17a:4ba3::100\n'
                        'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
                        'option6:malicious-option,aaa').lstrip()
        dm = self._get_dnsmasq(FakeV6NetworkStatelessDHCP())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

        mock_tag_support.return_value = True
        exp_host_data = (
            '00:16:3e:c2:77:1d,tag:dhcpv6,'
            'set:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n').lstrip()
        dm = self._get_dnsmasq(FakeV6NetworkStatelessDHCP())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

    @mock.patch.object(checks, 'dnsmasq_host_tag_support', autospec=True)
    def test_host_and_opts_file_on_stateful_dhcpv6_same_subnet_fixedips(
            self, mock_tag_support):
        mock_tag_support.return_value = False
        self.conf.set_override('dnsmasq_enable_addr6_list', True)
        exp_host_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/host'
        exp_host_data = (
            '00:00:f3:aa:bb:cc,host-fdca-3ba5-a17a-4ba3--2.openstacklocal.,'
            '[fdca:3ba5:a17a:4ba3::2],[fdca:3ba5:a17a:4ba3::4]\n'.lstrip())
        exp_opt_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/opts'
        exp_opt_data = ('tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
                        'option6:dns-server,[2001:0200:feed:7ac0::1]\n'
                        'tag:subnet-ffffffff-ffff-ffff-ffff-ffffffffffff,'
                        'option6:domain-search,openstacklocal').lstrip()
        dm = self._get_dnsmasq(FakeV6NetworkStatefulDHCPSameSubnetFixedIps())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

        mock_tag_support.return_value = True
        exp_host_data = (
            '00:00:f3:aa:bb:cc,tag:dhcpv6,'
            'host-fdca-3ba5-a17a-4ba3--2.openstacklocal.,'
            '[fdca:3ba5:a17a:4ba3::2],[fdca:3ba5:a17a:4ba3::4]\n'.lstrip())
        dm = self._get_dnsmasq(FakeV6NetworkStatefulDHCPSameSubnetFixedIps())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

    def test_host_and_opts_file_on_stateless_dhcpv6_network_no_dns(self):
        exp_host_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/host'
        exp_opt_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/opts'
        exp_opt_data = ('tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
                        'option6:dns-server\n'
                        'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
                        'option6:domain-search,openstacklocal').lstrip()
        dm = self._get_dnsmasq(FakeV6NetworkStatelessDHCPNoDnsProvided())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, ''),
                                    mock.call(exp_opt_name, exp_opt_data)])

    def test_host_file_on_net_with_v6_slaac_and_v4(self):
        exp_host_name = '/dhcp/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee/host'
        exp_host_data = (
            '00:00:80:aa:bb:cc,host-192-168-0-2.openstacklocal.,192.168.0.2,'
            'set:port-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee\n'
            '00:16:3E:C2:77:1D,host-192-168-0-4.openstacklocal.,192.168.0.4,'
            'set:port-gggggggg-gggg-gggg-gggg-gggggggggggg\n00:00:0f:rr:rr:rr,'
            'host-192-168-0-1.openstacklocal.,192.168.0.1,'
            'set:port-rrrrrrrr-rrrr-rrrr-rrrr-rrrrrrrrrrrr\n').lstrip()
        dm = self._get_dnsmasq(FakeDualStackNetworkingSingleDHCPTags())
        dm._output_hosts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data)])

    @mock.patch.object(checks, 'dnsmasq_host_tag_support', autospec=True)
    def test_host_and_opts_file_on_net_with_V6_stateless_and_V4_subnets(
            self, mock_tag_support):
        mock_tag_support.return_value = False
        exp_host_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/host'
        exp_host_data = (
            '00:16:3e:c2:77:1d,set:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n'
            '00:16:3e:c2:77:1d,host-192-168-0-3.openstacklocal.,'
            '192.168.0.3,set:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n'
            '00:00:0f:rr:rr:rr,'
            'host-192-168-0-1.openstacklocal.,192.168.0.1\n').lstrip()
        exp_opt_name = '/dhcp/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/opts'
        exp_opt_data = (
            'tag:subnet-eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee,'
            'option6:domain-search,openstacklocal\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:dns-server,8.8.8.8\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:classless-static-route,20.0.0.1/24,20.0.0.1,'
            '169.254.169.254/32,192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            '249,20.0.0.1/24,20.0.0.1,169.254.169.254/32,'
            '192.168.0.1,0.0.0.0/0,192.168.0.1\n'
            'tag:subnet-dddddddd-dddd-dddd-dddd-dddddddddddd,'
            'option:router,192.168.0.1\n'
            'tag:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh,'
            'option6:dns-server,ffea:3ba5:a17a:4ba3::100').lstrip()

        dm = self._get_dnsmasq(FakeNetworkWithV6SatelessAndV4DHCPSubnets())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

        mock_tag_support.return_value = True
        exp_host_data = (
            '00:16:3e:c2:77:1d,tag:dhcpv6,'
            'set:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n'
            '00:16:3e:c2:77:1d,host-192-168-0-3.openstacklocal.,'
            '192.168.0.3,set:port-hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh\n'
            '00:00:0f:rr:rr:rr,'
            'host-192-168-0-1.openstacklocal.,192.168.0.1\n').lstrip()
        dm = self._get_dnsmasq(FakeNetworkWithV6SatelessAndV4DHCPSubnets())
        dm._output_hosts_file()
        dm._output_opts_file()
        self.safe.assert_has_calls([mock.call(exp_host_name, exp_host_data),
                                    mock.call(exp_opt_name, exp_opt_data)])

    def test_has_metadata_subnet_returns_true(self):
        self.assertTrue(dhcp.Dnsmasq.has_metadata_subnet(
            [FakeV4MetadataSubnet()]))

    def test_has_metadata_subnet_returns_false(self):
        self.assertFalse(dhcp.Dnsmasq.has_metadata_subnet(
            [FakeV4Subnet()]))

    def test_should_enable_metadata_ovn_metadata_port_returns_false(self):
        self.assertFalse(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeNetworkDhcpandOvnMetadataPort()))

    def test_should_enable_metadata_isolated_network_returns_true(self):
        self.assertTrue(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4NetworkNoRouter()))

    def test_should_enable_metadata_isolated_network_returns_true_ipv6(self):
        self.assertTrue(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV6Network()))

    def test_should_enable_metadata_non_isolated_network_returns_false(self):
        self.assertFalse(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4NetworkDistRouter()))

    def test_should_enable_metadata_isolated_meta_disabled_returns_false(self):
        self.conf.set_override('enable_isolated_metadata', False)
        self.assertFalse(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4MetadataNetwork()))

    def test_should_enable_metadata_with_metadata_network_returns_true(self):
        self.conf.set_override('enable_metadata_network', True)
        self.assertTrue(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeV4MetadataNetwork()))

    def test_should_force_metadata_returns_true(self):
        self.conf.set_override("force_metadata", True)
        self.assertTrue(dhcp.Dnsmasq.should_enable_metadata(
            self.conf, FakeDualNetworkDualDHCP()))

    def _test__generate_opts_per_subnet_helper(
            self, config_opts, expected_mdt_ip,
            network_class=FakeNetworkDhcpPort):
        for key, value in config_opts.items():
            self.conf.set_override(key, value)
        dm = self._get_dnsmasq(network_class())
        with mock.patch('neutron.agent.linux.ip_lib.'
                        'get_devices_with_ip') as list_mock:
            list_mock.return_value = [{'cidr': alloc.ip_address + '/24'}
                                      for alloc in FakeDhcpPort().fixed_ips]
            options, idx_map = dm._generate_opts_per_subnet()

        contains_metadata_ip = any(['%s' % constants.METADATA_CIDR in line
                                    for line in options])
        self.assertEqual(expected_mdt_ip, contains_metadata_ip)

    def test__generate_opts_per_subnet_no_metadata(self):
        config = {'enable_isolated_metadata': False,
                  'force_metadata': False}
        self._test__generate_opts_per_subnet_helper(config, False)

    def test__generate_opts_per_subnet_with_metadata_port(self):
        config = {'enable_isolated_metadata': False,
                  'force_metadata': False}
        self._test__generate_opts_per_subnet_helper(config, True,
            network_class=FakeNetworkDhcpandOvnMetadataPort)

    def test__generate_opts_per_subnet_isolated_metadata_with_router(self):
        config = {'enable_isolated_metadata': True,
                  'force_metadata': False}
        self._test__generate_opts_per_subnet_helper(config, True)

    def test__generate_opts_per_subnet_forced_metadata(self):
        config = {'enable_isolated_metadata': False,
                  'force_metadata': True}
        self._test__generate_opts_per_subnet_helper(config, True)

    def test__generate_opts_per_subnet_forced_metadata_non_local_subnet(self):
        config = {'enable_isolated_metadata': False,
                  'force_metadata': True}
        self._test__generate_opts_per_subnet_helper(
            config, True, network_class=FakeNonLocalSubnets)

    def test_client_id_num(self):
        dm = self._get_dnsmasq(FakeV4NetworkClientIdNum())
        self.assertEqual('test_client_id_num',
                         dm._get_client_id(FakePortWithClientIdNum()))

    def test_client_id_num_str(self):
        dm = self._get_dnsmasq(FakeV4NetworkClientIdNumStr())
        self.assertEqual('test_client_id_num',
                         dm._get_client_id(FakePortWithClientIdNumStr()))


class TestDeviceManager(TestConfBase):
    def setUp(self):
        super(TestDeviceManager, self).setUp()
        ip_lib_patcher = mock.patch('neutron.agent.linux.dhcp.ip_lib')
        load_interface_driver_patcher = mock.patch(
            'neutron.agent.linux.dhcp.agent_common_utils.'
            'load_interface_driver')
        self.mock_ip_lib = ip_lib_patcher.start()
        self.mock_load_interface_driver = load_interface_driver_patcher.start()
        mock.patch.object(netutils, 'is_ipv6_enabled',
                          return_value=True).start()

    def _test_setup(self, load_interface_driver, ip_lib, use_gateway_ips):
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            # Create DeviceManager.
            self.conf.register_opt(cfg.BoolOpt('enable_isolated_metadata',
                                               default=False))
            self.conf.register_opt(cfg.BoolOpt('force_metadata',
                                               default=False))
            plugin = mock.Mock()
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            mgr = dhcp.DeviceManager(self.conf, plugin)
            load_interface_driver.assert_called_with(
                self.conf, get_networks_callback=plugin.get_networks)

            # Setup with no existing DHCP port - expect a new DHCP port to
            # be created.
            network = FakeDeviceManagerNetwork()
            network.project_id = 'Project A'

            def mock_create(dict):
                port = dhcp.DictModel(dict['port'])
                port.id = 'abcd-123456789'
                port.mac_address = '00-12-34-56-78-90'
                port.fixed_ips = [
                    dhcp.DictModel({'subnet_id': ip['subnet_id'],
                                    'ip_address': 'unique-IP-address'})
                    for ip in port.fixed_ips
                ]
                # server rudely gave us an extra address we didn't ask for
                port.fixed_ips.append(dhcp.DictModel(
                    {'subnet_id': 'ffffffff-6666-6666-6666-ffffffffffff',
                     'ip_address': '2003::f816:3eff:fe45:e893'}))
                return port

            plugin.create_dhcp_port.side_effect = mock_create
            mgr.driver.get_device_name.return_value = 'ns-XXX'
            mgr.driver.use_gateway_ips = use_gateway_ips
            ip_lib.ensure_device_is_ready.return_value = True
            mgr.setup(network)
            plugin.create_dhcp_port.assert_called_with(mock.ANY)

            mgr.driver.init_l3.assert_called_with('ns-XXX',
                                                  mock.ANY,
                                                  namespace='qdhcp-ns')
            cidrs = set(mgr.driver.init_l3.call_args[0][1])
            if use_gateway_ips:
                self.assertEqual(cidrs, set(['%s/%s' % (s.gateway_ip,
                                                        s.cidr.split('/')[1])
                                             for s in network.subnets]))
            else:
                self.assertEqual(cidrs, set(['unique-IP-address/24',
                                         'unique-IP-address/64']))

            # Now call setup again.  This time we go through the existing
            # port code path, and the driver's init_l3 method is called
            # again.
            plugin.create_dhcp_port.reset_mock()
            mgr.driver.init_l3.reset_mock()
            mgr.setup(network)
            mgr.driver.init_l3.assert_called_with('ns-XXX',
                                                  mock.ANY,
                                                  namespace='qdhcp-ns')
            cidrs = set(mgr.driver.init_l3.call_args[0][1])
            if use_gateway_ips:
                self.assertEqual(cidrs, set(['%s/%s' % (s.gateway_ip,
                                                        s.cidr.split('/')[1])
                                             for s in network.subnets]))
            else:
                self.assertEqual(cidrs, set(['unique-IP-address/24',
                                             'unique-IP-address/64']))
            self.assertFalse(plugin.create_dhcp_port.called)

    def test_setup_device_manager_dhcp_port_without_gateway_ips(self):
        self._test_setup(self.mock_load_interface_driver,
                         self.mock_ip_lib, use_gateway_ips=False)

    def test_setup_device_manager_dhcp_port_with_gateway_ips(self):
        self._test_setup(self.mock_load_interface_driver,
                         self.mock_ip_lib, use_gateway_ips=True)

    def _test_setup_reserved(self, enable_isolated_metadata=False,
                             force_metadata=False):
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            # Create DeviceManager.
            self.conf.register_opt(
                cfg.BoolOpt('enable_isolated_metadata',
                            default=enable_isolated_metadata))
            self.conf.register_opt(
                cfg.BoolOpt('force_metadata',
                            default=force_metadata))
            plugin = mock.Mock()
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            mgr = dhcp.DeviceManager(self.conf, plugin)
            self.mock_load_interface_driver.assert_called_with(
                self.conf, get_networks_callback=plugin.get_networks)

            # Setup with a reserved DHCP port.
            network = FakeDualNetworkReserved()
            network.project_id = 'Project A'
            reserved_port = network.ports[-1]

            def mock_update(port_id, dict):
                port = reserved_port
                port.network_id = dict['port']['network_id']
                port.device_id = dict['port']['device_id']
                return port

            plugin.update_dhcp_port.side_effect = mock_update
            mgr.driver.get_device_name.return_value = 'ns-XXX'
            mgr.driver.use_gateway_ips = False
            self.mock_ip_lib.ensure_device_is_ready.return_value = True
            mgr.setup(network)
            plugin.update_dhcp_port.assert_called_with(reserved_port.id,
                                                       mock.ANY)

            expect_ips = ['192.168.0.6/24', 'fdca:3ba5:a17a:4ba3::2/64']
            if enable_isolated_metadata or force_metadata:
                expect_ips.extend([
                    constants.METADATA_CIDR,
                    common_constants.METADATA_V6_CIDR])
            mgr.driver.init_l3.assert_called_with('ns-XXX',
                                                  expect_ips,
                                                  namespace='qdhcp-ns')

    def test_setup_reserved_and_disable_metadata(self):
        """Test reserved port case of DeviceManager's DHCP port setup
        logic which metadata disabled.
        """
        self._test_setup_reserved()

    def test_setup_reserved_with_isolated_metadata_enable(self):
        """Test reserved port case of DeviceManager's DHCP port setup
        logic which isolated_ metadata enabled.
        """
        self._test_setup_reserved(enable_isolated_metadata=True)

    def test_setup_reserved_with_force_metadata_enable(self):
        """Test reserved port case of DeviceManager's DHCP port setup
        logic which force_metadata enabled.
        """
        self._test_setup_reserved(force_metadata=True)

    def test_setup_reserved_and_enable_metadata(self):
        """Test reserved port case of DeviceManager's DHCP port setup
        logic which both isolated_metadata and force_metadata enabled.
        """
        self._test_setup_reserved(enable_isolated_metadata=True,
                                  force_metadata=True)

    def test_setup_reserved_2(self):
        """Test scenario where a network has two reserved ports, and
        update_dhcp_port fails for the first of those.
        """
        with mock.patch.object(dhcp.ip_lib, 'IPDevice') as mock_IPDevice:
            # Create DeviceManager.
            self.conf.register_opt(
                cfg.BoolOpt('enable_isolated_metadata', default=False))
            self.conf.register_opt(
                cfg.BoolOpt('force_metadata', default=False))
            plugin = mock.Mock()
            device = mock.Mock()
            mock_IPDevice.return_value = device
            device.route.get_gateway.return_value = None
            mgr = dhcp.DeviceManager(self.conf, plugin)
            self.mock_load_interface_driver.assert_called_with(
                self.conf, get_networks_callback=plugin.get_networks)

            # Setup with a reserved DHCP port.
            network = FakeDualNetworkReserved2()
            network.project_id = 'Project A'
            reserved_port_1 = network.ports[-2]
            reserved_port_2 = network.ports[-1]

            def mock_update(port_id, dict):
                if port_id == reserved_port_1.id:
                    return None

                port = reserved_port_2
                port.network_id = dict['port']['network_id']
                port.device_id = dict['port']['device_id']
                return port

            plugin.update_dhcp_port.side_effect = mock_update
            mgr.driver.get_device_name.return_value = 'ns-XXX'
            mgr.driver.use_gateway_ips = False
            self.mock_ip_lib.ensure_device_is_ready.return_value = True
            mgr.setup(network)
            plugin.update_dhcp_port.assert_called_with(reserved_port_2.id,
                                                       mock.ANY)

            mgr.driver.init_l3.assert_called_with(
                'ns-XXX', ['192.168.0.6/24', 'fdca:3ba5:a17a:4ba3::2/64'],
                namespace='qdhcp-ns')

    def test__setup_reserved_dhcp_port_with_fake_remote_error(self):
        """Test scenario where a fake_network has two reserved ports, and
        update_dhcp_port fails for the first of those with a RemoteError.
        """
        # Setup with a reserved DHCP port.
        fake_network = FakeDualNetworkReserved2()
        fake_network.project_id = 'Project A'
        reserved_port_2 = fake_network.ports[-1]

        mock_plugin = mock.Mock()
        dh = dhcp.DeviceManager(cfg.CONF, mock_plugin)
        messaging_error = oslo_messaging.RemoteError(
            exc_type='FakeRemoteError')
        mock_plugin.update_dhcp_port.side_effect = [messaging_error,
                                                    reserved_port_2]

        with testtools.ExpectedException(oslo_messaging.RemoteError):
            dh.setup_dhcp_port(fake_network)


class TestDictModel(base.BaseTestCase):

    def setUp(self):
        super(TestDictModel, self).setUp()
        self._a = uuidutils.generate_uuid()
        self._b = uuidutils.generate_uuid()
        self.dm = dhcp.DictModel(a=self._a, b=self._b)

    def test_basic_dict(self):
        d = dict(a=1, b=2)
        m = dhcp.DictModel(d)
        self.assertEqual(1, m.a)
        self.assertEqual(2, m.b)

    def test_dict_has_sub_dict(self):
        d = dict(a=dict(b=2))
        m = dhcp.DictModel(d)
        self.assertEqual(2, m.a.b)

    def test_dict_contains_list(self):
        d = dict(a=[1, 2])
        m = dhcp.DictModel(d)
        self.assertEqual([1, 2], m.a)

    def test_dict_contains_list_of_dicts(self):
        d = dict(a=[dict(b=2), dict(c=3)])
        m = dhcp.DictModel(d)
        self.assertEqual(2, m.a[0].b)
        self.assertEqual(3, m.a[1].c)

    def test_string_representation_port(self):
        port = dhcp.DictModel({'id': 'id', 'network_id': 'net_id'})
        self.assertEqual('id=id, network_id=net_id', str(port))

    def test_string_representation_network(self):
        net = dhcp.DictModel({'id': 'id', 'name': 'myname'})
        self.assertEqual('id=id, name=myname', str(net))

    def test__init_parameters(self):
        self.assertEqual(self._a, self.dm.a)
        self.assertEqual(self._b, self.dm.b)

    def test__init_dictmodel(self):
        dm2 = dhcp.DictModel(self.dm)
        self.assertEqual(self._a, dm2.a)
        self.assertEqual(self._b, dm2.b)
        dm2.a = 'new_value'
        self.assertEqual('new_value', dm2.a)
        self.assertEqual(self._a, self.dm.a)

    def test__getattr(self):
        self.assertEqual({'a': self._a, 'b': self._b},
                         self.dm._dictmodel_internal_storage)
        try:
            self.dm.z
        except AttributeError:
            pass
        except Exception:
            self.fail('Getting a non existing attribute from a DictModel '
                      'object should raise AttributeError')

    def test__setattr(self):
        self.dm.c = 'c_value'
        self.assertEqual('c_value', self.dm.c)

    def test__delattr(self):
        del self.dm.a
        self.assertIsNone(self.dm.get('a'))

    def test__str(self):
        reference = 'a=%s, b=%s' % (self._a, self._b)
        self.assertEqual(reference, str(self.dm))

    def test__getitem(self):
        self.assertEqual(self._a, self.dm['a'])
        self.assertEqual(self._b, self.dm['b'])

    def test__setitem(self):
        self.dm['a'] = 'a_new_value'
        self.assertEqual('a_new_value', self.dm.a)
        self.assertEqual('a_new_value', self.dm['a'])
        self.assertEqual(self._b, self.dm.b)

    def test__iter(self):
        list_keys = sorted(list(self.dm))
        self.assertEqual(['a', 'b'], list_keys)

    def test__len(self):
        self.assertEqual(2, len(self.dm))

    def test__copy_and_deepcopy(self):
        for method in (copy.copy, copy.deepcopy):
            self.dm._tuple = (10, 11)
            self.dm._list = [20, 21]
            dm2 = method(self.dm)
            dm2._tuple = (30, 31)
            dm2._list[0] = 200
            self.assertEqual((10, 11), self.dm._tuple)
            self.assertEqual([20, 21], self.dm._list)
            self.assertEqual((30, 31), dm2._tuple)
            self.assertEqual([200, 21], dm2._list)
