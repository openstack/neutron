# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import testtools

from neutron.agent.linux import keepalived
from neutron.common import constants as n_consts
from neutron.tests import base

# Keepalived user guide:
# http://www.keepalived.org/pdf/UserGuide.pdf


class KeepalivedGetFreeRangeTestCase(base.BaseTestCase):
    def test_get_free_range(self):
        free_range = keepalived.get_free_range(
            parent_range='169.254.0.0/16',
            excluded_ranges=['169.254.0.0/24',
                             '169.254.1.0/24',
                             '169.254.2.0/24'],
            size=24)
        self.assertEqual('169.254.3.0/24', free_range)

    def test_get_free_range_without_excluded(self):
        free_range = keepalived.get_free_range(
            parent_range='169.254.0.0/16',
            excluded_ranges=[],
            size=20)
        self.assertEqual('169.254.0.0/20', free_range)

    def test_get_free_range_excluded_out_of_parent(self):
        free_range = keepalived.get_free_range(
            parent_range='169.254.0.0/16',
            excluded_ranges=['255.255.255.0/24'],
            size=24)
        self.assertEqual('169.254.0.0/24', free_range)

    def test_get_free_range_not_found(self):
        tiny_parent_range = '192.168.1.0/24'
        huge_size = 8
        with testtools.ExpectedException(ValueError):
            keepalived.get_free_range(
                parent_range=tiny_parent_range,
                excluded_ranges=[],
                size=huge_size)


class KeepalivedConfBaseMixin(object):

    def _get_config(self):
        config = keepalived.KeepalivedConf()

        instance1 = keepalived.KeepalivedInstance('MASTER', 'eth0', 1,
                                                  ['169.254.192.0/18'],
                                                  advert_int=5)
        instance1.set_authentication('AH', 'pass123')
        instance1.track_interfaces.append("eth0")

        vip_address1 = keepalived.KeepalivedVipAddress('192.168.1.0/24',
                                                       'eth1')

        vip_address2 = keepalived.KeepalivedVipAddress('192.168.2.0/24',
                                                       'eth2')

        vip_address3 = keepalived.KeepalivedVipAddress('192.168.3.0/24',
                                                       'eth2')

        vip_address_ex = keepalived.KeepalivedVipAddress('192.168.55.0/24',
                                                         'eth10')

        instance1.vips.append(vip_address1)
        instance1.vips.append(vip_address2)
        instance1.vips.append(vip_address3)
        instance1.vips.append(vip_address_ex)

        virtual_route = keepalived.KeepalivedVirtualRoute(n_consts.IPv4_ANY,
                                                          "192.168.1.1",
                                                          "eth1")
        instance1.virtual_routes.append(virtual_route)

        instance2 = keepalived.KeepalivedInstance('MASTER', 'eth4', 2,
                                                  ['169.254.192.0/18'],
                                                  mcast_src_ip='224.0.0.1')
        instance2.track_interfaces.append("eth4")

        vip_address1 = keepalived.KeepalivedVipAddress('192.168.3.0/24',
                                                       'eth6')

        instance2.vips.append(vip_address1)
        instance2.vips.append(vip_address2)
        instance2.vips.append(vip_address_ex)

        config.add_instance(instance1)
        config.add_instance(instance2)

        return config


class KeepalivedConfTestCase(base.BaseTestCase,
                             KeepalivedConfBaseMixin):

    expected = """vrrp_instance VR_1 {
    state MASTER
    interface eth0
    virtual_router_id 1
    priority 50
    garp_master_repeat 5
    garp_master_refresh 10
    advert_int 5
    authentication {
        auth_type AH
        auth_pass pass123
    }
    track_interface {
        eth0
    }
    virtual_ipaddress {
        169.254.0.1/24 dev eth0
    }
    virtual_ipaddress_excluded {
        192.168.1.0/24 dev eth1
        192.168.2.0/24 dev eth2
        192.168.3.0/24 dev eth2
        192.168.55.0/24 dev eth10
    }
    virtual_routes {
        0.0.0.0/0 via 192.168.1.1 dev eth1
    }
}
vrrp_instance VR_2 {
    state MASTER
    interface eth4
    virtual_router_id 2
    priority 50
    garp_master_repeat 5
    garp_master_refresh 10
    mcast_src_ip 224.0.0.1
    track_interface {
        eth4
    }
    virtual_ipaddress {
        169.254.0.2/24 dev eth4
    }
    virtual_ipaddress_excluded {
        192.168.2.0/24 dev eth2
        192.168.3.0/24 dev eth6
        192.168.55.0/24 dev eth10
    }
}"""

    def test_config_generation(self):
        config = self._get_config()
        self.assertEqual(self.expected, config.get_config_str())

    def test_config_with_reset(self):
        config = self._get_config()
        self.assertEqual(self.expected, config.get_config_str())

        config.reset()
        self.assertEqual('', config.get_config_str())

    def test_get_existing_vip_ip_addresses_returns_list(self):
        config = self._get_config()
        instance = config.get_instance(1)
        current_vips = sorted(instance.get_existing_vip_ip_addresses('eth2'))
        self.assertEqual(['192.168.2.0/24', '192.168.3.0/24'], current_vips)


class KeepalivedStateExceptionTestCase(base.BaseTestCase):
    def test_state_exception(self):
        invalid_vrrp_state = 'a seal walks'
        self.assertRaises(keepalived.InvalidInstanceStateException,
                          keepalived.KeepalivedInstance,
                          invalid_vrrp_state, 'eth0', 33,
                          ['169.254.192.0/18'])

        invalid_auth_type = 'into a club'
        instance = keepalived.KeepalivedInstance('MASTER', 'eth0', 1,
                                                 ['169.254.192.0/18'])
        self.assertRaises(keepalived.InvalidAuthenticationTypeException,
                          instance.set_authentication,
                          invalid_auth_type, 'some_password')


class KeepalivedInstanceTestCase(base.BaseTestCase,
                                 KeepalivedConfBaseMixin):
    def test_get_primary_vip(self):
        instance = keepalived.KeepalivedInstance('MASTER', 'ha0', 42,
                                                 ['169.254.192.0/18'])
        self.assertEqual('169.254.0.42/24', instance.get_primary_vip())

    def test_remove_adresses_by_interface(self):
        config = self._get_config()
        instance = config.get_instance(1)
        instance.remove_vips_vroutes_by_interface('eth2')
        instance.remove_vips_vroutes_by_interface('eth10')

        expected = """vrrp_instance VR_1 {
    state MASTER
    interface eth0
    virtual_router_id 1
    priority 50
    garp_master_repeat 5
    garp_master_refresh 10
    advert_int 5
    authentication {
        auth_type AH
        auth_pass pass123
    }
    track_interface {
        eth0
    }
    virtual_ipaddress {
        169.254.0.1/24 dev eth0
    }
    virtual_ipaddress_excluded {
        192.168.1.0/24 dev eth1
    }
    virtual_routes {
        0.0.0.0/0 via 192.168.1.1 dev eth1
    }
}
vrrp_instance VR_2 {
    state MASTER
    interface eth4
    virtual_router_id 2
    priority 50
    garp_master_repeat 5
    garp_master_refresh 10
    mcast_src_ip 224.0.0.1
    track_interface {
        eth4
    }
    virtual_ipaddress {
        169.254.0.2/24 dev eth4
    }
    virtual_ipaddress_excluded {
        192.168.2.0/24 dev eth2
        192.168.3.0/24 dev eth6
        192.168.55.0/24 dev eth10
    }
}"""

        self.assertEqual(expected, config.get_config_str())

    def test_build_config_no_vips(self):
        expected = """vrrp_instance VR_1 {
    state MASTER
    interface eth0
    virtual_router_id 1
    priority 50
    garp_master_repeat 5
    garp_master_refresh 10
    virtual_ipaddress {
        169.254.0.1/24 dev eth0
    }
}"""
        instance = keepalived.KeepalivedInstance(
            'MASTER', 'eth0', 1, ['169.254.192.0/18'])
        self.assertEqual(expected, '\n'.join(instance.build_config()))


class KeepalivedVipAddressTestCase(base.BaseTestCase):
    def test_vip_with_scope(self):
        vip = keepalived.KeepalivedVipAddress('fe80::3e97:eff:fe26:3bfa/64',
                                              'eth1',
                                              'link')
        self.assertEqual('fe80::3e97:eff:fe26:3bfa/64 dev eth1 scope link',
                         vip.build_config())


class KeepalivedVirtualRouteTestCase(base.BaseTestCase):
    def test_virtual_route_with_dev(self):
        route = keepalived.KeepalivedVirtualRoute(n_consts.IPv4_ANY, '1.2.3.4',
                                                  'eth0')
        self.assertEqual('0.0.0.0/0 via 1.2.3.4 dev eth0',
                         route.build_config())

    def test_virtual_route_without_dev(self):
        route = keepalived.KeepalivedVirtualRoute('50.0.0.0/8', '1.2.3.4')
        self.assertEqual('50.0.0.0/8 via 1.2.3.4', route.build_config())
