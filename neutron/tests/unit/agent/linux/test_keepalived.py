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

from neutron.agent.linux import keepalived
from neutron.tests import base

# Keepalived user guide:
# http://www.keepalived.org/pdf/UserGuide.pdf


class KeepalivedConfBaseMixin(object):

    def _get_config(self):
        config = keepalived.KeepalivedConf()

        group1 = keepalived.KeepalivedGroup(1)
        group2 = keepalived.KeepalivedGroup(2)

        group1.set_notify('master', '/tmp/script.sh')

        instance1 = keepalived.KeepalivedInstance('MASTER', 'eth0', 1,
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

        virtual_route = keepalived.KeepalivedVirtualRoute("0.0.0.0/0",
                                                          "192.168.1.1",
                                                          "eth1")
        instance1.virtual_routes.append(virtual_route)

        group1.add_instance(instance1)

        instance2 = keepalived.KeepalivedInstance('MASTER', 'eth4', 2,
                                                  mcast_src_ip='224.0.0.1')
        instance2.track_interfaces.append("eth4")

        vip_address1 = keepalived.KeepalivedVipAddress('192.168.3.0/24',
                                                       'eth6')

        instance2.vips.append(vip_address1)
        instance2.vips.append(vip_address2)
        instance2.vips.append(vip_address_ex)

        group2.add_instance(instance2)

        config.add_group(group1)
        config.add_instance(instance1)
        config.add_group(group2)
        config.add_instance(instance2)

        return config


class KeepalivedConfTestCase(base.BaseTestCase,
                             KeepalivedConfBaseMixin):

    expected = """vrrp_sync_group VG_1 {
    group {
        VR_1
    }
    notify_master "/tmp/script.sh"
}
vrrp_sync_group VG_2 {
    group {
        VR_2
    }
}
vrrp_instance VR_1 {
    state MASTER
    interface eth0
    virtual_router_id 1
    priority 50
    advert_int 5
    authentication {
        auth_type AH
        auth_pass pass123
    }
    track_interface {
        eth0
    }
    virtual_ipaddress {
        192.168.1.0/24 dev eth1
    }
    virtual_ipaddress_excluded {
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
    mcast_src_ip 224.0.0.1
    track_interface {
        eth4
    }
    virtual_ipaddress {
        192.168.2.0/24 dev eth2
    }
    virtual_ipaddress_excluded {
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


class KeepalivedStateExceptionTestCase(base.BaseTestCase):
    def test_state_exception(self):
        group = keepalived.KeepalivedGroup('group2')

        invalid_notify_state = 'a seal walks'
        self.assertRaises(keepalived.InvalidNotifyStateException,
                          group.set_notify,
                          invalid_notify_state, '/tmp/script.sh')

        invalid_vrrp_state = 'into a club'
        self.assertRaises(keepalived.InvalidInstanceStateException,
                          keepalived.KeepalivedInstance,
                          invalid_vrrp_state, 'eth0', 33)

        invalid_auth_type = '[hip, hip]'
        instance = keepalived.KeepalivedInstance('MASTER', 'eth0', 1)
        self.assertRaises(keepalived.InvalidAuthenticationTypeExecption,
                          instance.set_authentication,
                          invalid_auth_type, 'some_password')


class KeepalivedInstanceTestCase(base.BaseTestCase,
                                 KeepalivedConfBaseMixin):
    def test_remove_adresses_by_interface(self):
        config = self._get_config()
        instance = config.get_instance(1)
        instance.remove_vips_vroutes_by_interface('eth2')
        instance.remove_vips_vroutes_by_interface('eth10')

        expected = """vrrp_sync_group VG_1 {
    group {
        VR_1
    }
    notify_master "/tmp/script.sh"
}
vrrp_sync_group VG_2 {
    group {
        VR_2
    }
}
vrrp_instance VR_1 {
    state MASTER
    interface eth0
    virtual_router_id 1
    priority 50
    advert_int 5
    authentication {
        auth_type AH
        auth_pass pass123
    }
    track_interface {
        eth0
    }
    virtual_ipaddress {
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
    mcast_src_ip 224.0.0.1
    track_interface {
        eth4
    }
    virtual_ipaddress {
        192.168.2.0/24 dev eth2
    }
    virtual_ipaddress_excluded {
        192.168.3.0/24 dev eth6
        192.168.55.0/24 dev eth10
    }
}"""

        self.assertEqual(expected, config.get_config_str())


class KeepalivedVirtualRouteTestCase(base.BaseTestCase):
    def test_virtual_route_with_dev(self):
        route = keepalived.KeepalivedVirtualRoute('0.0.0.0/0', '1.2.3.4',
                                                  'eth0')
        self.assertEqual('0.0.0.0/0 via 1.2.3.4 dev eth0',
                         route.build_config())

    def test_virtual_route_without_dev(self):
        route = keepalived.KeepalivedVirtualRoute('50.0.0.0/8', '1.2.3.4')
        self.assertEqual('50.0.0.0/8 via 1.2.3.4', route.build_config())
