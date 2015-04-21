# Copyright 2015 Intel Corporation.
# Copyright 2015 Isaku Yamahata <isaku.yamahata at intel com>
#                               <isaku.yamahata at gmail com>
# All Rights Reserved.
#
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

from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_firewall
from neutron.agent import securitygroups_rpc as sg_cfg
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.functional.agent.linux import helpers
from neutron.tests.functional import base
from oslo_config import cfg


class IptablesFirewallTestCase(base.BaseSudoTestCase):
    MAC_REAL = "fa:16:3e:9a:2f:49"
    MAC_SPOOFED = "fa:16:3e:9a:2f:48"
    FAKE_SECURITY_GROUP_ID = "fake_sg_id"

    def _set_src_mac(self, mac):
        self.client.port.link.set_down()
        self.client.port.link.set_address(mac)
        self.client.port.link.set_up()

    def setUp(self):
        cfg.CONF.register_opts(sg_cfg.security_group_opts, 'SECURITYGROUP')
        super(IptablesFirewallTestCase, self).setUp()

        bridge = self.useFixture(net_helpers.LinuxBridgeFixture()).bridge
        self.client, self.server = self.useFixture(
            machine_fixtures.PeerMachines(bridge)).machines

        self.firewall = iptables_firewall.IptablesFirewallDriver(
            namespace=bridge.namespace)

        self._set_src_mac(self.MAC_REAL)

        client_br_port_name = net_helpers.VethFixture.get_peer_name(
            self.client.port.name)
        self.src_port_desc = {'admin_state_up': True,
                              'device': client_br_port_name,
                              'device_owner': 'compute:None',
                              'fixed_ips': [self.client.ip],
                              'mac_address': self.MAC_REAL,
                              'port_security_enabled': True,
                              'security_groups': [self.FAKE_SECURITY_GROUP_ID],
                              'status': 'ACTIVE'}

    # setup firewall on bridge and send packet from src_veth and observe
    # if sent packet can be observed on dst_veth
    def test_port_sec_within_firewall(self):
        client_ip_wrapper = ip_lib.IPWrapper(self.client.namespace)
        pinger = helpers.Pinger(client_ip_wrapper)

        # update the sg_group to make ping pass
        sg_rules = [{'ethertype': 'IPv4', 'direction': 'ingress',
                     'source_ip_prefix': '0.0.0.0/0', 'protocol': 'icmp'},
                    {'ethertype': 'IPv4', 'direction': 'egress'}]

        with self.firewall.defer_apply():
            self.firewall.update_security_group_rules(
                                                self.FAKE_SECURITY_GROUP_ID,
                                                sg_rules)
        self.firewall.prepare_port_filter(self.src_port_desc)
        pinger.assert_ping(self.server.ip)

        # modify the src_veth's MAC and test again
        self._set_src_mac(self.MAC_SPOOFED)
        pinger.assert_no_ping(self.server.ip)

        # update the port's port_security_enabled value and test again
        self.src_port_desc['port_security_enabled'] = False
        self.firewall.update_port_filter(self.src_port_desc)
        pinger.assert_ping(self.server.ip)
