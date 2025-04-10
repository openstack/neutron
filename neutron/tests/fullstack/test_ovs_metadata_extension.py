# Copyright (c) 2023 China Unicom Cloud Data Co.,Ltd.
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

import netaddr
from neutron_lib import constants
from neutron_lib.plugins.ml2 import ovs_constants as p_const
from neutron_lib.plugins import utils as p_utils
from oslo_log import log as logging
from oslo_utils import uuidutils

from neutron.tests.common.exclusive_resources import ip_network
from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.fullstack.resources import machine

LOG = logging.getLogger(__name__)

METADATA_REQUEST_TIMEOUT = 60
METADATA_REQUEST_SLEEP = 5
TOO_MANY_REQUESTS_CODE = '429'


class OvsMetadataExtensionTestCase(base.BaseFullStackTestCase):
    number_of_hosts = 1

    def setUp(self):
        host_desc = [
            environment.HostDescription(
                l2_agent_type=constants.AGENT_TYPE_OVS,
                firewall_driver='openvswitch',
                l3_agent=True,
                dhcp_agent=False) for _ in range(self.number_of_hosts)]
        env_desc = environment.EnvironmentDescription(
            mech_drivers='openvswitch',
            has_metadata=True, metadata_host='127.0.0.1',
            metadata_port=58775,
            host_proxy_listen_port=55555,
            enable_traditional_dhcp=False)
        env = environment.Environment(env_desc, host_desc)
        super().setUp(env)
        self.tenant_id = uuidutils.generate_uuid()
        self.vm_id_1 = uuidutils.generate_uuid()
        self.vm_id_2 = uuidutils.generate_uuid()

        network = self.safe_client.create_network(
            self.tenant_id, name='public', external=True)
        cidr = self.useFixture(
            ip_network.ExclusiveIPNetwork(
                "240.0.0.0", "240.255.255.255", "24")).network
        self.safe_client.create_subnet(
            self.tenant_id, network['id'], cidr)

        router = self.safe_client.create_router(
            self.tenant_id, external_network=network['id'])

        self.network = self.safe_client.create_network(
            self.tenant_id, 'network-test')
        subnet_routes_v4 = [
            {"destination": "1.1.1.0/24", "nexthop": "10.0.0.100"},
            {"destination": "2.2.2.2/32", "nexthop": "10.0.0.101"}]
        self.subnet_v4 = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            enable_dhcp=False,
            name='subnet-v4-test',
            host_routes=subnet_routes_v4)

        router_interface_info = self.safe_client.add_router_interface(
            router['id'], self.subnet_v4['id'])
        self.block_until_port_status_active(
            router_interface_info['port_id'])

        subnet_routes_v6 = [
            {"destination": "2001:4860:4860::8888/128",
             "nexthop": "fda7:a5cc:3460:1::1"},
            {"destination": "1234:5678:abcd::/64",
             "nexthop": "fda7:a5cc:3460:1::fff"}]
        self.subnet_v6 = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='fda7:a5cc:3460:1::/64',
            gateway_ip='fda7:a5cc:3460:1::1',
            enable_dhcp=True,
            ipv6_address_mode="dhcpv6-stateful",
            ipv6_ra_mode="dhcpv6-stateful",
            ip_version=6,
            name='subnet-v6-test',
            host_routes=subnet_routes_v6)

        # Need router radvd to send IPv6 address prefix to make the default
        # route work.
        router_interface_info = self.safe_client.add_router_interface(
            router['id'], self.subnet_v6['id'])
        self.block_until_port_status_active(
            router_interface_info['port_id'])

    def block_until_port_status_active(self, port_id):
        def is_port_status_active():
            port = self.client.show_port(port_id)
            return port['port']['status'] == 'ACTIVE'
        base.wait_until_true(lambda: is_port_status_active(), sleep=1)

    def _prepare_vms(self):
        sgs = [self.safe_client.create_security_group(self.tenant_id)
               for _ in range(2)]

        port1 = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            device_owner="compute:test_ovs_meta_1",
            device_id=self.vm_id_1,
            security_groups=[sgs[0]['id']])

        port2 = self.safe_client.create_port(
            self.tenant_id, self.network['id'],
            self.environment.hosts[0].hostname,
            device_owner="compute:test_ovs_meta_2",
            device_id=self.vm_id_2,
            security_groups=[sgs[1]['id']])

        # insert security-group-rules allow icmp
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[0]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[0]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv6,
            protocol=constants.PROTO_NAME_ICMP)

        # insert security-group-rules allow icmp
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[1]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv4,
            protocol=constants.PROTO_NAME_ICMP)
        self.safe_client.create_security_group_rule(
            self.tenant_id, sgs[1]['id'],
            direction=constants.INGRESS_DIRECTION,
            ethertype=constants.IPv6,
            protocol=constants.PROTO_NAME_ICMP)

        vm1 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port1,
                use_dhcp=False,
                use_dhcp6=False))

        vm2 = self.useFixture(
            machine.FakeFullstackMachine(
                self.environment.hosts[0],
                self.network['id'],
                self.tenant_id,
                self.safe_client,
                neutron_port=port2,
                use_dhcp=False,
                use_dhcp6=False))
        return machine.FakeFullstackMachinesList([vm1, vm2])

    def _wait_for_metadata_flows_applied(self, vm, table, actions):

        def _is_metadata_flow_set(vm, table, actions):
            LOG.info("Metadata bridge verify actions: %s", actions)
            flows = vm.host.br_meta.dump_flows_for_table(table)
            flows_list = flows.splitlines()
            LOG.info("Metadata bridge flows_list: %s", flows_list)
            pattern = re.compile(
                r"^.* table={},.* actions={}".format(table,
                                                     re.escape(actions)))
            for flow in flows_list:
                if pattern.match(flow.strip()):
                    return True
            return False
        base.wait_until_true(lambda: _is_metadata_flow_set(
            vm, table, actions))

    def test_ovs_meta_agent_extension_verify_ovs_flows(self):
        vms = self._prepare_vms()
        vms.block_until_all_boot()

        # Check ovs flows
        vm_0_provider_ip = vms[0].bridge.get_value_from_other_config(
            vms[0].port.name, "provider_ip", value_type=str)
        vm_0_provider_mac = vms[0].bridge.get_value_from_other_config(
            vms[0].port.name, "provider_mac", value_type=str)

        actions_0 = ("strip_vlan,mod_dl_src:%s,"
                     "mod_nw_src:%s,resubmit(,87)") % (vm_0_provider_mac,
                                                       vm_0_provider_ip)
        self._wait_for_metadata_flows_applied(vms[0], 80, actions_0)

        vm_1_provider_ip = vms[1].bridge.get_value_from_other_config(
            vms[1].port.name, "provider_ip", value_type=str)
        vm_1_provider_mac = vms[1].bridge.get_value_from_other_config(
            vms[1].port.name, "provider_mac", value_type=str)
        actions_1 = ("strip_vlan,mod_dl_src:%s,"
                     "mod_nw_src:%s,resubmit(,87)") % (vm_1_provider_mac,
                                                       vm_1_provider_ip)
        self._wait_for_metadata_flows_applied(vms[1], 80, actions_1)

        tap_meta_ofport = vms[0].host.br_meta.get_port_ofport("tap-meta")
        self._wait_for_metadata_flows_applied(
            vms[0], 87,
            ("mod_dl_dst:fa:16:ee:00:00:01,mod_nw_dst:240.0.0.1,"
             "mod_tp_dst:55555,output:%s" % tap_meta_ofport))

        vm_0_provider_mac_hex = "0x%s" % (
            vm_0_provider_mac.replace(":", ""))
        vm_0_provider_ip_hex = "%x" % netaddr.IPAddress(vm_0_provider_ip)
        vm_0_arp_res_actions = (
            "load:0x2->NXM_OF_ARP_OP[],"
            "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],"
            "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],"
            "load:%s->NXM_NX_ARP_SHA[],"
            "load:0x%s->NXM_OF_ARP_SPA[],"
            "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
            "mod_dl_src:%s,IN_PORT") % (vm_0_provider_mac_hex,
                                        vm_0_provider_ip_hex,
                                        vm_0_provider_mac)
        self._wait_for_metadata_flows_applied(
            vms[0], 90, vm_0_arp_res_actions)

        vm_1_provider_mac_hex = "0x%s" % (vm_1_provider_mac.replace(":", ""))
        vm_1_provider_ip_hex = "%x" % netaddr.IPAddress(vm_1_provider_ip)
        vm_1_arp_res_actions = (
            "load:0x2->NXM_OF_ARP_OP[],"
            "move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],"
            "move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],"
            "load:%s->NXM_NX_ARP_SHA[],"
            "load:0x%s->NXM_OF_ARP_SPA[],"
            "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],"
            "mod_dl_src:%s,IN_PORT") % (vm_1_provider_mac_hex,
                                        vm_1_provider_ip_hex,
                                        vm_1_provider_mac)
        self._wait_for_metadata_flows_applied(
            vms[1], 90, vm_1_arp_res_actions)

        local_vlan = vms[0].bridge.get_port_tag_by_name(vms[0].port.name)

        patch_name = p_utils.get_interface_name(
            vms[0].host.br_meta.br_name,
            prefix=p_const.PEER_PHYSICAL_PREFIX)
        patch_ofport = vms[0].host.br_meta.get_port_ofport(patch_name)
        self._wait_for_metadata_flows_applied(
            vms[0], 91,
            ("mod_vlan_vid:%s,mod_dl_dst:%s,"
             "mod_nw_src:169.254.169.254,mod_nw_dst:%s,mod_tp_src:80,"
             "output:%s" % (local_vlan, vms[0].neutron_port['mac_address'],
                            vms[0].ip, patch_ofport)))
        local_vlan = vms[1].bridge.get_port_tag_by_name(vms[1].port.name)
        patch_name = p_utils.get_interface_name(
            vms[1].host.br_meta.br_name,
            prefix=p_const.PEER_PHYSICAL_PREFIX)
        patch_ofport = vms[1].host.br_meta.get_port_ofport(patch_name)
        self._wait_for_metadata_flows_applied(
            vms[1], 91,
            ("mod_vlan_vid:%s,mod_dl_dst:%s,"
             "mod_nw_src:169.254.169.254,mod_nw_dst:%s,mod_tp_src:80,"
             "output:%s" % (local_vlan, vms[1].neutron_port['mac_address'],
                            vms[1].ip, patch_ofport)))
