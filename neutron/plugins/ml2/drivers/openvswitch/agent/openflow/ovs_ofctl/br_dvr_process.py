# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

# Copyright 2011 VMware, Inc.
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

from neutron_lib import constants


class OVSDVRProcessMixin(object):
    """Common logic for br-tun and br-phys' DVR_PROCESS tables.

    Inheriters should provide self.dvr_process_table_id and
    self.dvr_process_next_table_id.
    """

    def install_dvr_process_ipv4(self, vlan_tag, gateway_ip):
        # block ARP
        self.add_flow(table=self.dvr_process_table_id,
                      priority=3,
                      dl_vlan=vlan_tag,
                      proto='arp',
                      nw_dst=gateway_ip,
                      actions='drop')

    def delete_dvr_process_ipv4(self, vlan_tag, gateway_ip):
        self.delete_flows(table=self.dvr_process_table_id,
                          dl_vlan=vlan_tag,
                          proto='arp',
                          nw_dst=gateway_ip)

    def install_dvr_process_ipv6(self, vlan_tag, gateway_mac):
        # block RA
        self.add_flow(table=self.dvr_process_table_id,
                      priority=3,
                      dl_vlan=vlan_tag,
                      proto='icmp6',
                      icmp_type=constants.ICMPV6_TYPE_RA,
                      dl_src=gateway_mac,
                      actions='drop')

    def delete_dvr_process_ipv6(self, vlan_tag, gateway_mac):
        self.delete_flows(table=self.dvr_process_table_id,
                          dl_vlan=vlan_tag,
                          proto='icmp6',
                          icmp_type=constants.ICMPV6_TYPE_RA,
                          dl_src=gateway_mac)

    def install_dvr_process(self, vlan_tag, vif_mac, dvr_mac_address):
        self.add_flow(table=self.dvr_process_table_id,
                      priority=2,
                      dl_vlan=vlan_tag,
                      dl_dst=vif_mac,
                      actions="drop")
        self.add_flow(table=self.dvr_process_table_id,
                      priority=1,
                      dl_vlan=vlan_tag,
                      dl_src=vif_mac,
                      actions="mod_dl_src:%s,resubmit(,%s)" %
                      (dvr_mac_address, self.dvr_process_next_table_id))

    def delete_dvr_process(self, vlan_tag, vif_mac):
        self.delete_flows(table=self.dvr_process_table_id,
                          dl_vlan=vlan_tag,
                          dl_dst=vif_mac)
        self.delete_flows(table=self.dvr_process_table_id,
                          dl_vlan=vlan_tag,
                          dl_src=vif_mac)
