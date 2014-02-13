# Copyright (c) 2014 Cisco Systems Inc.
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
#
# @author: Arvind Somya (asomya@cisco.com), Cisco Systems Inc.

import netaddr

from oslo.config import cfg

from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.apic import apic_manager
from neutron.plugins.ml2.drivers.cisco.apic import exceptions as apic_exc


LOG = log.getLogger(__name__)


class APICMechanismDriver(api.MechanismDriver):

    def initialize(self):
        self.apic_manager = apic_manager.APICManager()

        # Create a Phys domain and VLAN namespace
        # Get vlan ns name
        ns_name = cfg.CONF.ml2_cisco_apic.apic_vlan_ns_name

        # Grab vlan ranges
        if len(cfg.CONF.ml2_type_vlan.network_vlan_ranges) != 1:
            raise apic_exc.ApicMultipleVlanRanges(
                cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        vlan_ranges = cfg.CONF.ml2_type_vlan.network_vlan_ranges[0]
        if ',' in vlan_ranges:
            raise apic_exc.ApicMultipleVlanRanges(vlan_ranges)
        (vlan_min, vlan_max) = vlan_ranges.split(':')[-2:]

        # Create VLAN namespace
        vlan_ns = self.apic_manager.ensure_vlan_ns_created_on_apic(ns_name,
                                                                   vlan_min,
                                                                   vlan_max)
        phys_name = cfg.CONF.ml2_cisco_apic.apic_vmm_domain
        # Create Physical domain
        self.apic_manager.ensure_phys_domain_created_on_apic(phys_name,
                                                             vlan_ns)

        # Create entity profile
        ent_name = cfg.CONF.ml2_cisco_apic.apic_entity_profile
        self.apic_manager.ensure_entity_profile_created_on_apic(ent_name)

        # Create function profile
        func_name = cfg.CONF.ml2_cisco_apic.apic_function_profile
        self.apic_manager.ensure_function_profile_created_on_apic(func_name)

        # Create infrastructure on apic
        self.apic_manager.ensure_infra_created_on_apic()

    def _perform_port_operations(self, context):
        # Get tenant details from port context
        tenant_id = context.current['tenant_id']

        # Get network
        network = context.network.current['id']
        net_name = context.network.current['name']

        # Get port
        port = context.current

        # Get segmentation id
        if not context.bound_segment:
            LOG.debug(_("Port %s is not bound to a segment"), port)
            return
        seg = None
        if (context.bound_segment.get(api.NETWORK_TYPE) in
            [constants.TYPE_VLAN]):
            seg = context.bound_segment.get(api.SEGMENTATION_ID)

        # Check if a compute port
        if not port['device_owner'].startswith('compute'):
            # Not a compute port, return
            return

        host = port.get(portbindings.HOST_ID)
        # Check host that the dhcp agent is running on
        filters = {'device_owner': 'network:dhcp',
                   'network_id': network}
        dhcp_ports = context._plugin.get_ports(context._plugin_context,
                                               filters=filters)
        dhcp_hosts = []
        for dhcp_port in dhcp_ports:
            dhcp_hosts.append(dhcp_port.get(portbindings.HOST_ID))

        # Create a static path attachment for this host/epg/switchport combo
        self.apic_manager.ensure_tenant_created_on_apic(tenant_id)
        if dhcp_hosts:
            for dhcp_host in dhcp_hosts:
                self.apic_manager.ensure_path_created_for_port(tenant_id,
                                                               network,
                                                               dhcp_host, seg,
                                                               net_name)
        if host not in dhcp_hosts:
            self.apic_manager.ensure_path_created_for_port(tenant_id, network,
                                                           host, seg, net_name)

    def create_port_postcommit(self, context):
        self._perform_port_operations(context)

    def update_port_postcommit(self, context):
        self._perform_port_operations(context)

    def create_network_postcommit(self, context):
        net_id = context.current['id']
        tenant_id = context.current['tenant_id']
        net_name = context.current['name']

        self.apic_manager.ensure_bd_created_on_apic(tenant_id, net_id)
        # Create EPG for this network
        self.apic_manager.ensure_epg_created_for_network(tenant_id, net_id,
                                                         net_name)

    def delete_network_postcommit(self, context):
        net_id = context.current['id']
        tenant_id = context.current['tenant_id']

        self.apic_manager.delete_bd_on_apic(tenant_id, net_id)
        self.apic_manager.delete_epg_for_network(tenant_id, net_id)

    def create_subnet_postcommit(self, context):
        tenant_id = context.current['tenant_id']
        network_id = context.current['network_id']
        gateway_ip = context.current['gateway_ip']
        cidr = netaddr.IPNetwork(context.current['cidr'])
        netmask = str(cidr.prefixlen)
        gateway_ip = gateway_ip + '/' + netmask

        self.apic_manager.ensure_subnet_created_on_apic(tenant_id, network_id,
                                                        gateway_ip)
