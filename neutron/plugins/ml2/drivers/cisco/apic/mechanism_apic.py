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

from apicapi import apic_manager
import netaddr

from oslo.config import cfg

from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.apic import apic_model
from neutron.plugins.ml2.drivers.cisco.apic import config


LOG = log.getLogger(__name__)


class APICMechanismDriver(api.MechanismDriver):

    @staticmethod
    def get_apic_manager():
        apic_config = cfg.CONF.ml2_cisco_apic
        network_config = {
            'vlan_ranges': cfg.CONF.ml2_type_vlan.network_vlan_ranges,
            'switch_dict': config.create_switch_dictionary(),
        }
        return apic_manager.APICManager(apic_model.ApicDbModel(), log,
                                        network_config, apic_config)

    def initialize(self):
        self.apic_manager = APICMechanismDriver.get_apic_manager()
        self.apic_manager.ensure_infra_created_on_apic()

    def _perform_port_operations(self, context):
        # Get tenant details from port context
        tenant_id = context.current['tenant_id']

        # Get network
        network = context.network.current['id']

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

        host = context.host
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
                                                               dhcp_host, seg)
        if host not in dhcp_hosts:
            self.apic_manager.ensure_path_created_for_port(tenant_id, network,
                                                           host, seg)

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
