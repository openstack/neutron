# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Cisco Systems, Inc.
# All rights reserved.
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
# @author: Sumit Naiksatam, Cisco Systems, Inc.
# @author: Edgar Magana, Cisco Systems, Inc.
# @author: Arvind Somya, Cisco Systems, Inc. (asomya@cisco.com)
#

"""
PlugIn for Nexus OS driver
"""

import logging

from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.plugins.cisco.common import cisco_constants as const
from neutron.plugins.cisco.common import cisco_exceptions as cisco_exc
from neutron.plugins.cisco.common import config as conf
from neutron.plugins.cisco.db import network_db_v2 as cdb
from neutron.plugins.cisco.db import nexus_db_v2 as nxos_db
from neutron.plugins.cisco.l2device_plugin_base import L2DevicePluginBase


LOG = logging.getLogger(__name__)


class NexusPlugin(L2DevicePluginBase):
    """Nexus PlugIn Main Class."""
    _networks = {}

    def __init__(self):
        """Extract configuration parameters from the configuration file."""
        self._client = importutils.import_object(conf.CISCO.nexus_driver)
        LOG.debug(_("Loaded driver %s"), conf.CISCO.nexus_driver)
        self._nexus_switches = conf.get_device_dictionary()

    def create_network(self, network, attachment):
        """Create or update a network when an attachment is changed.

        This method is not invoked at the usual plugin create_network() time.
        Instead, it is invoked on create/update port.

        :param network: Network on which the port operation is happening
        :param attachment: Details about the owner of the port

        Create a VLAN in the appropriate switch/port, and configure the
        appropriate interfaces for this VLAN.
        """
        LOG.debug(_("NexusPlugin:create_network() called"))
        # Grab the switch IPs and ports for this host
        host_connections = []
        host = attachment['host_name']
        for switch_type, switch_ip, attr in self._nexus_switches:
            if str(attr) == str(host):
                port = self._nexus_switches[switch_type, switch_ip, attr]
                # Get ether type for port, assume an ethernet type
                # if none specified.
                if ':' in port:
                    etype, port_id = port.split(':')
                else:
                    etype, port_id = 'ethernet', port
                host_connections.append((switch_ip, etype, port_id))
        if not host_connections:
            raise cisco_exc.NexusComputeHostNotConfigured(host=host)

        vlan_id = network[const.NET_VLAN_ID]
        vlan_name = network[const.NET_VLAN_NAME]
        auto_create = True
        auto_trunk = True
        if cdb.is_provider_vlan(vlan_id):
            vlan_name = ''.join([conf.CISCO.provider_vlan_name_prefix,
                                 str(vlan_id)])
            auto_create = conf.CISCO.provider_vlan_auto_create
            auto_trunk = conf.CISCO.provider_vlan_auto_trunk

        # Check if this network is already in the DB
        for switch_ip, etype, port_id in host_connections:
            vlan_created = False
            vlan_trunked = False
            eport_id = '%s:%s' % (etype, port_id)
            # Check for switch vlan bindings
            try:
                # This vlan has already been created on this switch
                # via another operation, like SVI bindings.
                nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
                vlan_created = True
                auto_create = False
            except cisco_exc.NexusPortBindingNotFound:
                # No changes, proceed as normal
                pass

            try:
                nxos_db.get_port_vlan_switch_binding(eport_id, vlan_id,
                                                     switch_ip)
            except cisco_exc.NexusPortBindingNotFound:
                if auto_create and auto_trunk:
                    # Create vlan and trunk vlan on the port
                    LOG.debug(_("Nexus: create & trunk vlan %s"), vlan_name)
                    self._client.create_and_trunk_vlan(
                        switch_ip, vlan_id, vlan_name, etype, port_id)
                    vlan_created = True
                    vlan_trunked = True
                elif auto_create:
                    # Create vlan but do not trunk it on the port
                    LOG.debug(_("Nexus: create vlan %s"), vlan_name)
                    self._client.create_vlan(switch_ip, vlan_id, vlan_name)
                    vlan_created = True
                elif auto_trunk:
                    # Only trunk vlan on the port
                    LOG.debug(_("Nexus: trunk vlan %s"), vlan_name)
                    self._client.enable_vlan_on_trunk_int(
                        switch_ip, vlan_id, etype, port_id)
                    vlan_trunked = True

            try:
                instance = attachment[const.INSTANCE_ID]
                nxos_db.add_nexusport_binding(eport_id, str(vlan_id),
                                              switch_ip, instance)
            except Exception:
                with excutils.save_and_reraise_exception():
                    # Add binding failed, roll back any vlan creation/enabling
                    if vlan_created and vlan_trunked:
                        LOG.debug(_("Nexus: delete & untrunk vlan %s"),
                                  vlan_name)
                        self._client.delete_and_untrunk_vlan(switch_ip,
                                                             vlan_id,
                                                             etype, port_id)
                    elif vlan_created:
                        LOG.debug(_("Nexus: delete vlan %s"), vlan_name)
                        self._client.delete_vlan(switch_ip, vlan_id)
                    elif vlan_trunked:
                        LOG.debug(_("Nexus: untrunk vlan %s"), vlan_name)
                        self._client.disable_vlan_on_trunk_int(switch_ip,
                                                               vlan_id,
                                                               etype,
                                                               port_id)

        net_id = network[const.NET_ID]
        new_net_dict = {const.NET_ID: net_id,
                        const.NET_NAME: network[const.NET_NAME],
                        const.NET_PORTS: {},
                        const.NET_VLAN_NAME: vlan_name,
                        const.NET_VLAN_ID: vlan_id}
        self._networks[net_id] = new_net_dict
        return new_net_dict

    def add_router_interface(self, vlan_name, vlan_id, subnet_id,
                             gateway_ip, router_id):
        """Create VLAN SVI on the Nexus switch."""
        # Find a switch to create the SVI on
        switch_ip = self._find_switch_for_svi()
        if not switch_ip:
            raise cisco_exc.NoNexusSviSwitch()

        # Check if this vlan exists on the switch already
        try:
            nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
        except cisco_exc.NexusPortBindingNotFound:
            # Create vlan and trunk vlan on the port
            self._client.create_and_trunk_vlan(
                switch_ip, vlan_id, vlan_name, etype=None, nexus_port=None)
        # Check if a router interface has already been created
        try:
            nxos_db.get_nexusvm_bindings(vlan_id, router_id)
            raise cisco_exc.SubnetInterfacePresent(subnet_id=subnet_id,
                                                   router_id=router_id)
        except cisco_exc.NexusPortBindingNotFound:
            self._client.create_vlan_svi(switch_ip, vlan_id, gateway_ip)
            nxos_db.add_nexusport_binding('router', str(vlan_id),
                                          switch_ip, router_id)

            return True

    def remove_router_interface(self, vlan_id, router_id):
        """Remove VLAN SVI from the Nexus Switch."""
        # Grab switch_ip from database
        switch_ip = nxos_db.get_nexusvm_bindings(vlan_id,
                                                 router_id)[0].switch_ip

        # Delete the SVI interface from the switch
        self._client.delete_vlan_svi(switch_ip, vlan_id)

        # Invoke delete_port to delete this row
        # And delete vlan if required
        return self.delete_port(router_id, vlan_id)

    def _find_switch_for_svi(self):
        """Get a switch to create the SVI on."""
        LOG.debug(_("Grabbing a switch to create SVI"))
        nexus_switches = self._client.nexus_switches
        if conf.CISCO.svi_round_robin:
            LOG.debug(_("Using round robin to create SVI"))
            switch_dict = dict(
                (switch_ip, 0) for switch_ip, _ in nexus_switches)
            try:
                bindings = nxos_db.get_nexussvi_bindings()
                # Build a switch dictionary with weights
                for binding in bindings:
                    switch_ip = binding.switch_ip
                    if switch_ip not in switch_dict:
                        switch_dict[switch_ip] = 1
                    else:
                        switch_dict[switch_ip] += 1
                # Search for the lowest value in the dict
                if switch_dict:
                    switch_ip = min(switch_dict, key=switch_dict.get)
                    return switch_ip
            except cisco_exc.NexusPortBindingNotFound:
                pass

        LOG.debug(_("No round robin or zero weights, using first switch"))
        # Return the first switch in the config
        return conf.first_device_ip

    def delete_network(self, tenant_id, net_id, **kwargs):
        """Delete network.

        Not applicable to Nexus plugin. Defined here to satisfy abstract
        method requirements.
        """
        LOG.debug(_("NexusPlugin:delete_network() called"))  # pragma no cover

    def update_network(self, tenant_id, net_id, **kwargs):
        """Update the properties of a particular Virtual Network.

        Not applicable to Nexus plugin. Defined here to satisfy abstract
        method requirements.
        """
        LOG.debug(_("NexusPlugin:update_network() called"))  # pragma no cover

    def create_port(self, tenant_id, net_id, port_state, port_id, **kwargs):
        """Create port.

        Not applicable to Nexus plugin. Defined here to satisfy abstract
        method requirements.
        """
        LOG.debug(_("NexusPlugin:create_port() called"))  # pragma no cover

    def delete_port(self, device_id, vlan_id):
        """Delete port.

        Delete port bindings from the database and scan whether the network
        is still required on the interfaces trunked.
        """
        LOG.debug(_("NexusPlugin:delete_port() called"))
        # Delete DB row(s) for this port
        try:
            rows = nxos_db.get_nexusvm_bindings(vlan_id, device_id)
        except cisco_exc.NexusPortBindingNotFound:
            return

        auto_delete = True
        auto_untrunk = True
        if cdb.is_provider_vlan(vlan_id):
            auto_delete = conf.CISCO.provider_vlan_auto_create
            auto_untrunk = conf.CISCO.provider_vlan_auto_trunk
            LOG.debug(_("delete_network(): provider vlan %s"), vlan_id)

        instance_id = False
        for row in rows:
            instance_id = row['instance_id']
            switch_ip = row.switch_ip
            etype, nexus_port = '', ''
            if row['port_id'] == 'router':
                etype, nexus_port = 'vlan', row['port_id']
                auto_untrunk = False
            else:
                etype, nexus_port = row['port_id'].split(':')

            nxos_db.remove_nexusport_binding(row.port_id, row.vlan_id,
                                             row.switch_ip,
                                             row.instance_id)
            # Check whether there are any remaining instances using this
            # vlan on this Nexus port.
            try:
                nxos_db.get_port_vlan_switch_binding(row.port_id,
                                                     row.vlan_id,
                                                     row.switch_ip)
            except cisco_exc.NexusPortBindingNotFound:
                try:
                    if nexus_port and auto_untrunk:
                        # Untrunk the vlan from this Nexus interface
                        self._client.disable_vlan_on_trunk_int(
                            switch_ip, row.vlan_id, etype, nexus_port)

                    # Check whether there are any remaining instances
                    # using this vlan on the Nexus switch.
                    if auto_delete:
                        try:
                            nxos_db.get_nexusvlan_binding(row.vlan_id,
                                                          row.switch_ip)
                        except cisco_exc.NexusPortBindingNotFound:
                            # Delete this vlan from this switch
                            self._client.delete_vlan(switch_ip, row.vlan_id)
                except Exception:
                    # The delete vlan operation on the Nexus failed,
                    # so this delete_port request has failed. For
                    # consistency, roll back the Nexus database to what
                    # it was before this request.
                    with excutils.save_and_reraise_exception():
                        nxos_db.add_nexusport_binding(row.port_id,
                                                      row.vlan_id,
                                                      row.switch_ip,
                                                      row.instance_id)

        return instance_id

    def update_port(self, tenant_id, net_id, port_id, port_state, **kwargs):
        """Update port.

        Not applicable to Nexus plugin. Defined here to satisfy abstract
        method requirements.
        """
        LOG.debug(_("NexusPlugin:update_port() called"))  # pragma no cover

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id,
                       **kwargs):
        """Plug interfaces.

        Not applicable to Nexus plugin. Defined here to satisfy abstract
        method requirements.
        """
        LOG.debug(_("NexusPlugin:plug_interface() called"))  # pragma no cover

    def unplug_interface(self, tenant_id, net_id, port_id, **kwargs):
        """Unplug interface.

        Not applicable to Nexus plugin. Defined here to satisfy abstract
        method requirements.
        """
        LOG.debug(_("NexusPlugin:unplug_interface() called")
                  )  # pragma no cover
