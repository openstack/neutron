"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2011 Cisco Systems, Inc.  All rights reserved.
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
#
"""
from copy import deepcopy
import logging

from quantum.common import exceptions as exc
from quantum.plugins.cisco.l2device_inventory_base \
        import L2NetworkDeviceInventoryBase
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as cred
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_utils as cutil
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco.db import ucs_db as udb
from quantum.plugins.cisco.ucs \
        import cisco_ucs_inventory_configuration as conf
from quantum.plugins.cisco.ucs import cisco_ucs_network_driver

LOG = logging.getLogger(__name__)

"""
The _inventory data strcuture contains a nested disctioary:
    {"UCSM_IP: {"Chassis-ID": [Balde-ID, Blade-ID],
                "Chassis-ID": [Blade-ID, Blade-ID, Blade-ID]]},
     "UCSM_IP: {"Chassis-ID": [Balde-ID]}
    }
"""
"""
_inventory_state data structure is organized as below:
{ucsm_ip:
    {chassis_id:
        {blade_id:
            {'blade-data':
                {blade-dn-1: {blade-intf-data},
                 blade-dn-2: {blade-intf-data}
                }
            }
        }
    }
}
'blade-data': Blade Data dictionary has the following keys:
===========================================================
const.BLADE_INTF_DATA: This is a dictionary, with the key as the
                       dn of the interface, and the value as the
                       Blade Interface Dictionary described next
const.BLADE_UNRESERVED_INTF_COUNT: Number of unreserved interfaces
                                   on this blade

'blade-intf-data': Blade Interface dictionary has the following keys:
=====================================================================
const.BLADE_INTF_DN
const.BLADE_INTF_ORDER
const.BLADE_INTF_LINK_STATE
const.BLADE_INTF_OPER_STATE
const.BLADE_INTF_INST_TYPE
const.BLADE_INTF_RHEL_DEVICE_NAME
const.BLADE_INTF_RESERVATION
const.TENANTID
const.PORTID
const.PROFILE_ID
const.INSTANCE_ID
const.VIF_ID
"""


class UCSInventory(L2NetworkDeviceInventoryBase):
    """
    Manages the state of all the UCS chasses, and blades in
    the system
    """

    _inventory = {}
    _host_names = {}
    _inventory_state = {}

    def __init__(self):
        self._client = cisco_ucs_network_driver.CiscoUCSMDriver()
        self._load_inventory()

    def _load_inventory(self):
        """Load the inventory from a config file"""
        inventory = deepcopy(conf.INVENTORY)
        LOG.info("Loaded UCS inventory: %s\n" % inventory)
        LOG.info("Building UCS inventory state (this may take a while)...")

        for ucsm in inventory.keys():
            ucsm_ip = inventory[ucsm][const.IP_ADDRESS]
            inventory[ucsm].pop(const.IP_ADDRESS)
            chassis_dict = {}
            for chassis in inventory[ucsm].keys():
                chassis_id = inventory[ucsm][chassis][const.CHASSIS_ID]
                inventory[ucsm][chassis].pop(const.CHASSIS_ID)
                blade_list = []
                for blade in inventory[ucsm][chassis].keys():
                    blade_id = \
                            inventory[ucsm][chassis][blade][const.BLADE_ID]
                    host_name = \
                            inventory[ucsm][chassis][blade][const.HOST_NAME]
                    host_key = ucsm_ip + "-" + chassis_id + "-" + blade_id
                    self._host_names[host_key] = host_name
                    blade_list.append(blade_id)
                chassis_dict[chassis_id] = blade_list
            self._inventory[ucsm_ip] = chassis_dict

        self._build_inventory_state()

    def _build_inventory_state(self):
        """Populate the state of all the blades"""
        for ucsm_ip in self._inventory.keys():
            self._inventory_state[ucsm_ip] = {ucsm_ip: {}}
            ucsm_username = cred.Store.getUsername(ucsm_ip)
            ucsm_password = cred.Store.getPassword(ucsm_ip)
            chasses_state = {}
            self._inventory_state[ucsm_ip] = chasses_state
            ucsm = self._inventory[ucsm_ip]
            for chassis_id in ucsm.keys():
                blades_dict = {}
                chasses_state[chassis_id] = blades_dict
                for blade_id in ucsm[chassis_id]:
                    blade_data = self._get_initial_blade_state(chassis_id,
                                                               blade_id,
                                                               ucsm_ip,
                                                               ucsm_username,
                                                               ucsm_password)
                    blades_dict[blade_id] = blade_data

        LOG.debug("UCS Inventory state is: %s\n" % self._inventory_state)
        return True

    def _get_host_name(self, ucsm_ip, chassis_id, blade_id):
        """Get the hostname based on the blade info"""
        host_key = ucsm_ip + "-" + chassis_id + "-" + blade_id
        return self._host_names[host_key]

    def _get_initial_blade_state(self, chassis_id, blade_id, ucsm_ip,
                                 ucsm_username, ucsm_password):
        """Get the initial blade state"""
        blade_intf_data = self._client.get_blade_data(chassis_id, blade_id,
                                                      ucsm_ip, ucsm_username,
                                                      ucsm_password)

        unreserved_counter = 0

        for blade_intf in blade_intf_data.keys():
            dist_name = blade_intf_data[blade_intf][const.BLADE_INTF_DN]
            # We first make a pass through the state in UCSM
            # If a particular interface is showing as being allocated in
            # UCSM then it is definitely being used and so should be
            # marked as reserved, else we temporarily mark it as unreserved
            # based on the UCSM state, but may later change it if a port
            # association is found in the DB
            if not const.TENANTID in blade_intf_data[blade_intf].keys():
                blade_intf_data[blade_intf][const.TENANTID] = None
            if not const.PORTID in blade_intf_data[blade_intf].keys():
                blade_intf_data[blade_intf][const.PORTID] = None
            if not const.PROFILE_ID in blade_intf_data[blade_intf].keys():
                blade_intf_data[blade_intf][const.PROFILE_ID] = None
            if not const.INSTANCE_ID in blade_intf_data[blade_intf].keys():
                blade_intf_data[blade_intf][const.INSTANCE_ID] = None
            if not const.VIF_ID in blade_intf_data[blade_intf].keys():
                blade_intf_data[blade_intf][const.VIF_ID] = None

            if (blade_intf_data[blade_intf][const.BLADE_INTF_LINK_STATE] == \
                const.BLADE_INTF_STATE_UNALLOCATED  or \
                blade_intf_data[blade_intf][const.BLADE_INTF_LINK_STATE] == \
                const.BLADE_INTF_STATE_UNKNOWN) and \
               blade_intf_data[blade_intf][const.BLADE_INTF_OPER_STATE] == \
               const.BLADE_INTF_STATE_UNKNOWN:
                blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                        const.BLADE_INTF_UNRESERVED
                unreserved_counter += 1
            else:
                blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                        const.BLADE_INTF_RESERVED

            port_binding = udb.get_portbinding_dn(dist_name)
            if port_binding:
                # We have found a port binding for this interface in the DB,
                # so we have earlier marked this interface as unreserved, we
                # need to change it, and also load the state from the DB for
                # other associations
                intf_data = blade_intf_data[blade_intf]
                if intf_data[const.BLADE_INTF_RESERVATION] == \
                   const.BLADE_INTF_UNRESERVED:
                    unreserved_counter -= 1
                    intf_data[const.BLADE_INTF_RESERVATION] = \
                            const.BLADE_INTF_RESERVED
                intf_data[const.TENANTID] = \
                        port_binding[const.TENANTID]
                intf_data[const.PORTID] = \
                        port_binding[const.PORTID]
                intf_data[const.PROFILE_ID] = \
                        port_binding[const.PORTPROFILENAME]
                intf_data[const.INSTANCE_ID] = \
                        port_binding[const.INSTANCE_ID]
                intf_data[const.VIF_ID] = \
                        port_binding[const.VIF_ID]
        host_name = self._get_host_name(ucsm_ip, chassis_id, blade_id)
        blade_data = {const.BLADE_INTF_DATA: blade_intf_data,
                      const.BLADE_UNRESERVED_INTF_COUNT: unreserved_counter,
                      const.HOST_NAME: host_name}
        return blade_data

    def _get_blade_state(self, chassis_id, blade_id, ucsm_ip,
                                 ucsm_username, ucsm_password):
        """Get the blade state"""
        blade_intf_data = self._client.get_blade_data(chassis_id, blade_id,
                                                      ucsm_ip, ucsm_username,
                                                      ucsm_password)
        unreserved_counter = 0

        for blade_intf in blade_intf_data.keys():
            if (blade_intf_data[blade_intf][const.BLADE_INTF_LINK_STATE] == \
                const.BLADE_INTF_STATE_UNALLOCATED  or \
                blade_intf_data[blade_intf][const.BLADE_INTF_LINK_STATE] == \
                const.BLADE_INTF_STATE_UNKNOWN) and \
               blade_intf_data[blade_intf][const.BLADE_INTF_OPER_STATE] == \
               const.BLADE_INTF_STATE_UNKNOWN:
                blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                        const.BLADE_INTF_UNRESERVED
                unreserved_counter += 1
            else:
                blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                        const.BLADE_INTF_RESERVED

        blade_data = {const.BLADE_INTF_DATA: blade_intf_data,
                     const.BLADE_UNRESERVED_INTF_COUNT: unreserved_counter}
        return blade_data

    def _get_all_ucsms(self):
        """Return a list of the IPs of all the UCSMs in the system"""
        return {const.DEVICE_IP: self._inventory.keys()}

    def _get_blade_for_port(self, args):
        """
        Return the a dict with IP address of the blade
        on which a dynamic vnic was reserved for this port
        """
        tenant_id = args[0]
        net_id = args[1]
        port_id = args[2]
        rsvd_info = self._get_rsvd_blade_intf_by_port(tenant_id, port_id)
        if not rsvd_info:
            raise exc.PortNotFound(net_id=net_id, port_id=port_id)
        device_params = {const.DEVICE_IP: [rsvd_info[const.UCSM_IP]]}
        return device_params

    def _get_host_name_for_rsvd_intf(self, tenant_id, instance_id):
        """
        Return the hostname of the blade with a reserved instance
        for this tenant
        """
        for ucsm_ip in self._inventory_state.keys():
            ucsm = self._inventory_state[ucsm_ip]
            for chassis_id in ucsm.keys():
                for blade_id in ucsm[chassis_id]:
                    blade_data = ucsm[chassis_id][blade_id]
                    blade_intf_data = blade_data[const.BLADE_INTF_DATA]
                    for blade_intf in blade_intf_data.keys():
                        tmp = deepcopy(blade_intf_data[blade_intf])
                        intf_data = blade_intf_data[blade_intf]
                        if (intf_data[const.BLADE_INTF_RESERVATION] ==
                           const.BLADE_INTF_RESERVED and
                           intf_data[const.TENANTID] == tenant_id and
                           intf_data[const.INSTANCE_ID] is None):
                            intf_data[const.INSTANCE_ID] = instance_id
                            host_name = self._get_host_name(ucsm_ip,
                                                            chassis_id,
                                                            blade_id)
                            port_binding = udb.get_portbinding_dn(blade_intf)
                            port_id = port_binding[const.PORTID]
                            udb.update_portbinding(port_id,
                                                   instance_id=instance_id)
                            return host_name
        LOG.warn("Could not find a reserved dynamic nic for tenant: %s" %
                 tenant_id)
        return None

    def _get_instance_port(self, tenant_id, instance_id, vif_id):
        """
        Return the device name for a reserved interface
        """
        found_blade_intf_data = None
        for ucsm_ip in self._inventory_state.keys():
            ucsm = self._inventory_state[ucsm_ip]
            for chassis_id in ucsm.keys():
                for blade_id in ucsm[chassis_id]:
                    blade_data = ucsm[chassis_id][blade_id]
                    blade_intf_data = blade_data[const.BLADE_INTF_DATA]
                    for blade_intf in blade_intf_data.keys():
                        intf_data = blade_intf_data[blade_intf]
                        if intf_data[const.BLADE_INTF_RESERVATION] == \
                           const.BLADE_INTF_RESERVED and \
                           intf_data[const.TENANTID] == tenant_id and \
                           intf_data[const.INSTANCE_ID] == instance_id:
                            found_blade_intf_data = blade_intf_data
                            LOG.debug("Found blade %s associated with this" \
                                      " instance: %s" % \
                                      (blade_id,
                                       instance_id))
                            break

        if found_blade_intf_data:
            blade_intf_data = found_blade_intf_data
            for blade_intf in blade_intf_data.keys():
                intf_data = blade_intf_data[blade_intf]
                if intf_data[const.BLADE_INTF_RESERVATION] == \
                   const.BLADE_INTF_RESERVED and \
                   intf_data[const.TENANTID] == tenant_id and \
                   (not intf_data[const.VIF_ID]):
                    intf_data[const.VIF_ID] = vif_id
                    intf_data[const.INSTANCE_ID] = instance_id
                    port_binding = udb.get_portbinding_dn(blade_intf)
                    port_id = port_binding[const.PORTID]
                    udb.update_portbinding(port_id, instance_id=instance_id,
                                           vif_id=vif_id)
                    db.port_set_attachment_by_id(port_id, vif_id +
                                                 const.UNPLUGGED)
                    device_name = intf_data[const.BLADE_INTF_RHEL_DEVICE_NAME]
                    profile_name = port_binding[const.PORTPROFILENAME]
                    dynamicnic_details = \
                            {const.DEVICENAME: device_name,
                             const.UCSPROFILE: profile_name}
                    LOG.debug("Found reserved dynamic nic: %s" \
                              "associated with port %s" %
                              (intf_data, port_id))
                    LOG.debug("Returning dynamic nic details: %s" %
                              dynamicnic_details)
                    return dynamicnic_details

        LOG.warn("Could not find a reserved dynamic nic for tenant: %s" %
                 tenant_id)
        return None

    def _disassociate_vifid_from_port(self, tenant_id, instance_id, vif_id):
        """
        Disassociate a VIF-ID from a port, this happens when a
        VM is destroyed
        """
        for ucsm_ip in self._inventory_state.keys():
            ucsm = self._inventory_state[ucsm_ip]
            for chassis_id in ucsm.keys():
                for blade_id in ucsm[chassis_id]:
                    blade_data = ucsm[chassis_id][blade_id]
                    blade_intf_data = blade_data[const.BLADE_INTF_DATA]
                    for blade_intf in blade_intf_data.keys():
                        intf_data = blade_intf_data[blade_intf]
                        if intf_data[const.BLADE_INTF_RESERVATION] == \
                           const.BLADE_INTF_RESERVED and \
                           intf_data[const.TENANTID] == tenant_id and \
                           blade_intf_data[blade_intf][const.INSTANCE_ID] == \
                           instance_id and \
                           intf_data[const.VIF_ID][:const.UUID_LENGTH] == \
                           vif_id:
                            intf_data[const.VIF_ID] = None
                            intf_data[const.INSTANCE_ID] = None
                            port_binding = udb.get_portbinding_dn(blade_intf)
                            port_id = port_binding[const.PORTID]
                            udb.update_portbinding(port_id, instance_id=None,
                                                   vif_id=None)
                            db.port_unset_attachment_by_id(port_id)
                            LOG.debug("Disassociated VIF-ID: %s " \
                                      "from port: %s" \
                                      "in UCS inventory state for blade: %s" %
                                      (vif_id, port_id, intf_data))
                            device_params = {const.DEVICE_IP: [ucsm_ip],
                                             const.PORTID: port_id}
                            return device_params
        LOG.warn("Disassociating VIF-ID in UCS inventory failed. " \
                 "Could not find a reserved dynamic nic for tenant: %s" %
                 tenant_id)
        return None

    def _get_rsvd_blade_intf_by_port(self, tenant_id, port_id):
        """
        Lookup a reserved blade interface based on tenant_id and port_id
        and return the blade interface info
        """
        for ucsm_ip in self._inventory_state.keys():
            ucsm = self._inventory_state[ucsm_ip]
            for chassis_id in ucsm.keys():
                for blade_id in ucsm[chassis_id]:
                    blade_data = ucsm[chassis_id][blade_id]
                    blade_intf_data = blade_data[const.BLADE_INTF_DATA]
                    for blade_intf in blade_intf_data.keys():
                        if not blade_intf_data[blade_intf][const.PORTID] or \
                           not blade_intf_data[blade_intf][const.TENANTID]:
                            continue
                        intf_data = blade_intf_data[blade_intf]
                        if intf_data[const.BLADE_INTF_RESERVATION] == \
                           const.BLADE_INTF_RESERVED and \
                           intf_data[const.TENANTID] == tenant_id and \
                           intf_data[const.PORTID] == port_id:
                            interface_dn = intf_data[const.BLADE_INTF_DN]
                            blade_intf_info = {const.UCSM_IP: ucsm_ip,
                                               const.CHASSIS_ID: chassis_id,
                                               const.BLADE_ID: blade_id,
                                               const.BLADE_INTF_DN:
                                               interface_dn}
                            return blade_intf_info
        LOG.warn("Could not find a reserved nic for tenant: %s port: %s" %
                 (tenant_id, port_id))
        return None

    def _get_least_reserved_blade(self, intf_count=1):
        """Return the blade with least number of dynamic nics reserved"""
        unreserved_interface_count = 0
        least_reserved_blade_ucsm = None
        least_reserved_blade_chassis = None
        least_reserved_blade_id = None
        least_reserved_blade_data = None

        for ucsm_ip in self._inventory_state.keys():
            ucsm = self._inventory_state[ucsm_ip]
            for chassis_id in ucsm.keys():
                for blade_id in ucsm[chassis_id]:
                    blade_data = ucsm[chassis_id][blade_id]
                    if blade_data[const.BLADE_UNRESERVED_INTF_COUNT] > \
                       unreserved_interface_count:
                        unreserved_interface_count = \
                                blade_data[const.BLADE_UNRESERVED_INTF_COUNT]
                        least_reserved_blade_ucsm = ucsm_ip
                        least_reserved_blade_chassis = chassis_id
                        least_reserved_blade_id = blade_id
                        least_reserved_blade_data = blade_data

        if unreserved_interface_count < intf_count:
            LOG.warn("Not enough dynamic nics available on a single host." \
                     " Requested: %s, Maximum available: %s" %
                     (intf_count, unreserved_interface_count))
            return False

        least_reserved_blade_dict = \
                {const.LEAST_RSVD_BLADE_UCSM: least_reserved_blade_ucsm,
                 const.LEAST_RSVD_BLADE_CHASSIS: least_reserved_blade_chassis,
                 const.LEAST_RSVD_BLADE_ID: least_reserved_blade_id,
                 const.LEAST_RSVD_BLADE_DATA: least_reserved_blade_data}
        LOG.debug("Found dynamic nic %s available for reservation",
                  least_reserved_blade_dict)
        return least_reserved_blade_dict

    def reload_inventory(self):
        """Reload the inventory from a conf file"""
        self._load_inventory()

    def reserve_blade_interface(self, ucsm_ip, chassis_id, blade_id,
                                blade_data_dict, tenant_id, port_id,
                                portprofile_name):
        """Reserve an interface on a blade"""
        ucsm_username = cred.Store.getUsername(ucsm_ip)
        ucsm_password = cred.Store.getPassword(ucsm_ip)
        """
        We are first getting the updated UCSM-specific blade
        interface state
        """
        blade_data = self._get_blade_state(chassis_id, blade_id, ucsm_ip,
                                           ucsm_username, ucsm_password)
        blade_intf_data = blade_data[const.BLADE_INTF_DATA]
        #import sys
        #sys.exit(ucsm_ip)
        chassis_data = self._inventory_state[ucsm_ip][chassis_id]
        old_blade_intf_data = chassis_data[blade_id][const.BLADE_INTF_DATA]

        """
        We will now copy the older non-UCSM-specific blade
        interface state
        """
        for blade_intf in blade_intf_data.keys():
            old_intf_data = old_blade_intf_data[blade_intf]
            blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                    old_intf_data[const.BLADE_INTF_RESERVATION]
            blade_intf_data[blade_intf][const.TENANTID] = \
                    old_intf_data[const.TENANTID]
            blade_intf_data[blade_intf][const.PORTID] = \
                    old_intf_data[const.PORTID]
            blade_intf_data[blade_intf][const.PROFILE_ID] = \
                    old_intf_data[const.PROFILE_ID]
            blade_intf_data[blade_intf][const.INSTANCE_ID] = \
                    old_intf_data[const.INSTANCE_ID]
            blade_intf_data[blade_intf][const.VIF_ID] = \
                    old_intf_data[const.VIF_ID]

        blade_data[const.BLADE_UNRESERVED_INTF_COUNT] = \
                chassis_data[blade_id][const.BLADE_UNRESERVED_INTF_COUNT]
        """
        Now we will reserve an interface if its available
        """
        for blade_intf in blade_intf_data.keys():
            intf_data = blade_intf_data[blade_intf]
            if intf_data[const.BLADE_INTF_RESERVATION] == \
               const.BLADE_INTF_UNRESERVED:
                intf_data[const.BLADE_INTF_RESERVATION] = \
                        const.BLADE_INTF_RESERVED
                intf_data[const.TENANTID] = tenant_id
                intf_data[const.PORTID] = port_id
                #intf_data[const.PROFILE_ID] = \
                #        portprofile_name
                intf_data[const.INSTANCE_ID] = None
                dev_eth_name = intf_data[const.BLADE_INTF_RHEL_DEVICE_NAME]
                """
                We are replacing the older blade interface state with new
                """
                chassis_data[blade_id][const.BLADE_INTF_DATA] = blade_intf_data
                chassis_data[blade_id][const.BLADE_UNRESERVED_INTF_COUNT] -= 1
                host_name = self._get_host_name(ucsm_ip, chassis_id,
                                                       blade_id)
                reserved_nic_dict = {const.RESERVED_NIC_HOSTNAME: host_name,
                                   const.RESERVED_NIC_NAME: dev_eth_name,
                                   const.BLADE_INTF_DN: blade_intf}
                port_binding = udb.add_portbinding(port_id, blade_intf, None,
                                                   None, None, None)
                udb.update_portbinding(port_id,
                                       tenant_id=intf_data[const.TENANTID])
                LOG.debug("Reserved blade interface: %s\n" % reserved_nic_dict)
                return reserved_nic_dict

        LOG.warn("Dynamic nic %s could not be reserved for port-id: %s" %
                 (blade_data, port_id))
        return False

    def unreserve_blade_interface(self, ucsm_ip, chassis_id, blade_id,
                                  interface_dn):
        """Unreserve a previously reserved interface on a blade"""
        ucsm_username = cred.Store.getUsername(ucsm_ip)
        ucsm_password = cred.Store.getPassword(ucsm_ip)
        blade_data = self._inventory_state[ucsm_ip][chassis_id][blade_id]

        blade_data[const.BLADE_UNRESERVED_INTF_COUNT] += 1
        blade_intf = blade_data[const.BLADE_INTF_DATA][interface_dn]
        blade_intf[const.BLADE_INTF_RESERVATION] = const.BLADE_INTF_UNRESERVED
        blade_intf[const.TENANTID] = None
        blade_intf[const.PORTID] = None
        blade_intf[const.PROFILE_ID] = None
        blade_intf[const.INSTANCE_ID] = None
        blade_intf[const.VIF_ID] = None
        LOG.debug("Unreserved blade interface %s\n" % interface_dn)

    def add_blade(self, ucsm_ip, chassis_id, blade_id):
        """Add a blade to the inventory"""
        # TODO (Sumit)
        pass

    def get_all_networks(self, args):
        """Return all UCSM IPs"""
        LOG.debug("get_all_networks() called\n")
        return self._get_all_ucsms()

    def create_network(self, args):
        """Return all UCSM IPs"""
        LOG.debug("create_network() called\n")
        return self._get_all_ucsms()

    def delete_network(self, args):
        """Return all UCSM IPs"""
        LOG.debug("delete_network() called\n")
        return self._get_all_ucsms()

    def get_network_details(self, args):
        """Return all UCSM IPs"""
        LOG.debug("get_network_details() called\n")
        return self._get_all_ucsms()

    def update_network(self, args):
        """Return all UCSM IPs"""
        LOG.debug("update_network() called\n")
        return self._get_all_ucsms()

    def get_all_ports(self, args):
        """Return all UCSM IPs"""
        LOG.debug("get_all_ports() called\n")
        return self._get_all_ucsms()

    def create_port(self, args):
        """
        Return the a dict with information of the blade
        on which a dynamic vnic is available
        """
        LOG.debug("create_port() called\n")
        least_reserved_blade_dict = self._get_least_reserved_blade()
        if not least_reserved_blade_dict:
            raise cexc.NoMoreNics()
        ucsm_ip = least_reserved_blade_dict[const.LEAST_RSVD_BLADE_UCSM]
        device_params = {const.DEVICE_IP: [ucsm_ip],
                         const.UCS_INVENTORY: self,
                         const.LEAST_RSVD_BLADE_DICT:\
                         least_reserved_blade_dict}
        return device_params

    def delete_port(self, args):
        """
        Return the a dict with information of the blade
        on which a dynamic vnic was reserved for this port
        """
        LOG.debug("delete_port() called\n")
        tenant_id = args[0]
        net_id = args[1]
        port_id = args[2]
        rsvd_info = self._get_rsvd_blade_intf_by_port(tenant_id, port_id)
        if not rsvd_info:
            LOG.warn("UCSInventory: Port not found: net_id: %s, port_id: %s" %
                     (net_id, port_id))
            return {const.DEVICE_IP: []}
        device_params = \
                {const.DEVICE_IP: [rsvd_info[const.UCSM_IP]],
                 const.UCS_INVENTORY: self,
                 const.CHASSIS_ID: rsvd_info[const.CHASSIS_ID],
                 const.BLADE_ID: rsvd_info[const.BLADE_ID],
                 const.BLADE_INTF_DN: rsvd_info[const.BLADE_INTF_DN]}
        return device_params

    def update_port(self, args):
        """
        Return the a dict with IP address of the blade
        on which a dynamic vnic was reserved for this port
        """
        LOG.debug("update_port() called\n")
        return self._get_blade_for_port(args)

    def get_port_details(self, args):
        """
        Return the a dict with IP address of the blade
        on which a dynamic vnic was reserved for this port
        """
        LOG.debug("get_port_details() called\n")
        return self._get_blade_for_port(args)

    def plug_interface(self, args):
        """
        Return the a dict with IP address of the blade
        on which a dynamic vnic was reserved for this port
        """
        LOG.debug("plug_interface() called\n")
        return self._get_blade_for_port(args)

    def unplug_interface(self, args):
        """
        Return the a dict with IP address of the blade
        on which a dynamic vnic was reserved for this port
        """
        LOG.debug("unplug_interface() called\n")
        return self._get_blade_for_port(args)

    def schedule_host(self, args):
        """Provides the hostname on which a dynamic vnic is reserved"""
        LOG.debug("schedule_host() called\n")
        instance_id = args[1]
        tenant_id = args[2][const.PROJECT_ID]
        host_name = self._get_host_name_for_rsvd_intf(tenant_id, instance_id)
        host_list = {const.HOST_LIST: {const.HOST_1: host_name}}
        LOG.debug("host_list is: %s" % host_list)
        return host_list

    def associate_port(self, args):
        """
        Get the portprofile name and the device name for the dynamic vnic
        """
        LOG.debug("associate_port() called\n")
        instance_id = args[1]
        tenant_id = args[2][const.PROJECT_ID]
        vif_id = args[2][const.VIF_ID]
        vif_info = self._get_instance_port(tenant_id, instance_id, vif_id)
        vif_desc = {const.VIF_DESC: vif_info}

        LOG.debug("vif_desc is: %s" % vif_desc)
        return vif_desc

    def detach_port(self, args):
        """
        Remove the VIF-ID and instance name association
        with the port
        """
        LOG.debug("detach_port() called\n")
        instance_id = args[1]
        tenant_id = args[2][const.PROJECT_ID]
        vif_id = args[2][const.VIF_ID]
        device_params = self._disassociate_vifid_from_port(tenant_id,
                                                           instance_id,
                                                           vif_id)
        return device_params

    def create_multiport(self, args):
        """
        Create multiple ports for a VM
        """
        LOG.debug("create_ports() called\n")
        tenant_id = args[0]
        ports_num = args[2]
        least_reserved_blade_dict = self._get_least_reserved_blade(ports_num)
        if not least_reserved_blade_dict:
            raise cexc.NoMoreNics()
        ucsm_ip = least_reserved_blade_dict[const.LEAST_RSVD_BLADE_UCSM]
        device_params = {const.DEVICE_IP: [ucsm_ip],
                         const.UCS_INVENTORY: self,
                         const.LEAST_RSVD_BLADE_DICT:\
                         least_reserved_blade_dict}
        return device_params
