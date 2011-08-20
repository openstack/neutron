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

import logging as LOG

from quantum.common import exceptions as exc
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials as cred
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.common import cisco_utils as cutil
from quantum.plugins.cisco.ucs import cisco_ucs_configuration as conf
from quantum.plugins.cisco.ucs import cisco_ucs_network_driver

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)

"""
The _inventory data strcuture contains a nested disctioary:
    {"UCSM_IP: {"Chassis-ID": [Balde-ID, Blade-ID],
                "Chassis-ID": [Blade-ID, Blade-ID, Blade-ID]]},
     "UCSM_IP: {"Chassis-ID": [Balde-ID]}
    }
"""

class UCSInventory(object):

    _inventory = {}
    _host_names = {}
    _inventory_state = {}

    def __init__(self):
        self._client = cisco_ucs_network_driver.CiscoUCSMDriver()
        self._load_inventory()

    def _load_inventory(self):
        """Load the inventory from a config file"""
        inventory = conf.INVENTORY
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

    def _get_host_name(self, ucsm_ip, chassis_id, blade_id):
        """Get the hostname based on the blade info"""
        host_key = ucsm_ip + "-" + chassis_id + "-" + blade_id
        return self._host_names[host_key]

    def _get_blade_state(self, chassis_id, blade_id, ucsm_ip, ucsm_username,
                          ucsm_password):
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

    def get_all_ucsms(self):
        return self._inventory.keys()

    def reload_inventory(self):
        """Reload the inventory from a conf file"""
        self._load_inventory()
        pass
    
    def build_inventory_state(self):
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
                    blade_data = self._get_blade_state(chassis_id, blade_id,
                                                       ucsm_ip, ucsm_username,
                                                       ucsm_password)
                    blades_dict[blade_id] = blade_data

        return True

    def get_least_reserved_blade(self):
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

        if unreserved_interface_count == 0:
            return False

        least_reserved_blade_dict = \
                {const.LEAST_RSVD_BLADE_UCSM: least_reserved_blade_ucsm,
                 const.LEAST_RSVD_BLADE_CHASSIS: least_reserved_blade_chassis,
                 const.LEAST_RSVD_BLADE_ID: least_reserved_blade_id,
                 const.LEAST_RSVD_BLADE_DATA: least_reserved_blade_data}
        return least_reserved_blade_dict

    def reserve_blade_interface(self, ucsm_ip, chassis_id, blade_id,
                                blade_data_dict, tenant_id, port_id,
                                portprofile_name):
        """Reserve an interface on a blade"""
        ucsm_username = cred.Store.getUsername(ucsm_ip)
        ucsm_password = cred.Store.getPassword(ucsm_ip)
        """
        We are first getting the updated blade interface state
        """
        blade_data = self._get_blade_state(chassis_id, blade_id, ucsm_ip,
                                           ucsm_username, ucsm_password)
        blade_intf_data = blade_data[const.BLADE_INTF_DATA]
        old_blade_intf_data = blade_data_dict[const.BLADE_INTF_DATA]

        """
        We will now copy the older blade interface reservation state
        """
        for blade_intf in blade_intf_data.keys():
            blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                    old_blade_intf_data[blade_intf]\
                    [const.BLADE_INTF_RESERVATION]

        blade_data[const.BLADE_UNRESERVED_INTF_COUNT] = \
                blade_data_dict[const.BLADE_UNRESERVED_INTF_COUNT]
        """
        Now we will reserve an interface if its available
        """
        for blade_intf in blade_intf_data.keys():
            if blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] == \
               const.BLADE_INTF_UNRESERVED:
                blade_intf_data[blade_intf][const.BLADE_INTF_RESERVATION] = \
                        const.BLADE_INTF_RESERVED
                blade_intf_data[blade_intf][const.TENANTID] = tenant_id
                blade_intf_data[blade_intf][const.PORTID] = port_id
                blade_intf_data[blade_intf][const.PROFILEID] = portprofile_name
                blade_intf_data[blade_intf][const.INSTANCE_ID] = None
                dev_eth_name = blade_intf_data[blade_intf] \
                        [const.BLADE_INTF_RHEL_DEVICE_NAME]
                """
                We are replacing the older blade interface state with new
                """
                self._inventory_state[ucsm_ip][chassis_id][blade_id] \
                        [const.BLADE_INTF_DATA] = blade_intf_data
                self._inventory_state[ucsm_ip][chassis_id][blade_id] \
                        [const.BLADE_UNRESERVED_INTF_COUNT] -= 1
                host_name = self._get_host_name(ucsm_ip, chassis_id,
                                                       blade_id)
                reserved_nic_dict = {const.RESERVED_NIC_HOSTNAME: host_name,
                                   const.RESERVED_NIC_NAME: dev_eth_name,
                                   const.BLADE_INTF_DN: blade_intf}
                LOG.debug("Reserved blade interface: %s\n" % reserved_nic_dict)
                return reserved_nic_dict

        return False

    def unreserve_blade_interface(self, ucsm_ip, chassis_id, blade_id,
                                  interface_dn):
        """Unreserve a previously reserved interface on a blade"""
        ucsm_username = cred.Store.getUsername(ucsm_ip)
        ucsm_password = cred.Store.getPassword(ucsm_ip)
        self._inventory_state[ucsm_ip][chassis_id][blade_id]\
                [const.BLADE_INTF_DATA] \
                [interface_dn][const.BLADE_INTF_RESERVATION] = \
                const.BLADE_INTF_UNRESERVED
        self._inventory_state[ucsm_ip][chassis_id][blade_id] \
                [const.BLADE_UNRESERVED_INTF_COUNT] += 1
        LOG.debug("Unreserved blade interface %s\n" % interface_dn)

    def get_rsvd_blade_intf_by_port(self, tenant_id, port_id):
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
                        if blade_intf_data[blade_intf]\
                           [const.BLADE_INTF_RESERVATION] == \
                           const.BLADE_INTF_RESERVED and \
                           blade_intf_data[blade_intf]\
                           [const.TENANTID] == tenant_id and \
                           blade_intf_data[blade_intf]\
                           [const.PORTID] == port_id:
                            interface_dn = blade_intf_data[blade_intf]\
                                    [const.BLADE_INTF_DN]
                            blade_intf_info = {const.UCSM_IP: ucsm_ip,
                                               const.CHASSIS_ID: chassis_id,
                                               const.BLADE_ID: blade_id,
                                               const.BLADE_INTF_DN: 
                                               interface_dn}
                            return blade_intf_info
        return None

    def get_host_name(self, tenant_id, instance_id):
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
                        if blade_intf_data[blade_intf]\
                           [const.BLADE_INTF_RESERVATION] == \
                           const.BLADE_INTF_RESERVED and \
                           blade_intf_data[blade_intf]\
                           [const.TENANTID] == tenant_id and \
                           blade_intf_data[blade_intf]\
                           [const.INSTANCE_ID] == None:
                            blade_intf_data[blade_intf]\
                                    [const.INSTANCE_ID] = instance_id
                            host_name = self._get_host_name(ucsm_ip,
                                                            chassis_id,
                                                            blade_id)
                            return host_name
        return None

    def get_instance_port(self, tenant_id, instance_id):
        """
        Return the device name for a reserved interface
        """
        for ucsm_ip in self._inventory_state.keys():
            ucsm = self._inventory_state[ucsm_ip]
            for chassis_id in ucsm.keys():
                for blade_id in ucsm[chassis_id]:
                    blade_data = ucsm[chassis_id][blade_id]
                    blade_intf_data = blade_data[const.BLADE_INTF_DATA]
                    for blade_intf in blade_intf_data.keys():
                        if blade_intf_data[blade_intf]\
                           [const.BLADE_INTF_RESERVATION] == \
                           const.BLADE_INTF_RESERVED and \
                           blade_intf_data[blade_intf]\
                           [const.TENANTID] == tenant_id and \
                           blade_intf_data[blade_intf]\
                           [const.INSTANCE_ID] == instance_id:
                            return blade_intf_data[blade_intf]\
                                    [const.BLADE_INTF_RHEL_DEVICE_NAME]
        return None

    def add_blade(self, ucsm_ip, chassis_id, blade_id):
        """Add a blade to the inventory"""
        pass


def main():
    #client = UCSInventory()
    #client.build_state()
    ucsinv = UCSInventory()
    reserved_nics = []
    ucsinv.build_inventory_state()
    while True:
        reserved_blade_dict = ucsinv.get_least_reserved_blade()
        if not reserved_blade_dict:
            print "No more unreserved blades\n"
            break

        least_reserved_blade_ucsm = reserved_blade_dict[const.LEAST_RSVD_BLADE_UCSM]
        least_reserved_blade_chassis = \
        reserved_blade_dict[const.LEAST_RSVD_BLADE_CHASSIS]
        least_reserved_blade_id = \
        reserved_blade_dict[const.LEAST_RSVD_BLADE_ID]
        least_reserved_blade_data = \
        reserved_blade_dict[const.LEAST_RSVD_BLADE_DATA]
        reserved_nic_dict = \
        ucsinv.reserve_blade_interface(least_reserved_blade_ucsm,
                                            least_reserved_blade_chassis,
                                            least_reserved_blade_id,
                                            least_reserved_blade_data,
                                      "demo")
        if reserved_nic_dict:
            reserved_intf_nic_info = {const.RESERVED_INTERFACE_UCSM:
                                   least_reserved_blade_ucsm,
                                   const.RESERVED_INTERFACE_CHASSIS:
                                   least_reserved_blade_chassis,
                                   const.RESERVED_INTERFACE_BLADE:
                                   least_reserved_blade_id,
                                   const.RESERVED_INTERFACE_DN:
                                   reserved_nic_dict[const.BLADE_INTF_DN]}
            reserved_nics.append(reserved_intf_nic_info)
            #break

    for rnic in reserved_nics:
        ucsinv.unreserve_blade_interface(
            rnic[const.RESERVED_INTERFACE_UCSM],
            rnic[const.RESERVED_INTERFACE_CHASSIS],
            rnic[const.RESERVED_INTERFACE_BLADE],
            rnic[const.RESERVED_INTERFACE_DN])


if __name__ == '__main__':
    main()
