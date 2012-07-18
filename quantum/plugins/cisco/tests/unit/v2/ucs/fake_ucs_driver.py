# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
# @author: Rohit Agarwalla, Cisco Systems, Inc.

from quantum.plugins.cisco.common import cisco_constants as const


class CiscoUCSMFakeDriver():
    """UCSM Fake Driver"""

    def __init__(self):
        pass

    def _get_blade_interfaces(self, chassis_number, blade_number, ucsm_ip,
                              ucsm_username, ucsm_password):
        blade_interfaces = {}
        for element in range(20):
            dist_name = "dn" + str(element)
            if dist_name:
                order = str(element)
                rhel_name = "eth" + str(element)
                blade_interface = {
                    const.BLADE_INTF_DN: dist_name,
                    const.BLADE_INTF_ORDER: order,
                    const.BLADE_INTF_LINK_STATE: None,
                    const.BLADE_INTF_OPER_STATE: None,
                    const.BLADE_INTF_INST_TYPE: const.BLADE_INTF_DYNAMIC,
                    const.BLADE_INTF_RHEL_DEVICE_NAME: rhel_name,
                }
                blade_interfaces[dist_name] = blade_interface

        return blade_interfaces

    def _get_blade_interface_state(self, blade_intf, ucsm_ip,
                                   ucsm_username, ucsm_password):
        blade_intf[const.BLADE_INTF_LINK_STATE] = \
            const.BLADE_INTF_STATE_UNKNOWN
        blade_intf[const.BLADE_INTF_OPER_STATE] = \
            const.BLADE_INTF_STATE_UNKNOWN
        blade_intf[const.BLADE_INTF_INST_TYPE] = \
            const.BLADE_INTF_DYNAMIC

    def create_vlan(self, vlan_name, vlan_id, ucsm_ip, ucsm_username,
                    ucsm_password):
        pass

    def create_profile(self, profile_name, vlan_name, ucsm_ip, ucsm_username,
                       ucsm_password):
        pass

    def change_vlan_in_profile(self, profile_name, old_vlan_name,
                               new_vlan_name, ucsm_ip, ucsm_username,
                               ucsm_password):
        pass

    def get_blade_data(self, chassis_number, blade_number, ucsm_ip,
                       ucsm_username, ucsm_password):
        """
        Returns only the dynamic interfaces on the blade
        """
        blade_interfaces = self._get_blade_interfaces(chassis_number,
                                                      blade_number,
                                                      ucsm_ip,
                                                      ucsm_username,
                                                      ucsm_password)
        for blade_intf in blade_interfaces.keys():
            self._get_blade_interface_state(blade_interfaces[blade_intf],
                                            ucsm_ip, ucsm_username,
                                            ucsm_password)
            if ((blade_interfaces[blade_intf][const.BLADE_INTF_INST_TYPE] !=
                 const.BLADE_INTF_DYNAMIC)):
                blade_interfaces.pop(blade_intf)

        return blade_interfaces

    def delete_vlan(self, vlan_name, ucsm_ip, ucsm_username, ucsm_password):
        pass

    def delete_profile(self, profile_name, ucsm_ip, ucsm_username,
                       ucsm_password):
        pass
