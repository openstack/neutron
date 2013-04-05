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
# @author: Debojyoti Dutta, Cisco Systems, Inc.
# @author: Edgar Magana, Cisco Systems Inc.
#
"""
Implements a Nexus-OS NETCONF over SSHv2 API Client
"""

import logging

from ncclient import manager

from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.nexus import cisco_nexus_snippets as snipp


LOG = logging.getLogger(__name__)


class CiscoNEXUSDriver():
    """
    Nexus Driver Main Class
    """
    def __init__(self):
        pass

    def nxos_connect(self, nexus_host, nexus_ssh_port, nexus_user,
                     nexus_password):
        """
        Makes the SSH connection to the Nexus Switch
        """
        man = manager.connect(host=nexus_host, port=nexus_ssh_port,
                              username=nexus_user, password=nexus_password)
        return man

    def create_xml_snippet(self, cutomized_config):
        """
        Creates the Proper XML structure for the Nexus Switch Configuration
        """
        conf_xml_snippet = snipp.EXEC_CONF_SNIPPET % (cutomized_config)
        return conf_xml_snippet

    def enable_vlan(self, mgr, vlanid, vlanname):
        """
        Creates a VLAN on Nexus Switch given the VLAN ID and Name
        """
        confstr = snipp.CMD_VLAN_CONF_SNIPPET % (vlanid, vlanname)
        confstr = self.create_xml_snippet(confstr)
        mgr.edit_config(target='running', config=confstr)

    def disable_vlan(self, mgr, vlanid):
        """
        Delete a VLAN on Nexus Switch given the VLAN ID
        """
        confstr = snipp.CMD_NO_VLAN_CONF_SNIPPET % vlanid
        confstr = self.create_xml_snippet(confstr)
        mgr.edit_config(target='running', config=confstr)

    def enable_port_trunk(self, mgr, interface):
        """
        Enables trunk mode an interface on Nexus Switch
        """
        confstr = snipp.CMD_PORT_TRUNK % (interface)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        mgr.edit_config(target='running', config=confstr)

    def disable_switch_port(self, mgr, interface):
        """
        Disables trunk mode an interface on Nexus Switch
        """
        confstr = snipp.CMD_NO_SWITCHPORT % (interface)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        mgr.edit_config(target='running', config=confstr)

    def enable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        """
        Enables trunk mode vlan access an interface on Nexus Switch given
        VLANID
        """
        confstr = snipp.CMD_VLAN_INT_SNIPPET % (interface, vlanid)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        mgr.edit_config(target='running', config=confstr)

    def disable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        """
        Enables trunk mode vlan access an interface on Nexus Switch given
        VLANID
        """
        confstr = snipp.CMD_NO_VLAN_INT_SNIPPET % (interface, vlanid)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        mgr.edit_config(target='running', config=confstr)

    def create_vlan(self, vlan_name, vlan_id, nexus_host, nexus_user,
                    nexus_password, nexus_ports,
                    nexus_ssh_port, vlan_ids=None):
        """
        Creates a VLAN and Enable on trunk mode an interface on Nexus Switch
        given the VLAN ID and Name and Interface Number
        """
        man = self.nxos_connect(nexus_host, int(nexus_ssh_port),
                                nexus_user, nexus_password)
        self.enable_vlan(man, vlan_id, vlan_name)
        if vlan_ids is '':
            vlan_ids = self.build_vlans_cmd()
        LOG.debug(_("NexusDriver VLAN IDs: %s"), vlan_ids)
        for ports in nexus_ports:
            self.enable_vlan_on_trunk_int(man, ports, vlan_ids)

    def delete_vlan(self, vlan_id, nexus_host, nexus_user, nexus_password,
                    nexus_ports, nexus_ssh_port):
        """
        Delete a VLAN and Disables trunk mode an interface on Nexus Switch
        given the VLAN ID and Interface Number
        """
        man = self.nxos_connect(nexus_host, int(nexus_ssh_port),
                                nexus_user, nexus_password)
        self.disable_vlan(man, vlan_id)
        for ports in nexus_ports:
            self.disable_vlan_on_trunk_int(man, ports, vlan_id)

    def build_vlans_cmd(self):
        """
        Builds a string with all the VLANs on the same Switch
        """
        assigned_vlan = cdb.get_all_vlanids_used()
        vlans = ''
        for vlanid in assigned_vlan:
            vlans = str(vlanid["vlan_id"]) + ',' + vlans
        if vlans == '':
            vlans = 'none'
        return vlans.strip(',')

    def add_vlan_int(self, vlan_id, nexus_host, nexus_user, nexus_password,
                     nexus_ports, nexus_ssh_port, vlan_ids=None):
        """
        Adds a vlan from interfaces on the Nexus switch given the VLAN ID
        """
        man = self.nxos_connect(nexus_host, int(nexus_ssh_port),
                                nexus_user, nexus_password)
        if not vlan_ids:
            vlan_ids = self.build_vlans_cmd()
        for ports in nexus_ports:
            self.enable_vlan_on_trunk_int(man, ports, vlan_ids)

    def remove_vlan_int(self, vlan_id, nexus_host, nexus_user, nexus_password,
                        nexus_ports, nexus_ssh_port):
        """
        Removes a vlan from interfaces on the Nexus switch given the VLAN ID
        """
        man = self.nxos_connect(nexus_host, int(nexus_ssh_port),
                                nexus_user, nexus_password)
        for ports in nexus_ports:
            self.disable_vlan_on_trunk_int(man, ports, vlan_id)
