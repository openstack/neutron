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

import eventlet
import logging

from ncclient import manager

from quantum.plugins.cisco.common import cisco_exceptions
from quantum.plugins.cisco.db import network_db_v2 as cdb
from quantum.plugins.cisco.db import nexus_db_v2
from quantum.plugins.cisco.nexus import cisco_nexus_snippets as snipp


LOG = logging.getLogger(__name__)


class CiscoNEXUSDriver():
    """
    Nexus Driver Main Class
    """
    def __init__(self):
        pass

    def _edit_config(self, mgr, target='running', config='',
                     allowed_exc_strs=None):
        """Modify switch config for a target config type.

        :param mgr: NetConf client manager
        :param target: Target config type
        :param config: Configuration string in XML format
        :param allowed_exc_strs: Exceptions which have any of these strings
                                 as a subset of their exception message
                                 (str(exception)) can be ignored

        :raises: NexusConfigFailed

        """
        if not allowed_exc_strs:
            allowed_exc_strs = []
        try:
            mgr.edit_config(target, config=config)
        except Exception as e:
            for exc_str in allowed_exc_strs:
                if exc_str in str(e):
                    break
            else:
                # Raise a Quantum exception. Include a description of
                # the original ncclient exception.
                raise cisco_exceptions.NexusConfigFailed(config=config, exc=e)

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
        """Create a VLAN on Nexus Switch given the VLAN ID and Name."""
        confstr = self.create_xml_snippet(
            snipp.CMD_VLAN_CONF_SNIPPET % (vlanid, vlanname))
        self._edit_config(mgr, target='running', config=confstr)

        # Enable VLAN active and no-shutdown states. Some versions of
        # Nexus switch do not allow state changes for the extended VLAN
        # range (1006-4094), but these errors can be ignored (default
        # values are appropriate).
        state_config = [snipp.CMD_VLAN_ACTIVE_SNIPPET,
                        snipp.CMD_VLAN_NO_SHUTDOWN_SNIPPET]
        for snippet in state_config:
            try:
                confstr = self.create_xml_snippet(snippet % vlanid)
                self._edit_config(
                    mgr,
                    target='running',
                    config=confstr,
                    allowed_exc_strs=["Can't modify state for extended",
                                      "Command is only allowed on VLAN"])
            except cisco_exceptions.NexusConfigFailed as e:
                # Rollback VLAN creation
                try:
                    self.disable_vlan(mgr, vlanid)
                finally:
                    # Re-raise original exception
                    raise e

    def disable_vlan(self, mgr, vlanid):
        """
        Delete a VLAN on Nexus Switch given the VLAN ID
        """
        confstr = snipp.CMD_NO_VLAN_CONF_SNIPPET % vlanid
        confstr = self.create_xml_snippet(confstr)
        self._edit_config(mgr, target='running', config=confstr)

    def enable_port_trunk(self, mgr, interface):
        """
        Enables trunk mode an interface on Nexus Switch
        """
        confstr = snipp.CMD_PORT_TRUNK % (interface)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        self._edit_config(mgr, target='running', config=confstr)

    def disable_switch_port(self, mgr, interface):
        """
        Disables trunk mode an interface on Nexus Switch
        """
        confstr = snipp.CMD_NO_SWITCHPORT % (interface)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        self._edit_config(mgr, target='running', config=confstr)

    def enable_vlan_on_trunk_int(self, mgr, nexus_switch, interface, vlanid):
        """Enable vlan in trunk interface.

        Enables trunk mode vlan access on an interface on Nexus Switch given
        VLANID. If one or more VLANs are already configured on this
        interface, include the 'add' keyword in the interface configuration.
        """
        if nexus_db_v2.get_port_switch_bindings(interface, nexus_switch):
            snippet = snipp.CMD_INT_VLAN_ADD_SNIPPET
        else:
            snippet = snipp.CMD_INT_VLAN_SNIPPET
        confstr = self.create_xml_snippet(snippet % (interface, vlanid))
        LOG.debug(_("NexusDriver: %s"), confstr)
        self._edit_config(mgr, target='running', config=confstr)

    def disable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        """
        Enables trunk mode vlan access an interface on Nexus Switch given
        VLANID
        """
        confstr = snipp.CMD_NO_VLAN_INT_SNIPPET % (interface, vlanid)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug(_("NexusDriver: %s"), confstr)
        self._edit_config(mgr, target='running', config=confstr)

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
            self.enable_vlan_on_trunk_int(man, nexus_host, ports, vlan_ids)

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
            self.enable_vlan_on_trunk_int(man, nexus_host, ports, vlan_ids)

    def remove_vlan_int(self, vlan_id, nexus_host, nexus_user, nexus_password,
                        nexus_ports, nexus_ssh_port):
        """
        Removes a vlan from interfaces on the Nexus switch given the VLAN ID
        """
        man = self.nxos_connect(nexus_host, int(nexus_ssh_port),
                                nexus_user, nexus_password)
        for ports in nexus_ports:
            self.disable_vlan_on_trunk_int(man, ports, vlan_id)
