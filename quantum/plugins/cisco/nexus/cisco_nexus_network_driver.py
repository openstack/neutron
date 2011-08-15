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

import logging as LOG
import string
import subprocess

from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_exceptions as cexc
from quantum.plugins.cisco.nexus import cisco_nexus_snippets as snipp

from ncclient import manager

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


class CiscoNEXUSDriver():

    def __init__(self):
        pass

    def nxos_connect(self, nexus_host, nexus_ssh_port, nexus_user,
                     nexus_password):
            m = manager.connect(host=nexus_host, port=nexus_ssh_port,
                                username=nexus_user, password=nexus_password)
            return m

    def enable_vlan(self, mgr, vlanid, vlanname):
        confstr = snipp.cmd_vlan_conf_snippet % (vlanid, vlanname)
        confstr = snipp.exec_conf_prefix + confstr + snipp.exec_conf_postfix
        mgr.edit_config(target='running', config=confstr)

    def disable_vlan(self, mgr, vlanid):
        confstr = snipp.cmd_no_vlan_conf_snippet % vlanid
        confstr = snipp.exec_conf_prefix + confstr + snipp.exec_conf_postfix
        mgr.edit_config(target='running', config=confstr)

    def enable_port_trunk(self, mgr, interface):
        confstr = snipp.cmd_port_trunk % (interface)
        confstr = snipp.exec_conf_prefix + confstr + snipp.exec_conf_postfix
        LOG.debug("NexusDriver: %s" % confstr)
        mgr.edit_config(target='running', config=confstr)

    def disable_switch_port(self, mgr, interface):
        confstr = snipp.cmd_no_switchport % (interface)
        confstr = snipp.exec_conf_prefix + confstr + snipp.exec_conf_postfix
        LOG.debug("NexusDriver: %s" % confstr)
        mgr.edit_config(target='running', config=confstr)

    def enable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        confstr = snipp.cmd_vlan_int_snippet % (interface, vlanid)
        confstr = snipp.exec_conf_prefix + confstr + snipp.exec_conf_postfix
        LOG.debug("NexusDriver: %s" % confstr)
        mgr.edit_config(target='running', config=confstr)

    def disable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        confstr = snipp.cmd_no_vlan_int_snippet % (interface, vlanid)
        confstr = snipp.exec_conf_prefix + confstr + snipp.exec_conf_postfix
        LOG.debug("NexusDriver: %s" % confstr)
        mgr.edit_config(target='running', config=confstr)

    def create_vlan(self, vlan_name, vlan_id, nexus_host, nexus_user,
                    nexus_password, nexus_interface, nexus_ssh_port):
        with self.nxos_connect(nexus_host, int(nexus_ssh_port), nexus_user,
                               nexus_password) as m:
            self.enable_vlan(m, vlan_id, vlan_name)
            self.enable_vlan_on_trunk_int(m, nexus_interface, vlan_id)

    def delete_vlan(self, vlan_id, nexus_host, nexus_user,
                    nexus_password, nexus_interface, nexus_ssh_port):
        with self.nxos_connect(nexus_host, int(nexus_ssh_port), nexus_user,
                               nexus_password) as m:
            self.disable_vlan(m, vlan_id)
            self.disable_switch_port(m, nexus_interface)
