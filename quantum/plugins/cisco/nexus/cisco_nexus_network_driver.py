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

from ncclient import manager

LOG.basicConfig(level=LOG.WARN)
LOG.getLogger(const.LOGGER_COMPONENT_NAME)


# The following are standard strings, messages used to communicate with Nexus,
#only place holder values change for each message
exec_conf_prefix = """
      <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <configure xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
          <__XML__MODE__exec_configure>
"""


exec_conf_postfix = """
          </__XML__MODE__exec_configure>
        </configure>
      </config>
"""


cmd_vlan_conf_snippet = """
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>%s</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <name>
                    <vlan-name>%s</vlan-name>
                  </name>
                  <state>
                    <vstate>active</vstate>
                  </state>
                  <no>
                    <shutdown/>
                  </no>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
"""

cmd_no_vlan_conf_snippet = """
          <no>
          <vlan>
            <vlan-id-create-delete>
              <__XML__PARAM_value>%s</__XML__PARAM_value>
            </vlan-id-create-delete>
          </vlan>
          </no>
"""

cmd_vlan_int_snippet = """
          <interface>
            <ethernet>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport></switchport>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>
                        <__XML__BLK_Cmd_switchport_trunk_allowed_allow-vlans>
                          <allow-vlans>%s</allow-vlans>
                        </__XML__BLK_Cmd_switchport_trunk_allowed_allow-vlans>
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </ethernet>
          </interface>
"""

cmd_port_trunk = """
          <interface>
            <ethernet>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport></switchport>
                <switchport>
                  <mode>
                    <trunk>
                    </trunk>
                  </mode>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </ethernet>
          </interface>
"""

cmd_no_switchport = """
          <interface>
            <ethernet>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <no>
                  <switchport>
                  </switchport>
                </no>
              </__XML__MODE_if-ethernet-switch>
            </ethernet>
          </interface>
"""


cmd_no_vlan_int_snippet = """
          <interface>
            <ethernet>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport></switchport>
                <no>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>
                        <__XML__BLK_Cmd_switchport_trunk_allowed_allow-vlans>
                          <allow-vlans>%s</allow-vlans>
                        </__XML__BLK_Cmd_switchport_trunk_allowed_allow-vlans>
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
               </no>
              </__XML__MODE_if-ethernet-switch>
            </ethernet>
          </interface>
"""


filter_show_vlan_brief_snippet = """
      <show xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
        <vlan>
          <brief/>
        </vlan>
      </show> """


class CiscoNEXUSDriver():

    def __init__(self):
        pass

    def nxos_connect(self, nexus_host, port, nexus_user, nexus_password):
            m = manager.connect(host=nexus_host, port=22, username=nexus_user,
                                password=nexus_password)
            return m

    def enable_vlan(self, mgr, vlanid, vlanname):
        confstr = cmd_vlan_conf_snippet % (vlanid, vlanname)
        confstr = exec_conf_prefix + confstr + exec_conf_postfix
        mgr.edit_config(target='running', config=confstr)

    def disable_vlan(self, mgr, vlanid):
        confstr = cmd_no_vlan_conf_snippet % vlanid
        confstr = exec_conf_prefix + confstr + exec_conf_postfix
        mgr.edit_config(target='running', config=confstr)

    def enable_port_trunk(self, mgr, interface):
        confstr = cmd_port_trunk % (interface)
        confstr = exec_conf_prefix + confstr + exec_conf_postfix
        print confstr
        mgr.edit_config(target='running', config=confstr)

    def disable_switch_port(self, mgr, interface):
        confstr = cmd_no_switchport % (interface)
        confstr = exec_conf_prefix + confstr + exec_conf_postfix
        print confstr
        mgr.edit_config(target='running', config=confstr)

    def enable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        confstr = cmd_vlan_int_snippet % (interface, vlanid)
        confstr = exec_conf_prefix + confstr + exec_conf_postfix
        print confstr
        mgr.edit_config(target='running', config=confstr)

    def disable_vlan_on_trunk_int(self, mgr, interface, vlanid):
        confstr = cmd_no_vlan_int_snippet % (interface, vlanid)
        confstr = exec_conf_prefix + confstr + exec_conf_postfix
        print confstr
        mgr.edit_config(target='running', config=confstr)

    def create_vlan(self, vlan_name, vlan_id, nexus_host, nexus_user,
                    nexus_password, nexus_interface):
        #TODO (Edgar) Move the SSH port to the configuration file
        with self.nxos_connect(nexus_host, 22, nexus_user,
                               nexus_password) as m:
            self.enable_vlan(m, vlan_id, vlan_name)
            self.enable_vlan_on_trunk_int(m, nexus_interface, vlan_id)

    def delete_vlan(self, vlan_id, nexus_host, nexus_user,
                    nexus_password, nexus_interface):
        with self.nxos_connect(nexus_host, 22, nexus_user,
                               nexus_password) as m:
            self.disable_vlan(m, vlan_id)
            self.disable_switch_port(m, nexus_interface)
