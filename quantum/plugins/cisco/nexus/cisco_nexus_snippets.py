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
# @author: Edgar Magana, Cisco Systems, Inc.

"""
Nexus-OS XML-based configuration snippets
"""

import logging

from quantum.plugins.cisco.common import cisco_constants as const


LOG = logging.getLogger(__name__)


# The following are standard strings, messages used to communicate with Nexus,
EXEC_CONF_SNIPPET = """
      <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <configure xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
          <__XML__MODE__exec_configure>%s
          </__XML__MODE__exec_configure>
        </configure>
      </config>
"""


CMD_VLAN_CONF_SNIPPET = """
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

CMD_NO_VLAN_CONF_SNIPPET = """
          <no>
          <vlan>
            <vlan-id-create-delete>
              <__XML__PARAM_value>%s</__XML__PARAM_value>
            </vlan-id-create-delete>
          </vlan>
          </no>
"""

CMD_VLAN_INT_SNIPPET = """
          <interface>
            <ethernet>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
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

CMD_PORT_TRUNK = """
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
              </__XML__MODE_if-ethernet-switch>C:  1: Missing docstring
            </ethernet>
          </interface>
"""

CMD_NO_SWITCHPORT = """
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


CMD_NO_VLAN_INT_SNIPPET = """
          <interface>
            <ethernet>C:  1: Missing docstring
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


FILTER_SHOW_VLAN_BRIEF_SNIPPET = """
      <show xmlns="http://www.cisco.com/nxos:1.0:vlan_mgr_cli">
        <vlan>
          <brief/>
        </vlan>
      </show>
"""
