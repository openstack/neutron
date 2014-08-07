# Copyright 2013 OpenStack Foundation.
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


"""
Cisco Nexus-OS XML-based configuration snippets.
"""


# The following are standard strings, messages used to communicate with Nexus.
EXEC_CONF_SNIPPET = """
      <config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <configure>
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
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
"""

CMD_VLAN_ACTIVE_SNIPPET = """
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>%s</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <state>
                    <vstate>active</vstate>
                  </state>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
"""

CMD_VLAN_NO_SHUTDOWN_SNIPPET = """
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>%s</__XML__PARAM_value>
                <__XML__MODE_vlan>
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

CMD_INT_VLAN_HEADER = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>"""

CMD_VLAN_ID = """
                          <vlan_id>%s</vlan_id>"""

CMD_VLAN_ADD_ID = """
                        <add>%s
                        </add>""" % CMD_VLAN_ID

CMD_INT_VLAN_TRAILER = """
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

CMD_INT_VLAN_SNIPPET = (CMD_INT_VLAN_HEADER +
                        CMD_VLAN_ID +
                        CMD_INT_VLAN_TRAILER)

CMD_INT_VLAN_ADD_SNIPPET = (CMD_INT_VLAN_HEADER +
                            CMD_VLAN_ADD_ID +
                            CMD_INT_VLAN_TRAILER)

CMD_PORT_TRUNK = """
          <interface>
            <%s>
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
            </%s>
          </interface>
"""

CMD_NO_SWITCHPORT = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <no>
                  <switchport>
                  </switchport>
                </no>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

CMD_NO_VLAN_INT_SNIPPET = """
          <interface>
            <%s>
              <interface>%s</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport></switchport>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>
                        <remove>
                          <vlan>%s</vlan>
                        </remove>
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </%s>
          </interface>
"""

CMD_VLAN_SVI_SNIPPET = """
<interface>
    <vlan>
        <vlan>%s</vlan>
        <__XML__MODE_vlan>
            <no>
              <shutdown/>
            </no>
            <ip>
                <address>
                    <address>%s</address>
                </address>
            </ip>
        </__XML__MODE_vlan>
    </vlan>
</interface>
"""

CMD_NO_VLAN_SVI_SNIPPET = """
<no>
    <interface>
        <vlan>
            <vlan>%s</vlan>
        </vlan>
    </interface>
</no>
"""
