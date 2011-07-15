# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Cisco Systems Inc.
# All Rights Reserved.
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
# @author: Debojyoti Dutta, Cisco Systems, Inc.

import sys
import os
import warnings
warnings.simplefilter("ignore", DeprecationWarning)
from ncclient import manager
from ncclient import NCClientError
from ncclient.transport.errors import *

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


def nxos_connect(host, port, user, password):
    try:
        m = manager.connect(host=host, port=port, username=user,
                             password=password)
        return m
    except SSHUnknownHostError:
        sys.stderr.write('SSH unknown host error\n')
        exit()


def enable_vlan(mgr, vlanid, vlanname):
    confstr = cmd_vlan_conf_snippet % (vlanid, vlanname)
    confstr = exec_conf_prefix + confstr + exec_conf_postfix
    mgr.edit_config(target='running', config=confstr)


def disable_vlan(mgr, vlanid):
    confstr = cmd_no_vlan_conf_snippet % vlanid
    confstr = exec_conf_prefix + confstr + exec_conf_postfix
    mgr.edit_config(target='running', config=confstr)


def enable_vlan_on_trunk_int(mgr, interface, vlanid):
    confstr = cmd_vlan_int_snippet % (interface, vlanid)
    confstr = exec_conf_prefix + confstr + exec_conf_postfix
    print confstr
    mgr.edit_config(target='running', config=confstr)


def disable_vlan_on_trunk_int(mgr, interface, vlanid):
    confstr = cmd_no_vlan_int_snippet % (interface, vlanid)
    confstr = exec_conf_prefix + confstr + exec_conf_postfix
    print confstr
    mgr.edit_config(target='running', config=confstr)


def test_nxos_api(host, user, password):
    with nxos_connect(host, port=22, user=user, password=password) as m:
        enable_vlan(m, '100', 'ccn1')
        enable_vlan_on_trunk_int(m, '2/1', '100')
        disable_vlan_on_trunk_int(m, '2/1', '100')
        disable_vlan(m, '100')
        result = m.get(("subtree", filter_show_vlan_brief_snippet))
        #print result


if __name__ == '__main__':
    test_nxos_api(sys.argv[1], sys.argv[2], sys.argv[3])
