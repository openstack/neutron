# Copyright (c) 2015 OpenStack Foundation
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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l2.extensions import qos
from neutron.plugins.ml2.drivers.openvswitch.mech_driver import (
    mech_openvswitch)


LOG = logging.getLogger(__name__)


class QosOVSAgentDriver(qos.QosAgentDriver):

    SUPPORTED_RULES = (
        mech_openvswitch.OpenvswitchMechanismDriver.supported_qos_rule_types)

    def __init__(self):
        super(QosOVSAgentDriver, self).__init__()
        self.br_int_name = cfg.CONF.OVS.integration_bridge
        self.br_int = None
        self.agent_api = None

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self):
        self.br_int = self.agent_api.request_int_br()
        self.cookie = self.br_int.default_cookie

    def create_bandwidth_limit(self, port, rule):
        self.update_bandwidth_limit(port, rule)

    def update_bandwidth_limit(self, port, rule):
        vif_port = port.get('vif_port')
        if not vif_port:
            port_id = port.get('port_id', None)
            LOG.debug("update_bandwidth_limit was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        max_kbps = rule.max_kbps
        # NOTE(slaweq): According to ovs docs:
        # http://openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html
        # ovs accepts only integer values of burst:
        max_burst_kbps = int(self._get_egress_burst_value(rule))

        self.br_int.create_egress_bw_limit_for_port(vif_port.port_name,
                                                    max_kbps,
                                                    max_burst_kbps)

    def delete_bandwidth_limit(self, port):
        vif_port = port.get('vif_port')
        if not vif_port:
            port_id = port.get('port_id', None)
            LOG.debug("delete_bandwidth_limit was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        self.br_int.delete_egress_bw_limit_for_port(vif_port.port_name)

    def create_dscp_marking(self, port, rule):
        self.update_dscp_marking(port, rule)

    def update_dscp_marking(self, port, rule):
        port_name = port['vif_port'].port_name
        port = self.br_int.get_port_ofport(port_name)
        mark = rule.dscp_mark
        #mark needs to be bit shifted 2 left to not overwrite the
        #lower 2 bits of type of service packet header.
        #source: man ovs-ofctl (/mod_nw_tos)
        mark = str(mark << 2)

        # reg2 is a metadata field that does not alter packets.
        # By loading a value into this field and checking if the value is
        # altered it allows the packet to be resubmitted and go through
        # the flow table again to be identified by other flows.
        flows = self.br_int.dump_flows_for(cookie=self.cookie, table=0,
                                           in_port=port, reg2=0)
        if not flows:
            actions = ("mod_nw_tos:" + mark + ",load:55->NXM_NX_REG2[0..5]," +
                       "resubmit(,0)")
            self.br_int.add_flow(in_port=port, table=0, priority=65535,
                                 reg2=0, actions=actions)
        else:
            for flow in flows:
                actions = str(flow).partition("actions=")[2]
                acts = actions.split(',')
                # mod_nw_tos = modify type of service header
                # This is the second byte of the IPv4 packet header.
                # DSCP makes up the upper 6 bits of this header field.
                actions = "mod_nw_tos:" + mark + ","
                actions += ','.join([act for act in acts
                                     if "mod_nw_tos:" not in act])
                self.br_int.mod_flow(reg2=0, in_port=port, table=0,
                                     actions=actions)

    def delete_dscp_marking(self, port):
        port_name = port['vif_port'].port_name
        port = self.br_int.get_port_ofport(port_name)

        self.br_int.delete_flows(in_port=port, table=0, reg2=0)
