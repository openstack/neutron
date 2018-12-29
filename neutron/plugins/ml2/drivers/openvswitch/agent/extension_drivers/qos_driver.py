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

import collections

from neutron_lib import constants
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l2.extensions import qos_linux as qos
from neutron.services.qos.drivers.openvswitch import driver


LOG = logging.getLogger(__name__)


class QosOVSAgentDriver(qos.QosLinuxAgentDriver):

    SUPPORTED_RULES = driver.SUPPORTED_RULES

    def __init__(self):
        super(QosOVSAgentDriver, self).__init__()
        self.br_int_name = cfg.CONF.OVS.integration_bridge
        self.br_int = None
        self.agent_api = None
        self.ports = collections.defaultdict(dict)

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
            port_id = port.get('port_id')
            LOG.debug("update_bandwidth_limit was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        self.ports[port['port_id']][(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                     rule.direction)] = port
        if rule.direction == constants.INGRESS_DIRECTION:
            self._update_ingress_bandwidth_limit(vif_port, rule)
        else:
            self._update_egress_bandwidth_limit(vif_port, rule)

    def delete_bandwidth_limit(self, port):
        port_id = port.get('port_id')
        vif_port = port.get('vif_port')
        port = self.ports[port_id].pop((qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                        constants.EGRESS_DIRECTION),
                                       None)

        if not port and not vif_port:
            LOG.debug("delete_bandwidth_limit was received "
                      "for port %s but port was not found. "
                      "It seems that bandwidth_limit is already deleted",
                      port_id)
            return
        vif_port = vif_port or port.get('vif_port')
        self.br_int.delete_egress_bw_limit_for_port(vif_port.port_name)

    def delete_bandwidth_limit_ingress(self, port):
        port_id = port.get('port_id')
        vif_port = port.get('vif_port')
        port = self.ports[port_id].pop((qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                        constants.INGRESS_DIRECTION),
                                       None)
        if not port and not vif_port:
            LOG.debug("delete_bandwidth_limit_ingress was received "
                      "for port %s but port was not found. "
                      "It seems that bandwidth_limit is already deleted",
                      port_id)
            return
        vif_port = vif_port or port.get('vif_port')
        self.br_int.delete_ingress_bw_limit_for_port(vif_port.port_name)

    def create_dscp_marking(self, port, rule):
        self.update_dscp_marking(port, rule)

    def update_dscp_marking(self, port, rule):
        self.ports[port['port_id']][qos_consts.RULE_TYPE_DSCP_MARKING] = port
        vif_port = port.get('vif_port')
        if not vif_port:
            port_id = port.get('port_id')
            LOG.debug("update_dscp_marking was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        port_name = vif_port.port_name
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
        vif_port = port.get('vif_port')
        dscp_port = self.ports[port['port_id']].pop(qos_consts.
                                                    RULE_TYPE_DSCP_MARKING, 0)

        if not dscp_port and not vif_port:
            LOG.debug("delete_dscp_marking was received for port %s but "
                      "no port information was stored to be deleted",
                      port['port_id'])
            return

        vif_port = vif_port or dscp_port.get('vif_port')
        port_num = vif_port.ofport
        self.br_int.uninstall_flows(in_port=port_num, table_id=0, reg2=0)

    def _update_egress_bandwidth_limit(self, vif_port, rule):
        max_kbps = rule.max_kbps
        # NOTE(slaweq): According to ovs docs:
        # http://openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html
        # ovs accepts only integer values of burst:
        max_burst_kbps = int(self._get_egress_burst_value(rule))

        self.br_int.create_egress_bw_limit_for_port(vif_port.port_name,
                                                    max_kbps,
                                                    max_burst_kbps)

    def _update_ingress_bandwidth_limit(self, vif_port, rule):
        port_name = vif_port.port_name
        max_kbps = rule.max_kbps or 0
        max_burst_kbps = rule.max_burst_kbps or 0

        self.br_int.update_ingress_bw_limit_for_port(
            port_name,
            max_kbps,
            max_burst_kbps
        )
