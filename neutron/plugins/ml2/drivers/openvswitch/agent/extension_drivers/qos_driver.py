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

from neutron.agent.common import ovs_lib
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

    def initialize(self):
        self.br_int = ovs_lib.OVSBridge(self.br_int_name)

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
        max_burst_kbps = rule.max_burst_kbps

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
