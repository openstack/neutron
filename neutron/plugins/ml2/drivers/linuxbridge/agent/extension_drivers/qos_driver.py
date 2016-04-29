# Copyright 2016 OVH SAS
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
from oslo_log import helpers as log_helpers
from oslo_log import log

from neutron._i18n import _LI
from neutron.agent.l2.extensions import qos
from neutron.agent.linux import tc_lib
from neutron.plugins.ml2.drivers.linuxbridge.mech_driver import (
    mech_linuxbridge)

LOG = log.getLogger(__name__)


class QosLinuxbridgeAgentDriver(qos.QosAgentDriver):

    SUPPORTED_RULES = (
        mech_linuxbridge.LinuxbridgeMechanismDriver.supported_qos_rule_types
    )

    def initialize(self):
        LOG.info(_LI("Initializing Linux bridge QoS extension"))

    @log_helpers.log_method_call
    def create_bandwidth_limit(self, port, rule):
        tc_wrapper = self._get_tc_wrapper(port)
        tc_wrapper.set_filters_bw_limit(
            rule.max_kbps, self._get_egress_burst_value(rule)
        )

    @log_helpers.log_method_call
    def update_bandwidth_limit(self, port, rule):
        tc_wrapper = self._get_tc_wrapper(port)
        tc_wrapper.update_filters_bw_limit(
            rule.max_kbps, self._get_egress_burst_value(rule)
        )

    @log_helpers.log_method_call
    def delete_bandwidth_limit(self, port):
        tc_wrapper = self._get_tc_wrapper(port)
        tc_wrapper.delete_filters_bw_limit()

    def _get_tc_wrapper(self, port):
        return tc_lib.TcCommand(
            port['device'],
            cfg.CONF.QOS.kernel_hz,
        )
