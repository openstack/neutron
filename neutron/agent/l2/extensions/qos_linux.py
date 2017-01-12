# Copyright (c) 2017 Cloudbase Solutions
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

from neutron.agent.l2.extensions import qos
from neutron.agent.linux import tc_lib


class QosLinuxAgentDriver(qos.QosAgentDriver):

    def _get_egress_burst_value(self, rule):
        """Return burst value used for egress bandwidth limitation.

        Because Egress bw_limit is done on ingress qdisc by LB and ovs drivers
        so it will return burst_value used by tc on as ingress_qdisc.
        """
        return tc_lib.TcCommand.get_ingress_qdisc_burst_value(
            rule.max_kbps, rule.max_burst_kbps)
