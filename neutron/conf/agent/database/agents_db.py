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

from neutron._i18n import _
from neutron.common import _constants

AGENT_OPTS = [
    cfg.IntOpt('agent_down_time', default=75,
               help=_("Seconds to regard the agent is down; should be at "
                      "least twice report_interval, to be sure the "
                      "agent is down for good.")),
    cfg.StrOpt('dhcp_load_type', default='networks',
               choices=['networks', 'subnets', 'ports'],
               help=_('Representing the resource type whose load is being '
                      'reported by the agent. This can be "networks", '
                      '"subnets" or "ports". '
                      'When specified (Default is networks), the server will '
                      'extract particular load sent as part of its agent '
                      'configuration object from the agent report state, '
                      'which is the number of resources being consumed, at '
                      'every report_interval.'
                      'dhcp_load_type can be used in combination with '
                      'network_scheduler_driver = '
                      'neutron.scheduler.dhcp_agent_scheduler.WeightScheduler '
                      'When the network_scheduler_driver is WeightScheduler, '
                      'dhcp_load_type can be configured to represent the '
                      'choice for the resource being balanced. '
                      'Example: dhcp_load_type=networks')),
    cfg.BoolOpt('enable_new_agents', default=True,
                help=_("Agent starts with admin_state_up=False when "
                       "enable_new_agents=False. In the case, user's "
                       "resources will not be scheduled automatically to the "
                       "agent until admin changes admin_state_up to True.")),
    cfg.IntOpt("rpc_resources_processing_step",
               default=_constants.RPC_RES_PROCESSING_STEP, min=1,
               help=_("Number of resources for neutron to divide "
                      "the large RPC call data sets. It can be reduced "
                      "if RPC timeout occurred. The best value can be "
                      "determined empirically in your environment."))
]


def register_db_agents_opts(conf=cfg.CONF):
    conf.register_opts(AGENT_OPTS)
