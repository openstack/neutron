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
    # The agent_down_time value can only be a max of INT_MAX (as defined in C),
    # where int is usually 32 bits. The agent_down_time will be passed to
    # eventlet in milliseconds and any number higher will produce an OverFlow
    # error. More details here: https://bugs.launchpad.net/neutron/+bug/2028724
    cfg.IntOpt('agent_down_time', default=75,
               max=((2**32 / 2 - 1) // 1000),
               help=_("Seconds to regard the agent as down; should be at "
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
                      'every report_interval. '
                      'dhcp_load_type can be used in combination with '
                      'network_scheduler_driver = '
                      'neutron.scheduler.dhcp_agent_scheduler.WeightScheduler '
                      'When the network_scheduler_driver is WeightScheduler, '
                      'dhcp_load_type can be configured to represent the '
                      'choice for the resource being balanced. '
                      'Example: dhcp_load_type=networks')),
    cfg.BoolOpt('enable_new_agents', default=True,
                help=_("Agents start with admin_state_up=False when "
                       "enable_new_agents=False. In this case, a user's "
                       "resources will not be scheduled automatically to an "
                       "agent until an admin sets admin_state_up to True.")),
    cfg.IntOpt("rpc_resources_processing_step",
               default=_constants.RPC_RES_PROCESSING_STEP, min=1,
               help=_("Number of resources for neutron to divide "
                      "a large RPC call into data sets. It can be reduced "
                      "if RPC timeouts occur. The best value should be "
                      "determined empirically in your environment."))
]


def register_db_agents_opts(conf=cfg.CONF):
    conf.register_opts(AGENT_OPTS)
