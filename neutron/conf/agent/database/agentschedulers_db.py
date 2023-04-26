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


AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('network_scheduler_driver',
               default='neutron.scheduler.'
                       'dhcp_agent_scheduler.WeightScheduler',
               help=_('Driver to use for scheduling networks to a DHCP '
                      'agent')),
    cfg.BoolOpt('network_auto_schedule', default=True,
                help=_('Allow auto scheduling networks to a DHCP agent.')),
    cfg.BoolOpt('allow_automatic_dhcp_failover', default=True,
                help=_('Automatically remove networks from offline DHCP '
                       'agents.')),
    cfg.IntOpt('dhcp_agents_per_network', default=1,
               min=1,
               help=_('Number of DHCP agents scheduled to host a tenant '
                      'network. If this number is greater than 1, the '
                      'scheduler automatically assigns multiple DHCP agents '
                      'for a given tenant network, providing high '
                      'availability for the DHCP service. However this does '
                      'not provide high availability for the IPv6 metadata '
                      'service in isolated networks.')),
    cfg.BoolOpt('enable_services_on_agents_with_admin_state_down',
                default=False,
                help=_('Enable services on an agent with admin_state_up '
                       'False. If this option is False, when admin_state_up '
                       'of an agent is turned False, services on it will be '
                       'disabled. Agents with admin_state_up False are not '
                       'selected for automatic scheduling regardless of this '
                       'option. But manual scheduling to such agents is '
                       'available if this option is True.')),
]


def register_db_agentschedulers_opts(conf=cfg.CONF):
    conf.register_opts(AGENTS_SCHEDULER_OPTS)
