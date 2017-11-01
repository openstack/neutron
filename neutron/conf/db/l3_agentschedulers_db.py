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


L3_AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('router_scheduler_driver',
               default='neutron.scheduler.l3_agent_scheduler.'
                       'LeastRoutersScheduler',
               help=_('Driver to use for scheduling '
                      'router to a default L3 agent')),
    cfg.BoolOpt('router_auto_schedule', default=True,
                help=_('Allow auto scheduling of routers to L3 agent.')),
    cfg.BoolOpt('allow_automatic_l3agent_failover', default=False,
                help=_('Automatically reschedule routers from offline L3 '
                       'agents to online L3 agents.')),
]


def register_db_l3agentschedulers_opts(conf=cfg.CONF):
    conf.register_opts(L3_AGENTS_SCHEDULER_OPTS)
