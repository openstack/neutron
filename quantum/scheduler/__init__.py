# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 OpenStack LLC.
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

from oslo.config import cfg


AGENTS_SCHEDULER_OPTS = [
    cfg.StrOpt('network_scheduler_driver',
               default='quantum.scheduler.'
                       'dhcp_agent_scheduler.ChanceScheduler',
               help=_('Driver to use for scheduling network to DHCP agent')),
    cfg.StrOpt('router_scheduler_driver',
               default='quantum.scheduler.l3_agent_scheduler.ChanceScheduler',
               help=_('Driver to use for scheduling '
                      'router to a default L3 agent')),
    cfg.BoolOpt('network_auto_schedule', default=True,
                help=_('Allow auto scheduling networks to DHCP agent.')),
    cfg.BoolOpt('router_auto_schedule', default=True,
                help=_('Allow auto scheduling routers to L3 agent.')),
]
