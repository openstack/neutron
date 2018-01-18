# Copyright (c) 2016 IBM Corp.
#
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

from oslo_config import cfg

from neutron._i18n import _

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.IntOpt('quitting_rpc_timeout', default=10,
               help=_("Set new timeout in seconds for new rpc calls after "
                      "agent receives SIGTERM. If value is set to 0, rpc "
                      "timeout won't be changed")),
    cfg.IntOpt('dscp', min=0, max=63,
               help=_("The DSCP value to use for outer headers during tunnel "
                      "encapsulation.")),
    cfg.BoolOpt('dscp_inherit', default=False,
                help=_("If set to True, the DSCP value of tunnel "
                       "interfaces is overwritten and set to inherit. "
                       "The DSCP value of the inner header is then "
                       "copied to the outer header.")),
]


def register_agent_opts(cfg=cfg.CONF):
    cfg.register_opts(agent_opts, "AGENT")
