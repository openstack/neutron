# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

from oslo.config import cfg

from quantum.agent.common import config
from quantum.openstack.common import rpc  # noqa
from quantum import scheduler


ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]

ofc_opts = [
    cfg.StrOpt('host', default='127.0.0.1',
               help=_("Host to connect to")),
    cfg.StrOpt('port', default='8888',
               help=_("Port to connect to")),
    cfg.StrOpt('driver', default='trema',
               help=_("Driver to use")),
    cfg.BoolOpt('enable_packet_filter', default=True,
                help=_("Enable packet filter")),
    cfg.BoolOpt('use_ssl', default=False,
                help=_("Use SSL to connect")),
    cfg.StrOpt('key_file', default=None,
               help=_("Key file")),
    cfg.StrOpt('cert_file', default=None,
               help=_("Certificate file")),
]


cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
cfg.CONF.register_opts(ofc_opts, "OFC")
config.register_agent_state_opts_helper(cfg.CONF)
config.register_root_helper(cfg.CONF)
cfg.CONF.register_opts(scheduler.AGENTS_SCHEDULER_OPTS)

# shortcuts
CONF = cfg.CONF
OVS = cfg.CONF.OVS
AGENT = cfg.CONF.AGENT
OFC = cfg.CONF.OFC
