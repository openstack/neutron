# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Red Hat, Inc.
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

from neutron.agent.common import config
from neutron.agent.linux import ovs_lib  # noqa

ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use")),
    cfg.StrOpt('openflow_rest_api', default='127.0.0.1:8080',
               help=_("OpenFlow REST API location")),
    cfg.IntOpt('tunnel_key_min', default=1,
               help=_("Minimum tunnel ID to use")),
    cfg.IntOpt('tunnel_key_max', default=0xffffff,
               help=_("Maximum tunnel ID to use")),
    cfg.StrOpt('tunnel_ip', default=None,
               help=_("Tunnel IP to use")),
    cfg.StrOpt('tunnel_interface', default=None,
               help=_("Tunnel interface to use")),
    cfg.IntOpt('ovsdb_port', default=6634,
               help=_("OVSDB port to connect to")),
    cfg.StrOpt('ovsdb_ip', default=None,
               help=_("OVSDB IP to connect to")),
    cfg.StrOpt('ovsdb_interface', default=None,
               help=_("OVSDB interface to connect to")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]


cfg.CONF.register_opts(ovs_opts, "OVS")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_root_helper(cfg.CONF)
