# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from oslo_config import cfg

from neutron.agent.common import config

DEFAULT_INTERFACE_MAPPINGS = []

eswitch_opts = [
    cfg.ListOpt('physical_interface_mappings',
                default=DEFAULT_INTERFACE_MAPPINGS,
                help=_("List of <physical_network>:<physical_interface>")),
    cfg.StrOpt('daemon_endpoint',
               default='tcp://127.0.0.1:60001',
               help=_('eswitch daemon end point')),
    cfg.IntOpt('request_timeout', default=3000,
               help=_("The number of milliseconds the agent will wait for "
                      "response on request to daemon.")),
    cfg.IntOpt('retries', default=3,
               help=_("The number of retries the agent will send request "
                      "to daemon before giving up")),
    cfg.IntOpt('backoff_rate', default=2,
               help=_("backoff rate multiplier for waiting period between "
                      "retries for request to daemon, i.e. value of 2 will "
                      " double the request timeout each retry")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]


cfg.CONF.register_opts(eswitch_opts, "ESWITCH")
cfg.CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)
