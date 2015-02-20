# Copyright 2014 OneConvergence, Inc. All Rights Reserved.
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
#

""" Register the configuration options"""

from oslo_config import cfg


NVSD_OPT = [
    cfg.StrOpt('nvsd_ip',
               default='127.0.0.1',
               help=_("NVSD Controller IP address")),
    cfg.IntOpt('nvsd_port',
               default=8082,
               help=_("NVSD Controller Port number")),
    cfg.StrOpt('nvsd_user',
               default='ocplugin',
               help=_("NVSD Controller username")),
    cfg.StrOpt('nvsd_passwd',
               default='oc123', secret=True,
               help=_("NVSD Controller password")),
    cfg.IntOpt('request_timeout',
               default=30,
               help=_("NVSD controller REST API request timeout in seconds")),
    cfg.IntOpt('nvsd_retries', default=0,
               help=_("Number of login retries to NVSD controller"))
]

agent_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("integration bridge")),
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]

cfg.CONF.register_opts(NVSD_OPT, "nvsd")
cfg.CONF.register_opts(agent_opts, "AGENT")

CONF = cfg.CONF
AGENT = cfg.CONF.AGENT
