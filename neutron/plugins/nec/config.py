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

from oslo_config import cfg

from neutron.agent.common import config


ovs_opts = [
    cfg.StrOpt('integration_bridge', default='br-int',
               help=_("Integration bridge to use.")),
]

agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
]

ofc_opts = [
    cfg.StrOpt('host', default='127.0.0.1',
               help=_("Host to connect to.")),
    cfg.StrOpt('path_prefix', default='',
               help=_("Base URL of OFC REST API. "
                      "It is prepended to each API request.")),
    cfg.StrOpt('port', default='8888',
               help=_("Port to connect to.")),
    cfg.StrOpt('driver', default='trema',
               help=_("Driver to use.")),
    cfg.BoolOpt('enable_packet_filter', default=True,
                help=_("Enable packet filter.")),
    cfg.BoolOpt('support_packet_filter_on_ofc_router', default=True,
                help=_("Support packet filter on OFC router interface.")),
    cfg.BoolOpt('use_ssl', default=False,
                help=_("Use SSL to connect.")),
    cfg.StrOpt('key_file',
               help=_("Location of key file.")),
    cfg.StrOpt('cert_file',
               help=_("Location of certificate file.")),
    cfg.BoolOpt('insecure_ssl', default=False,
                help=_("Disable SSL certificate verification.")),
    cfg.IntOpt('api_max_attempts', default=3,
               help=_("Maximum attempts per OFC API request. "
                      "NEC plugin retries API request to OFC "
                      "when OFC returns ServiceUnavailable (503). "
                      "The value must be greater than 0.")),
]

provider_opts = [
    cfg.StrOpt('default_router_provider',
               default='l3-agent',
               help=_('Default router provider to use.')),
    cfg.ListOpt('router_providers',
                default=['l3-agent', 'openflow'],
                help=_('List of enabled router providers.'))
]


def register_plugin_opts():
    cfg.CONF.register_opts(ofc_opts, "OFC")
    cfg.CONF.register_opts(provider_opts, "PROVIDER")


def register_agent_opts():
    cfg.CONF.register_opts(agent_opts, "AGENT")
    cfg.CONF.register_opts(ovs_opts, "OVS")
    config.register_agent_state_opts_helper(cfg.CONF)
