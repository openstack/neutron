# Copyright 2011 VMware, Inc
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


SERVICE_OPTS = [
    cfg.IntOpt('periodic_interval',
               default=40,
               help=_('Seconds between running periodic tasks.')),
    cfg.IntOpt('api_workers',
               min=1,
               help=_('Number of separate API worker processes for service. '
                      'If not specified, the default is equal to the number '
                      'of CPUs available for best performance, capped by '
                      'potential RAM usage.')),
    cfg.IntOpt('rpc_workers',
               min=0,
               help=_('Number of RPC worker processes for service. '
                      'If not specified, the default is equal to half the '
                      'number of API workers. If set to 0, no RPC worker '
                      'is launched.')),
    cfg.IntOpt('rpc_state_report_workers',
               default=1,
               min=0,
               help=_('Number of RPC worker processes dedicated to the state '
                      'reports queue. If set to 0, no dedicated RPC worker '
                      'for state reports queue is launched.')),
    cfg.IntOpt('periodic_fuzzy_delay',
               default=5,
               help=_('Range of seconds to randomly delay when starting the '
                      'periodic task scheduler to reduce stampeding. '
                      '(Disable by setting to 0)')),
]

RPC_EXTRA_OPTS = [
    cfg.IntOpt('rpc_response_max_timeout',
               default=600,
               help=_('Maximum seconds to wait for a response from an RPC '
                      'call.')),
]

DNSSETTINGS_CONF_SECTION = 'customdns'
DNSSETTINGS_OPTS = [
    cfg.BoolOpt('enabled',
                default=False,
                help=_("Enable domain specific DNS settings")),
    cfg.ListOpt('upstream_dns_servers', default=[],
                help=_("Custom upstream DNS server IPs")),
    cfg.ListOpt('domain_name_prefixes', default=[],
                help=_("OS Domain Name Prefixes to match against")),
    cfg.ListOpt('project_ids', default=[],
                help=_("IDs of projects to match for testing only")),
]


def register_service_opts(opts, conf=cfg.CONF):
    conf.register_opts(opts)


def register_dns_opts(opts, conf=cfg.CONF):
    conf.register_opts(opts, group=DNSSETTINGS_CONF_SECTION)


def get_rpc_workers(conf=cfg.CONF):
    """Retrieve the conf knob rpc_workers, register option first if needed"""
    try:
        return conf.rpc_workers
    except cfg.NoSuchOptError:
        register_service_opts(SERVICE_OPTS, conf=conf)
        return conf.rpc_workers
