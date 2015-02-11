# Copyright 2014 IBM Corp.
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


DEFAULT_INTERFACE_MAPPINGS = []
DEFAULT_CONTROLLER_IPS = ['127.0.0.1']

sdnve_opts = [
    cfg.BoolOpt('use_fake_controller', default=False,
                help=_("Whether to use a fake controller.")),
    cfg.StrOpt('base_url', default='/one/nb/v2/',
               help=_("Base URL for SDN-VE controller REST API.")),
    cfg.ListOpt('controller_ips', default=DEFAULT_CONTROLLER_IPS,
                help=_("List of IP addresses of SDN-VE controller(s).")),
    cfg.StrOpt('info', default='sdnve_info_string',
               help=_("SDN-VE RPC subject.")),
    cfg.StrOpt('port', default='8443',
               help=_("SDN-VE controller port number.")),
    cfg.StrOpt('format', default='json',
               help=_("SDN-VE request/response format.")),
    cfg.StrOpt('userid', default='admin',
               help=_("SDN-VE administrator user ID.")),
    cfg.StrOpt('password', default='admin', secret=True,
               help=_("SDN-VE administrator password.")),
    cfg.StrOpt('integration_bridge',
               help=_("Integration bridge to use.")),
    cfg.BoolOpt('reset_bridge', default=True,
                help=_("Whether to reset the integration bridge before use.")),
    cfg.BoolOpt('out_of_band', default=True,
                help=_("Indicating if controller is out of band or not.")),
    cfg.ListOpt('interface_mappings',
                default=DEFAULT_INTERFACE_MAPPINGS,
                help=_("List of <physical_network_name>:<interface_name> "
                       "mappings.")),
    cfg.StrOpt('default_tenant_type', default='OVERLAY',
               help=_("Tenant type: OVERLAY (default) or OF.")),
    cfg.StrOpt('overlay_signature', default='SDNVE-OVERLAY',
               help=_("The string in tenant description that indicates "
                      "the tenant is a OVERLAY tenant.")),
    cfg.StrOpt('of_signature', default='SDNVE-OF',
               help=_("The string in tenant description that indicates "
                      "the tenant is a OF tenant.")),
]

sdnve_agent_opts = [
    cfg.IntOpt('polling_interval', default=2,
               help=_("Agent polling interval if necessary.")),
    cfg.BoolOpt('rpc', default=True,
                help=_("Whether to use rpc.")),

]


cfg.CONF.register_opts(sdnve_opts, "SDNVE")
cfg.CONF.register_opts(sdnve_agent_opts, "SDNVE_AGENT")
