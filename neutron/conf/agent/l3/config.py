# Copyright (c) 2015 OpenStack Foundation.
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

from neutron_lib import constants
from oslo_config import cfg

from neutron._i18n import _


OPTS = [
    cfg.StrOpt('agent_mode', default=constants.L3_AGENT_MODE_LEGACY,
               choices=(constants.L3_AGENT_MODE_DVR,
                        constants.L3_AGENT_MODE_DVR_SNAT,
                        constants.L3_AGENT_MODE_LEGACY,
                        constants.L3_AGENT_MODE_DVR_NO_EXTERNAL),
               help=_("The working mode for the agent. Allowed modes are: "
                      "'legacy' - this preserves the existing behavior "
                      "where the L3 agent is deployed on a centralized "
                      "networking node to provide L3 services like DNAT, "
                      "and SNAT. Use this mode if you do not want to "
                      "adopt DVR. 'dvr' - this mode enables DVR "
                      "functionality and must be used for an L3 agent "
                      "that runs on a compute host. 'dvr_snat' - this "
                      "enables centralized SNAT support in conjunction "
                      "with DVR.  This mode must be used for an L3 agent "
                      "running on a centralized node (or in single-host "
                      "deployments, e.g. devstack). "
                      "dvr_snat mode is not supported on a compute host. "
                      "'dvr_no_external' - this mode enables only East/West "
                      "DVR routing functionality for a L3 agent that runs on "
                      "a compute host, the North/South functionality such "
                      "as DNAT and SNAT will be provided by the centralized "
                      "network node that is running in 'dvr_snat' mode. "
                      "This mode should be used when there is no "
                      "external network connectivity on the compute host.")),
    cfg.PortOpt('metadata_port',
                default=9697,
                help=_("TCP Port used by Neutron metadata namespace proxy.")),
    cfg.BoolOpt('handle_internal_only_routers',
                default=True,
                help=_("Indicates that this L3 agent should also handle "
                       "routers that do not have an external network gateway "
                       "configured. This option should be True only for a "
                       "single agent in a Neutron deployment, and may be "
                       "False for all agents if all routers must have an "
                       "external network gateway.")),
    cfg.StrOpt('ipv6_gateway', default='',
               help=_("With IPv6, the network used for the external gateway "
                      "does not need to have an associated subnet, since the "
                      "automatically assigned link-local address (LLA) can "
                      "be used. However, an IPv6 gateway address is needed "
                      "for use as the next-hop for the default route. "
                      "If no IPv6 gateway address is configured here, "
                      "(and only then) the neutron router will be configured "
                      "to get its default route from router advertisements "
                      "(RAs) from the upstream router; in which case the "
                      "upstream router must also be configured to send "
                      "these RAs. "
                      "The ipv6_gateway, when configured, should be the LLA "
                      "of the interface on the upstream router. If a "
                      "next-hop using a global unique address (GUA) is "
                      "desired, it needs to be done via a subnet allocated "
                      "to the network and not through this parameter. ")),
    cfg.StrOpt('prefix_delegation_driver',
               default='dibbler',
               help=_('Driver used for ipv6 prefix delegation. This needs to '
                      'be an entry point defined in the '
                      'neutron.agent.linux.pd_drivers namespace. See '
                      'setup.cfg for entry points included with the neutron '
                      'source.')),
    cfg.BoolOpt('enable_metadata_proxy', default=True,
                help=_("Allow running metadata proxy.")),
    cfg.StrOpt('metadata_access_mark',
               default='0x1',
               help=_('Iptables mangle mark used to mark metadata valid '
                      'requests. This mark will be masked with 0xffff so '
                      'that only the lower 16 bits will be used.')),
    cfg.StrOpt('external_ingress_mark',
               default='0x2',
               help=_('Iptables mangle mark used to mark ingress from '
                      'external network. This mark will be masked with '
                      '0xffff so that only the lower 16 bits will be used.')),
    cfg.StrOpt('radvd_user',
               default='',
               help=_('The username passed to radvd, used to drop root '
                      'privileges and change user ID to username and group ID '
                      'to the primary group of username. If no user specified '
                      '(by default), the user executing the L3 agent will be '
                      'passed. If "root" specified, because radvd is spawned '
                      'as root, no "username" parameter will be passed.')),
    cfg.BoolOpt('cleanup_on_shutdown', default=False,
                help=_('Delete all routers on L3 agent shutdown. For L3 HA '
                       'routers it includes a shutdown of keepalived and '
                       'the state change monitor. NOTE: Setting to True '
                       'could affect the data plane when stopping or '
                       'restarting the L3 agent.')),
]


def register_l3_agent_config_opts(opts, cfg=cfg.CONF):
    cfg.register_opts(opts)
