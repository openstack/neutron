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
    # TODO(kevinbenton): The following opt is duplicated between the OVS agent
    # and the Linuxbridge agent to make it easy to back-port. These shared opts
    # should be moved into a common agent config options location as part of
    # the deduplication work.
    cfg.BoolOpt('prevent_arp_spoofing', default=True,
                deprecated_for_removal=True,
                help=_("Enable suppression of ARP responses that don't match "
                       "an IP address that belongs to the port from which "
                       "they originate. Note: This prevents the VMs attached "
                       "to this agent from spoofing, it doesn't protect them "
                       "from other devices which have the capability to spoof "
                       "(e.g. bare metal or VMs attached to agents without "
                       "this flag set to True). Spoofing rules will not be "
                       "added to any ports that have port security disabled. "
                       "For LinuxBridge, this requires ebtables. For OVS, it "
                       "requires a version that supports matching ARP "
                       "headers. This option will be removed in Ocata so "
                       "the only way to disable protection will be via the "
                       "port security extension."))
]


def register_agent_opts(cfg=cfg.CONF):
    cfg.register_opts(agent_opts, "AGENT")
