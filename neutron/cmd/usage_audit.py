#!/usr/bin/env python
# Copyright (c) 2012 New Dream Network, LLC (DreamHost)
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
"""Cron script to generate usage notifications for networks, ports and
subnets.

"""

import sys

from neutron.common import config
from neutron.common import rpc as n_rpc
from neutron import context
from neutron import manager
from neutron.plugins.common import constants


def main():
    config.init(sys.argv[1:])
    config.setup_logging()

    cxt = context.get_admin_context()
    plugin = manager.NeutronManager.get_plugin()
    l3_plugin = manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
    notifier = n_rpc.get_notifier('network')
    for network in plugin.get_networks(cxt):
        notifier.info(cxt, 'network.exists', {'network': network})
    for subnet in plugin.get_subnets(cxt):
        notifier.info(cxt, 'subnet.exists', {'subnet': subnet})
    for port in plugin.get_ports(cxt):
        notifier.info(cxt, 'port.exists', {'port': port})
    for router in l3_plugin.get_routers(cxt):
        notifier.info(cxt, 'router.exists', {'router': router})
    for floatingip in l3_plugin.get_floatingips(cxt):
        notifier.info(cxt, 'floatingip.exists', {'floatingip': floatingip})
