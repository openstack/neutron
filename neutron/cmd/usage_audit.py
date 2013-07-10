#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 New Dream Network, LLC (DreamHost)
# Author: Julien Danjou <julien@danjou.info>
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

from oslo.config import cfg

from neutron.common import config
from neutron import context
from neutron import manager
from neutron.openstack.common.notifier import api as notifier_api


def main():
    cfg.CONF(project='neutron')
    config.setup_logging(cfg.CONF)

    cxt = context.get_admin_context()
    plugin = manager.NeutronManager.get_plugin()
    for network in plugin.get_networks(cxt):
        notifier_api.notify(cxt,
                            notifier_api.publisher_id('network'),
                            'network.exists',
                            notifier_api.INFO,
                            {'network': network})
    for subnet in plugin.get_subnets(cxt):
        notifier_api.notify(cxt,
                            notifier_api.publisher_id('network'),
                            'subnet.exists',
                            notifier_api.INFO,
                            {'subnet': subnet})
    for port in plugin.get_ports(cxt):
        notifier_api.notify(cxt,
                            notifier_api.publisher_id('network'),
                            'port.exists',
                            notifier_api.INFO,
                            {'port': port})
    for router in plugin.get_routers(cxt):
        notifier_api.notify(cxt,
                            notifier_api.publisher_id('network'),
                            'router.exists',
                            notifier_api.INFO,
                            {'router': router})
    for floatingip in plugin.get_floatingips(cxt):
        notifier_api.notify(cxt,
                            notifier_api.publisher_id('network'),
                            'floatingip.exists',
                            notifier_api.INFO,
                            {'floatingip': floatingip})
