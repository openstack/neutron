# Copyright (c) 2014 Cisco Systems Inc.
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

from oslo_log import log

from neutron.common import constants as n_constants
from neutron import context
from neutron.i18n import _LW
from neutron import manager
from neutron.openstack.common import loopingcall
from neutron.plugins.ml2 import db as l2_db
from neutron.plugins.ml2 import driver_context

LOG = log.getLogger(__name__)


class SynchronizerBase(object):

    def __init__(self, driver, interval=None):
        self.core_plugin = manager.NeutronManager.get_plugin()
        self.driver = driver
        self.interval = interval

    def sync(self, f, *args, **kwargs):
        """Fire synchronization based on interval.

        Interval can be 0 for 'sync once' >0 for 'sync periodically' and
        <0 for 'no sync'
        """
        if self.interval:
            if self.interval > 0:
                loop_call = loopingcall.FixedIntervalLoopingCall(f, *args,
                                                                 **kwargs)
                loop_call.start(interval=self.interval)
                return loop_call
        else:
            # Fire once
            f(*args, **kwargs)


class ApicBaseSynchronizer(SynchronizerBase):

    def sync_base(self):
        self.sync(self._sync_base)

    def _sync_base(self):
        ctx = context.get_admin_context()
        # Sync Networks
        for network in self.core_plugin.get_networks(ctx):
            mech_context = driver_context.NetworkContext(self.core_plugin, ctx,
                                                         network)
            try:
                self.driver.create_network_postcommit(mech_context)
            except Exception:
                LOG.warn(_LW("Create network postcommit failed for "
                             "network %s"), network['id'])

        # Sync Subnets
        for subnet in self.core_plugin.get_subnets(ctx):
            mech_context = driver_context.SubnetContext(self.core_plugin, ctx,
                                                        subnet)
            try:
                self.driver.create_subnet_postcommit(mech_context)
            except Exception:
                LOG.warn(_LW("Create subnet postcommit failed for"
                             " subnet %s"), subnet['id'])

        # Sync Ports (compute/gateway/dhcp)
        for port in self.core_plugin.get_ports(ctx):
            _, binding = l2_db.get_locked_port_and_binding(ctx.session,
                                                           port['id'])
            network = self.core_plugin.get_network(ctx, port['network_id'])
            mech_context = driver_context.PortContext(self.core_plugin, ctx,
                                                      port, network, binding,
                                                      [])
            try:
                self.driver.create_port_postcommit(mech_context)
            except Exception:
                LOG.warn(_LW("Create port postcommit failed for"
                             " port %s"), port['id'])


class ApicRouterSynchronizer(SynchronizerBase):

    def sync_router(self):
        self.sync(self._sync_router)

    def _sync_router(self):
        ctx = context.get_admin_context()
        # Sync Router Interfaces
        filters = {'device_owner': [n_constants.DEVICE_OWNER_ROUTER_INTF]}
        for interface in self.core_plugin.get_ports(ctx, filters=filters):
            try:
                self.driver.add_router_interface_postcommit(
                    ctx, interface['device_id'],
                    {'port_id': interface['id']})
            except Exception:
                LOG.warn(_LW("Add interface postcommit failed for "
                             "port %s"), interface['id'])
