# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Big Switch Networks, Inc.
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
#
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.
# @author: Kevin Benton, Big Switch Networks, Inc.
import copy

import eventlet
from oslo.config import cfg

from neutron import context as ctx
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.bigswitch import config as pl_config
from neutron.plugins.bigswitch import plugin
from neutron.plugins.bigswitch import servermanager
from neutron.plugins.ml2 import driver_api as api


LOG = log.getLogger(__name__)
put_context_in_serverpool = plugin.put_context_in_serverpool


class BigSwitchMechanismDriver(plugin.NeutronRestProxyV2Base,
                               api.MechanismDriver):

    """Mechanism Driver for Big Switch Networks Controller.

    This driver relays the network create, update, delete
    operations to the Big Switch Controller.
    """

    def initialize(self):
        LOG.debug(_('Initializing driver'))

        # register plugin config opts
        pl_config.register_config()
        self.evpool = eventlet.GreenPool(cfg.CONF.RESTPROXY.thread_pool_size)
        # backend doesn't support bulk operations yet
        self.native_bulk_support = False

        # init network ctrl connections
        self.servers = servermanager.ServerPool()
        self.servers.get_topo_function = self._get_all_data
        self.servers.get_topo_function_args = {'get_ports': True,
                                               'get_floating_ips': False,
                                               'get_routers': False}
        self.segmentation_types = ', '.join(cfg.CONF.ml2.type_drivers)
        LOG.debug(_("Initialization done"))

    @put_context_in_serverpool
    def create_network_postcommit(self, context):
        # create network on the network controller
        self._send_create_network(context.current)

    @put_context_in_serverpool
    def update_network_postcommit(self, context):
        # update network on the network controller
        self._send_update_network(context.current)

    @put_context_in_serverpool
    def delete_network_postcommit(self, context):
        # delete network on the network controller
        self._send_delete_network(context.current)

    @put_context_in_serverpool
    def create_port_postcommit(self, context):
        # create port on the network controller
        port = self._prepare_port_for_controller(context)
        if port:
            self.async_port_create(port["network"]["tenant_id"],
                                   port["network"]["id"], port)

    @put_context_in_serverpool
    def update_port_postcommit(self, context):
        # update port on the network controller
        port = self._prepare_port_for_controller(context)
        if port:
            self.servers.rest_update_port(port["network"]["tenant_id"],
                                          port["network"]["id"], port)

    @put_context_in_serverpool
    def delete_port_postcommit(self, context):
        # delete port on the network controller
        port = context.current
        net = context.network.current
        self.servers.rest_delete_port(net["tenant_id"], net["id"], port['id'])

    def _prepare_port_for_controller(self, context):
        # make a copy so the context isn't changed for other drivers
        port = copy.deepcopy(context.current)
        net = context.network.current
        port['network'] = net
        port['bound_segment'] = context.bound_segment
        actx = ctx.get_admin_context()
        prepped_port = self._extend_port_dict_binding(actx, port)
        prepped_port = self._map_state_and_status(prepped_port)
        if (portbindings.HOST_ID not in prepped_port or
            prepped_port[portbindings.HOST_ID] == ''):
            LOG.warning(_("Ignoring port notification to controller because "
                          "of missing host ID."))
            # in ML2, controller doesn't care about ports without
            # the host_id set
            return False
        return prepped_port
