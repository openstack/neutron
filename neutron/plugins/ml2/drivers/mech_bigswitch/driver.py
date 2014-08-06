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
import copy
import datetime
import httplib

import eventlet
from oslo.config import cfg

from neutron import context as ctx
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import log
from neutron.openstack.common import timeutils
from neutron.plugins.bigswitch import config as pl_config
from neutron.plugins.bigswitch import plugin
from neutron.plugins.bigswitch import servermanager
from neutron.plugins.common import constants as pconst
from neutron.plugins.ml2 import driver_api as api


EXTERNAL_PORT_OWNER = 'neutron:external_port'
LOG = log.getLogger(__name__)
put_context_in_serverpool = plugin.put_context_in_serverpool

# time in seconds to maintain existence of vswitch response
CACHE_VSWITCH_TIME = 60


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
        # Track hosts running IVS to avoid excessive calls to the backend
        self.ivs_host_cache = {}

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
            try:
                self.async_port_create(port["network"]["tenant_id"],
                                       port["network"]["id"], port)
            except servermanager.RemoteRestError as e:
                with excutils.save_and_reraise_exception() as ctxt:
                    if (cfg.CONF.RESTPROXY.auto_sync_on_failure and
                        e.status == httplib.NOT_FOUND and
                        servermanager.NXNETWORK in e.reason):
                        ctxt.reraise = False
                        LOG.error(_("Iconsistency with backend controller "
                                    "triggering full synchronization."))
                        topoargs = self.servers.get_topo_function_args
                        self._send_all_data(
                            send_ports=topoargs['get_ports'],
                            send_floating_ips=topoargs['get_floating_ips'],
                            send_routers=topoargs['get_routers'],
                            triggered_by_tenant=port["network"]["tenant_id"]
                        )

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

    def bind_port(self, context):
        """Marks ports as bound.

        Binds external ports and IVS ports.
        Fabric configuration will occur on the subsequent port update.
        Currently only vlan segments are supported.
        """
        if context.current['device_owner'] == EXTERNAL_PORT_OWNER:
            # TODO(kevinbenton): check controller to see if the port exists
            # so this driver can be run in parallel with others that add
            # support for external port bindings
            for segment in context.network.network_segments:
                if segment[api.NETWORK_TYPE] == pconst.TYPE_VLAN:
                    context.set_binding(
                        segment[api.ID], portbindings.VIF_TYPE_BRIDGE,
                        {portbindings.CAP_PORT_FILTER: False,
                         portbindings.OVS_HYBRID_PLUG: False})
                    return

        # IVS hosts will have a vswitch with the same name as the hostname
        if self.does_vswitch_exist(context.host):
            for segment in context.network.network_segments:
                if segment[api.NETWORK_TYPE] == pconst.TYPE_VLAN:
                    context.set_binding(
                        segment[api.ID], portbindings.VIF_TYPE_IVS,
                        {portbindings.CAP_PORT_FILTER: True,
                        portbindings.OVS_HYBRID_PLUG: False})

    def does_vswitch_exist(self, host):
        """Check if Indigo vswitch exists with the given hostname.

        Returns True if switch exists on backend.
        Returns False if switch does not exist.
        Returns None if backend could not be reached.
        Caches response from backend.
        """
        try:
            return self._get_cached_vswitch_existence(host)
        except ValueError:
            # cache was empty for that switch or expired
            pass

        try:
            self.servers.rest_get_switch(host)
            exists = True
        except servermanager.RemoteRestError as e:
            if e.status == 404:
                exists = False
            else:
                # Another error, return without caching to try again on
                # next binding
                return
        self.ivs_host_cache[host] = {
            'timestamp': datetime.datetime.now(),
            'exists': exists
        }
        return exists

    def _get_cached_vswitch_existence(self, host):
        """Returns cached existence. Old and non-cached raise ValueError."""
        entry = self.ivs_host_cache.get(host)
        if not entry:
            raise ValueError(_('No cache entry for host %s') % host)
        diff = timeutils.delta_seconds(entry['timestamp'],
                                       datetime.datetime.now())
        if diff > CACHE_VSWITCH_TIME:
            self.ivs_host_cache.pop(host)
            raise ValueError(_('Expired cache entry for host %s') % host)
        return entry['exists']
