# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Arista Networks, Inc.  All rights reserved.
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
# @author: Sukhdev Kapur, Arista Networks, Inc.
#

import threading
from oslo.config import cfg

from neutron import context as nctx
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import constants as q_const
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_rpc_base
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.arista.arista_l3_driver import AristaL3Driver
from neutron.plugins.ml2.drivers.arista.arista_l3_driver import NeutronNets
from neutron.plugins.ml2.driver_context import NetworkContext

LOG = logging.getLogger(__name__)


class AristaL3ServicePluginRpcCallbacks(q_rpc.RpcCallback,
                               l3_rpc_base.L3RpcCallbackMixin):

    RPC_API_VERSION = '1.2'


class AristaL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                   extraroute_db.ExtraRoute_db_mixin,
                   l3_gwmode_db.L3_NAT_db_mixin,
                   l3_agentschedulers_db.L3AgentSchedulerDbMixin):

    """Implements L3 Router service plugin for Arista Hardware.

    Creates routers in Arista Hardware, managees them, adds/deletes interfaces
    to the routes. 
    """

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self, driver=None):

        self.driver = driver or AristaL3Driver()
        self.ndb = NeutronNets()
        #self.sync_serv = SyncService()
        self.setup_rpc()
        self.sync_timeout = cfg.CONF.l3_arista.l3_sync_interval
        self.sync_lock = threading.Lock()
        self._synchronization_thread()


    def setup_rpc(self):
        # RPC support
        self.topic = topics.L3PLUGIN
        self.conn = q_rpc.create_connection(new=True)
        self.agent_notifiers.update(
            {q_const.AGENT_TYPE_L3: l3_rpc_agent_api.L3AgentNotifyAPI()})
        self.endpoints = [AristaL3ServicePluginRpcCallbacks()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("Arista L3 Router Service Plugin for Arista Hardware "
                "based routing" )

    def _synchronization_thread(self):
        with self.sync_lock:
            #self.sync_serv.synchronize()
            self.synchronize()

        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()

    def stop_synchronization_thread(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    def create_router(self, context, router):
        """Create a new router entry in DB, and create it Arista HW"""

        LOG.debug(_("AristaL3ServicePlugin.create_router() called, "
                    "router=%s ."), router)
        tenant_id = self._get_tenant_id_for_create(context, router['router'])

        # Add router to the DB
        with context.session.begin(subtransactions=True):
            new_router = super(AristaL3ServicePlugin, self).create_router(
                                                                 context,
                                                                 router)
        # create router on the Arista Hw
        try:
            self.driver.create_router(context, tenant_id, new_router)
            return new_router
        except Exception:
            LOG.error(_("Error creating router on Arista HW "
                        "router=%s ") % new_router)
            with excutils.save_and_reraise_exception():
                super(AristaL3ServicePlugin, self).delete_router(context,
                                                    new_router['id'])

    def update_router(self, context, router_id, router):
        """Update an existing router in DB, and update it in Arista HW"""

        LOG.debug(_("AristaL3ServicePlugin.update_router() called, "
                    "id=%(id)s, router=%(router)s ."),
                  {'id': router_id, 'router': router})

        with context.session.begin(subtransactions=True):
            #Read existing router record from DB
            original_router = super(AristaL3ServicePlugin, self).get_router(
                                    context, router_id)
            #Update the router DB
            new_router = super(AristaL3ServicePlugin, self).update_router(
                context, router_id, router)

        # modify router on the Arista Hw
        try:
            self.driver.update_router(context, router_id,
                                      original_router, new_router)
            return new_router
        except Exception:
            LOG.error(_("Error updating router on Arista HW "
                        "router=%s ") % new_router)
            #reset the router to original settings
            #super(AristaL3ServicePlugin, self).update_router(context,
            #                                      router_id, original_router)

    def delete_router(self, context, router_id):
        """Delete an existing from Arista HW as well as from the DB"""

        LOG.debug(_("AristaL3ServicePlugin.delete_router() called, id=%s."),
                     router_id)

        router = super(AristaL3ServicePlugin, self).get_router(context,
                                                               router_id)
        tenant_id = router['tenant_id']

        # delete router on the Arista Hw
        try:
            self.driver.delete_router(context, tenant_id, router_id, router)
        except Exception as e:
            LOG.error(_("Error deleting router on Arista HW "
                        "router id=%s exception=%s") % (router,e))

        with context.session.begin(subtransactions=True):
            super(AristaL3ServicePlugin, self).delete_router(context,
                                                             router_id)


    def add_router_interface(self, context, router_id, interface_info):
        """Add a subnet of a network to an existing router"""

        LOG.debug(_("AristaL3ServicePlugin.add_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  {'id': router_id, 'interface': interface_info})
        
        router_info =  super(AristaL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)

        #Get network information for the subnet that is being added to the 
        #router. 
        #Check if the interface information is by port-id or subnet-id
        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        if add_by_sub:
            subnet = self.get_subnet(context, interface_info['subnet_id'])
        elif add_by_port:
            port = self.get_port(context, interface_info['port_id'])
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet = self.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
            
        #To create SVI's in Arista HW, the segmentation Id is required
        #for this network. 
        ml2_db = NetworkContext(self, context, {'id' : network_id} )
        seg_id = ml2_db.network_segments[0]['segmentation_id']

        #Package all the info needed for Hw programming
        router = super(AristaL3ServicePlugin, self).get_router(context,
                                                               router_id)
        router_info['seg_id'] =  seg_id
        router_info['name'] =  router['name']
        router_info['cidr'] =  subnet['cidr']
        router_info['gip'] =  subnet['gateway_ip']
        router_info['ip_version'] =  subnet['ip_version']

        try:
            self.driver.add_router_interface(context, router_info)
            return router_info
        except Exception:
            LOG.error(_("Error Adding interface %(subnet_id)s to "
                        "router %(router_id)s on Arista HW") % 
                         {'subnet_id': subnet_id, 'router_id':router_id})
            with excutils.save_and_reraise_exception():
                super(AristaL3ServicePlugin, self).remove_router_interface(
                                                    context,
                                                    router_id,
                                                    interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        """Add a subnet of a network to an existing router"""

        LOG.debug(_("AristaDriver.remove_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  {'id': router_id, 'interface': interface_info})


        router_info = super(AristaL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)

        #get network information of the subnet that is being removed
        subnet = self.get_subnet(context, router_info['subnet_id'])
        network_id = subnet['network_id']

        #For SVI removal from Arista HW, segmentation ID is needed
        ml2_db = NetworkContext(self, context, {'id' : network_id} )
        seg_id = ml2_db.network_segments[0]['segmentation_id']

        router = super(AristaL3ServicePlugin, self).get_router(context,
                                                               router_id)
        router_info['seg_id'] =  seg_id
        router_info['name'] =  router['name']

        try:
            self.driver.remove_router_interface(context, router_info)
            return router_info
        except Exception as exc:
            LOG.error(_("Error removing interface %(interface)s from "
                        "router %(router_id)s on Arista HW"
                        "Exception =(exc)s") % {'interface': interface_info,
                                                'router_id':router_id
                                                'e': exc})

    def synchronize(self):
        """Syncronizes Router DB from Neturon DB with EOS.

        Walks through the Neturon Db and ensures that all the routers
        created in Netuton DB match with EOS. After creating appropriate
        routers, it ensures to add interfaces as well. 
        uses idompotent properties of EOS configuration, which means
        same commands can be repeated. 
        """
        LOG.info(_('Syncing Neutron Router DB <-> EOS'))
        ctx = nctx.get_admin_context()

        routers = super(AristaL3ServicePlugin, self).get_routers(ctx)
        for r in routers:
            print r
            tenant_id = r['tenant_id']
            ports =self.ndb.get_all_ports_for_tenant(tenant_id)

            try:
                self.driver.create_router(self, tenant_id, r)
                
            except Exception as e:
                print e
                continue

            "figure out which interfaces are added to this router"
            for p in ports:
                if p['device_id'] == r['id']:
                    net_id = p['network_id']
                    subnet_id = p['fixed_ips'][0]['subnet_id']
                    subnet = self.ndb.get_subnet_info(subnet_id)
                    ml2_db = NetworkContext(self, ctx, {'id' : net_id} )
                    seg_id = ml2_db.network_segments[0]['segmentation_id']

                    r['seg_id'] =  seg_id
                    r['cidr'] =  subnet['cidr']
                    r['gip'] =  subnet['gateway_ip']
                    r['ip_version'] =  subnet['ip_version']

                    try:
                        self.driver.add_router_interface(self, r)
                    except Exception as e:
                        LOG.error(_("Error Adding interface %(subnet_id)s to "
                                    "router %(router_id)s on Arista HW") % 
                                     {'subnet_id': subnet_id,
                                      'router_id':router_id})

    def _validate_interface_info(self, interface_info):
        port_id_specified = interface_info and 'port_id' in interface_info
        subnet_id_specified = interface_info and 'subnet_id' in interface_info
        if not (port_id_specified or subnet_id_specified):
            msg = _("Either subnet_id or port_id must be specified")
            #raise n_exc.BadRequest(resource='router', msg=msg)
        if port_id_specified and subnet_id_specified:
            msg = _("Cannot specify both subnet-id and port-id")
            #raise n_exc.BadRequest(resource='router', msg=msg)
        return port_id_specified, subnet_id_specified


class SyncService(extraroute_db.ExtraRoute_db_mixin):
    """Synchronizatin of information between Neutron and EOS

    Periodically (through configuration option), this service
    ensures that Networks and VMs configured on EOS/Arista HW
    are always in sync with Neutron DB.
    """

    def __init__(self):
        super(SyncService, self).__init__()
        self.admin_ctx = nctx.get_admin_context()

    #def synchronize(self):
    #    """Sends data to EOS which differs from neutron DB."""

    #    LOG.info(_('Syncing Neutron Router DB <-> EOS'))
    #    routers= self.get_routers(self.admin_ctx)
    #    print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" 
    #    print routers
    #    print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
