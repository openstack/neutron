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

import copy
import threading

from networking_arista.common import db_lib
from networking_arista.l3Plugin import arista_l3_driver
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.rpc.handlers import l3_rpc
from neutron.common import constants as q_const
from neutron.common import log
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron import context as nctx
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.i18n import _LE, _LI
from neutron.plugins.common import constants
from neutron.plugins.ml2.driver_context import NetworkContext  # noqa

LOG = logging.getLogger(__name__)


class AristaL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                   extraroute_db.ExtraRoute_db_mixin,
                   l3_gwmode_db.L3_NAT_db_mixin,
                   l3_agentschedulers_db.L3AgentSchedulerDbMixin):

    """Implements L3 Router service plugin for Arista hardware.

    Creates routers in Arista hardware, manages them, adds/deletes interfaces
    to the routes.
    """

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self, driver=None):

        self.driver = driver or arista_l3_driver.AristaL3Driver()
        self.ndb = db_lib.NeutronNets()
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
        self.endpoints = [l3_rpc.L3RpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("Arista L3 Router Service Plugin for Arista Hardware "
                "based routing")

    def _synchronization_thread(self):
        with self.sync_lock:
            self.synchronize()

        self.timer = threading.Timer(self.sync_timeout,
                                     self._synchronization_thread)
        self.timer.start()

    def stop_synchronization_thread(self):
        if self.timer:
            self.timer.cancel()
            self.timer = None

    @log.log
    def create_router(self, context, router):
        """Create a new router entry in DB, and create it Arista HW."""

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
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Error creating router on Arista HW router=%s "),
                          new_router)
                super(AristaL3ServicePlugin, self).delete_router(context,
                                                    new_router['id'])

    @log.log
    def update_router(self, context, router_id, router):
        """Update an existing router in DB, and update it in Arista HW."""

        with context.session.begin(subtransactions=True):
            # Read existing router record from DB
            original_router = super(AristaL3ServicePlugin, self).get_router(
                                    context, router_id)
            # Update router DB
            new_router = super(AristaL3ServicePlugin, self).update_router(
                context, router_id, router)

        # Modify router on the Arista Hw
        try:
            self.driver.update_router(context, router_id,
                                      original_router, new_router)
            return new_router
        except Exception:
            LOG.error(_LE("Error updating router on Arista HW router=%s "),
                      new_router)

    @log.log
    def delete_router(self, context, router_id):
        """Delete an existing router from Arista HW as well as from the DB."""

        router = super(AristaL3ServicePlugin, self).get_router(context,
                                                               router_id)
        tenant_id = router['tenant_id']

        # Delete router on the Arista Hw
        try:
            self.driver.delete_router(context, tenant_id, router_id, router)
        except Exception as e:
            LOG.error(_LE("Error deleting router on Arista HW "
                          "router %(r)s exception=%(e)s"),
                      {'r': router, 'e': e})

        with context.session.begin(subtransactions=True):
            super(AristaL3ServicePlugin, self).delete_router(context,
                                                             router_id)

    @log.log
    def add_router_interface(self, context, router_id, interface_info):
        """Add a subnet of a network to an existing router."""

        new_router = super(AristaL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)

        # Get network info for the subnet that is being added to the router.
        # Check if the interface information is by port-id or subnet-id
        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        if add_by_sub:
            subnet = self.get_subnet(context, interface_info['subnet_id'])
        elif add_by_port:
            port = self.get_port(context, interface_info['port_id'])
            subnet_id = port['fixed_ips'][0]['subnet_id']
            subnet = self.get_subnet(context, subnet_id)
        network_id = subnet['network_id']

        # To create SVI's in Arista HW, the segmentation Id is required
        # for this network.
        ml2_db = NetworkContext(self, context, {'id': network_id})
        seg_id = ml2_db.network_segments[0]['segmentation_id']

        # Package all the info needed for Hw programming
        router = super(AristaL3ServicePlugin, self).get_router(context,
                                                               router_id)
        router_info = copy.deepcopy(new_router)
        router_info['seg_id'] = seg_id
        router_info['name'] = router['name']
        router_info['cidr'] = subnet['cidr']
        router_info['gip'] = subnet['gateway_ip']
        router_info['ip_version'] = subnet['ip_version']

        try:
            self.driver.add_router_interface(context, router_info)
            return new_router
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Error Adding subnet %(subnet)s to "
                              "router %(router_id)s on Arista HW"),
                          {'subnet': subnet, 'router_id': router_id})
                super(AristaL3ServicePlugin, self).remove_router_interface(
                                                    context,
                                                    router_id,
                                                    interface_info)

    @log.log
    def remove_router_interface(self, context, router_id, interface_info):
        """Remove a subnet of a network from an existing router."""

        new_router = (
                   super(AristaL3ServicePlugin, self).remove_router_interface(
                         context, router_id, interface_info))

        # Get network information of the subnet that is being removed
        subnet = self.get_subnet(context, new_router['subnet_id'])
        network_id = subnet['network_id']

        # For SVI removal from Arista HW, segmentation ID is needed
        ml2_db = NetworkContext(self, context, {'id': network_id})
        seg_id = ml2_db.network_segments[0]['segmentation_id']

        router = super(AristaL3ServicePlugin, self).get_router(context,
                                                               router_id)
        router_info = copy.deepcopy(new_router)
        router_info['seg_id'] = seg_id
        router_info['name'] = router['name']

        try:
            self.driver.remove_router_interface(context, router_info)
            return new_router
        except Exception as exc:
            LOG.error(_LE("Error removing interface %(interface)s from "
                          "router %(router_id)s on Arista HW"
                          "Exception =(exc)s"),
                      {'interface': interface_info, 'router_id': router_id,
                       'exc': exc})

    def synchronize(self):
        """Synchronizes Router DB from Neturon DB with EOS.

        Walks through the Neturon Db and ensures that all the routers
        created in Netuton DB match with EOS. After creating appropriate
        routers, it ensures to add interfaces as well.
        Uses idempotent properties of EOS configuration, which means
        same commands can be repeated.
        """
        LOG.info(_LI('Syncing Neutron Router DB <-> EOS'))
        ctx = nctx.get_admin_context()

        routers = super(AristaL3ServicePlugin, self).get_routers(ctx)
        for r in routers:
            tenant_id = r['tenant_id']
            ports = self.ndb.get_all_ports_for_tenant(tenant_id)

            try:
                self.driver.create_router(self, tenant_id, r)

            except Exception:
                continue

            # Figure out which interfaces are added to this router
            for p in ports:
                if p['device_id'] == r['id']:
                    net_id = p['network_id']
                    subnet_id = p['fixed_ips'][0]['subnet_id']
                    subnet = self.ndb.get_subnet_info(subnet_id)
                    ml2_db = NetworkContext(self, ctx, {'id': net_id})
                    seg_id = ml2_db.network_segments[0]['segmentation_id']

                    r['seg_id'] = seg_id
                    r['cidr'] = subnet['cidr']
                    r['gip'] = subnet['gateway_ip']
                    r['ip_version'] = subnet['ip_version']

                    try:
                        self.driver.add_router_interface(self, r)
                    except Exception:
                        LOG.error(_LE("Error Adding interface %(subnet_id)s "
                                      "to router %(router_id)s on Arista HW"),
                                  {'subnet_id': subnet_id, 'router_id': r})
