#
# Copyright 2013 Radware LTD.
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
# @author: Avishay Balderman, Radware

from oslo.config import cfg

from neutron.common import legacy
from neutron.db import api as qdbapi
from neutron.db.loadbalancer import loadbalancer_db
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)

DEFAULT_DRIVER = ("neutron.services.loadbalancer.drivers.haproxy"
                  ".plugin_driver.HaproxyOnHostPluginDriver")

lbaas_plugin_opts = [
    cfg.StrOpt('driver_fqn',
               default=DEFAULT_DRIVER,
               help=_('LBaaS driver Fully Qualified Name'))
]

cfg.CONF.register_opts(lbaas_plugin_opts, "LBAAS")
legacy.override_config(cfg.CONF, [('LBAAS', 'driver_fqn')])


class LoadBalancerPlugin(loadbalancer_db.LoadBalancerPluginDb):

    """Implementation of the Neutron Loadbalancer Service Plugin.

    This class manages the workflow of LBaaS request/response.
    Most DB related works are implemented in class
    loadbalancer_db.LoadBalancerPluginDb.
    """
    supported_extension_aliases = ["lbaas"]

    def __init__(self):
        """Initialization for the loadbalancer service plugin."""

        qdbapi.register_models()
        self._load_drivers()

    def _load_drivers(self):
        """Loads plugin-driver from configuration.

           That method will later leverage service type framework
        """
        try:
            self.driver = importutils.import_object(
                cfg.CONF.LBAAS.driver_fqn, self
            )
        except ImportError:
            LOG.exception(_("Error loading LBaaS driver %s"),
                          cfg.CONF.LBAAS.driver_fqn)

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return "Neutron LoadBalancer Service Plugin"

    def create_vip(self, context, vip):
        v = super(LoadBalancerPlugin, self).create_vip(context, vip)
        self.driver.create_vip(context, v)
        return v

    def update_vip(self, context, id, vip):
        if 'status' not in vip['vip']:
            vip['vip']['status'] = constants.PENDING_UPDATE
        old_vip = self.get_vip(context, id)
        v = super(LoadBalancerPlugin, self).update_vip(context, id, vip)
        self.driver.update_vip(context, old_vip, v)
        return v

    def _delete_db_vip(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_vip(context, id)

    def delete_vip(self, context, id):
        self.update_status(context, loadbalancer_db.Vip,
                           id, constants.PENDING_DELETE)
        v = self.get_vip(context, id)
        self.driver.delete_vip(context, v)

    def create_pool(self, context, pool):
        p = super(LoadBalancerPlugin, self).create_pool(context, pool)
        self.driver.create_pool(context, p)
        return p

    def update_pool(self, context, id, pool):
        if 'status' not in pool['pool']:
            pool['pool']['status'] = constants.PENDING_UPDATE
        old_pool = self.get_pool(context, id)
        p = super(LoadBalancerPlugin, self).update_pool(context, id, pool)
        self.driver.update_pool(context, old_pool, p)
        return p

    def _delete_db_pool(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_pool(context, id)

    def delete_pool(self, context, id):
        self.update_status(context, loadbalancer_db.Pool,
                           id, constants.PENDING_DELETE)
        p = self.get_pool(context, id)
        self.driver.delete_pool(context, p)

    def create_member(self, context, member):
        m = super(LoadBalancerPlugin, self).create_member(context, member)
        self.driver.create_member(context, m)
        return m

    def update_member(self, context, id, member):
        if 'status' not in member['member']:
            member['member']['status'] = constants.PENDING_UPDATE
        old_member = self.get_member(context, id)
        m = super(LoadBalancerPlugin, self).update_member(context, id, member)
        self.driver.update_member(context, old_member, m)
        return m

    def _delete_db_member(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_member(context, id)

    def delete_member(self, context, id):
        self.update_status(context, loadbalancer_db.Member,
                           id, constants.PENDING_DELETE)
        m = self.get_member(context, id)
        self.driver.delete_member(context, m)

    def create_health_monitor(self, context, health_monitor):
        # no PENDING_CREATE status sinse healthmon is shared DB object
        hm = super(LoadBalancerPlugin, self).create_health_monitor(
            context,
            health_monitor
        )
        self.driver.create_health_monitor(context, hm)
        return hm

    def update_health_monitor(self, context, id, health_monitor):
        if 'status' not in health_monitor['health_monitor']:
            health_monitor['health_monitor']['status'] = (
                constants.PENDING_UPDATE
            )
        old_hm = self.get_health_monitor(context, id)
        hm = super(LoadBalancerPlugin, self).update_health_monitor(
            context,
            id,
            health_monitor
        )

        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                loadbalancer_db.PoolMonitorAssociation
            ).filter_by(monitor_id=hm['id'])
            for assoc in qry:
                self.driver.update_health_monitor(context, old_hm,
                                                  hm, assoc['pool_id'])
        return hm

    def _delete_db_pool_health_monitor(self, context, hm_id, pool_id):
        super(LoadBalancerPlugin, self).delete_pool_health_monitor(context,
                                                                   hm_id,
                                                                   pool_id)

    def delete_health_monitor(self, context, id):
        with context.session.begin(subtransactions=True):
            hm = self.get_health_monitor(context, id)
            qry = context.session.query(
                loadbalancer_db.PoolMonitorAssociation
            ).filter_by(monitor_id=id)
            for assoc in qry:
                self.driver.delete_pool_health_monitor(context,
                                                       hm,
                                                       assoc['pool_id'])

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        retval = super(LoadBalancerPlugin, self).create_pool_health_monitor(
            context,
            health_monitor,
            pool_id
        )
        # open issue: PoolMonitorAssociation has no status field
        # so we cant set the status to pending and let the driver
        # set the real status of the association
        self.driver.create_pool_health_monitor(
            context, health_monitor, pool_id)
        return retval

    def delete_pool_health_monitor(self, context, id, pool_id):
        hm = self.get_health_monitor(context, id)
        self.driver.delete_pool_health_monitor(
            context, hm, pool_id)

    def stats(self, context, pool_id):
        stats_data = self.driver.stats(context, pool_id)
        # if we get something from the driver -
        # update the db and return the value from db
        # else - return what we have in db
        if stats_data:
            super(LoadBalancerPlugin, self)._update_pool_stats(
                context,
                pool_id,
                stats_data
            )
        return super(LoadBalancerPlugin, self).stats(context,
                                                     pool_id)

    def populate_vip_graph(self, context, vip):
        """Populate the vip with: pool, members, healthmonitors."""

        pool = self.get_pool(context, vip['pool_id'])
        vip['pool'] = pool
        vip['members'] = [
            self.get_member(context, member_id)
            for member_id in pool['members']]
        vip['health_monitors'] = [
            self.get_health_monitor(context, hm_id)
            for hm_id in pool['health_monitors']]
        return vip
