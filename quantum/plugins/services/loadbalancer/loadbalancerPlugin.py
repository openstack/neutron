# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 OpenStack LLC.
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


from quantum.db import api as qdbapi
from quantum.db import model_base
from quantum.db.loadbalancer import loadbalancer_db
from quantum.extensions import loadbalancer
from quantum.openstack.common import log as logging
from quantum.plugins.common import constants

LOG = logging.getLogger(__name__)


class LoadBalancerPlugin(loadbalancer_db.LoadBalancerPluginDb):

    """
    Implementation of the Quantum Loadbalancer Service Plugin.

    This class manages the workflow of LBaaS request/response.
    Most DB related works are implemented in class
    loadbalancer_db.LoadBalancerPluginDb.
    """
    supported_extension_aliases = ["lbaas"]

    def __init__(self):
        """
        Do the initialization for the loadbalancer service plugin here.
        """
        qdbapi.register_models(base=model_base.BASEV2)

        # TODO: we probably need to setup RPC channel (to talk to LbAgent) here

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return "Quantum LoadBalancer Service Plugin"

    def create_vip(self, context, vip):
        v = super(LoadBalancerPlugin, self).create_vip(context, vip)
        self.update_status(context, loadbalancer_db.Vip, v['id'],
                           constants.PENDING_CREATE)
        LOG.debug(_("Create vip: %s"), v['id'])

        # If we adopt asynchronous mode, this method should return immediately
        # and let client to query the object status. The plugin will listen on
        # the event from device and update the object status by calling
        # self.update_state(context, Vip, id, ACTIVE/ERROR)
        #
        # In synchronous mode, send the request to device here and wait for
        # response. Eventually update the object status prior to the return.
        v_query = self.get_vip(context, v['id'])
        return v_query

    def update_vip(self, context, id, vip):
        v_query = self.get_vip(
            context, id, fields=["status"])
        if v_query['status'] in [
            constants.PENDING_DELETE, constants.ERROR]:
            raise loadbalancer.StateInvalid(id=id,
                                            state=v_query['status'])

        v = super(LoadBalancerPlugin, self).update_vip(context, id, vip)
        self.update_status(context, loadbalancer_db.Vip, id,
                           constants.PENDING_UPDATE)
        LOG.debug(_("Update vip: %s"), id)

        # TODO notify lbagent
        v_rt = self.get_vip(context, id)
        return v_rt

    def delete_vip(self, context, id):
        self.update_status(context, loadbalancer_db.Vip, id,
                           constants.PENDING_DELETE)
        LOG.debug(_("Delete vip: %s"), id)

        # TODO notify lbagent
        super(LoadBalancerPlugin, self).delete_vip(context, id)

    def get_vip(self, context, id, fields=None):
        res = super(LoadBalancerPlugin, self).get_vip(context, id, fields)
        LOG.debug(_("Get vip: %s"), id)
        return res

    def get_vips(self, context, filters=None, fields=None):
        res = super(LoadBalancerPlugin, self).get_vips(
            context, filters, fields)
        LOG.debug(_("Get vips"))
        return res

    def create_pool(self, context, pool):
        p = super(LoadBalancerPlugin, self).create_pool(context, pool)
        self.update_status(context, loadbalancer_db.Pool, p['id'],
                           constants.PENDING_CREATE)
        LOG.debug(_("Create pool: %s"), p['id'])

        # TODO notify lbagent
        p_rt = self.get_pool(context, p['id'])
        return p_rt

    def update_pool(self, context, id, pool):
        p_query = self.get_pool(context, id, fields=["status"])
        if p_query['status'] in [
            constants.PENDING_DELETE, constants.ERROR]:
            raise loadbalancer.StateInvalid(id=id,
                                            state=p_query['status'])
        p = super(LoadBalancerPlugin, self).update_pool(context, id, pool)
        LOG.debug(_("Update pool: %s"), p['id'])
        # TODO notify lbagent
        p_rt = self.get_pool(context, id)
        return p_rt

    def delete_pool(self, context, id):
        self.update_status(context, loadbalancer_db.Pool, id,
                           constants.PENDING_DELETE)
        # TODO notify lbagent
        super(LoadBalancerPlugin, self).delete_pool(context, id)
        LOG.debug(_("Delete pool: %s"), id)

    def get_pool(self, context, id, fields=None):
        res = super(LoadBalancerPlugin, self).get_pool(context, id, fields)
        LOG.debug(_("Get pool: %s"), id)
        return res

    def get_pools(self, context, filters=None, fields=None):
        res = super(LoadBalancerPlugin, self).get_pools(
            context, filters, fields)
        LOG.debug(_("Get Pools"))
        return res

    def stats(self, context, pool_id):
        res = super(LoadBalancerPlugin, self).get_stats(context, pool_id)
        LOG.debug(_("Get stats of Pool: %s"), pool_id)
        return res

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        m = super(LoadBalancerPlugin, self).create_pool_health_monitor(
            context, health_monitor, pool_id)
        LOG.debug(_("Create health_monitor of pool: %s"), pool_id)
        return m

    def get_pool_health_monitor(self, context, id, pool_id, fields=None):
        m = super(LoadBalancerPlugin, self).get_pool_health_monitor(
            context, id, pool_id, fields)
        LOG.debug(_("Get health_monitor of pool: %s"), pool_id)
        return m

    def delete_pool_health_monitor(self, context, id, pool_id):
        super(LoadBalancerPlugin, self).delete_pool_health_monitor(
            context, id, pool_id)
        LOG.debug(_("Delete health_monitor %(id)s of pool: %(pool_id)s"),
                  {"id": id, "pool_id": pool_id})

    def get_member(self, context, id, fields=None):
        res = super(LoadBalancerPlugin, self).get_member(
            context, id, fields)
        LOG.debug(_("Get member: %s"), id)
        return res

    def get_members(self, context, filters=None, fields=None):
        res = super(LoadBalancerPlugin, self).get_members(
            context, filters, fields)
        LOG.debug(_("Get members"))
        return res

    def create_member(self, context, member):
        m = super(LoadBalancerPlugin, self).create_member(context, member)
        self.update_status(context, loadbalancer_db.Member, m['id'],
                           constants.PENDING_CREATE)
        LOG.debug(_("Create member: %s"), m['id'])
        # TODO notify lbagent
        m_rt = self.get_member(context, m['id'])
        return m_rt

    def update_member(self, context, id, member):
        m_query = self.get_member(context, id, fields=["status"])
        if m_query['status'] in [
            constants.PENDING_DELETE, constants.ERROR]:
            raise loadbalancer.StateInvalid(id=id,
                                            state=m_query['status'])
        m = super(LoadBalancerPlugin, self).update_member(context, id, member)
        self.update_status(context, loadbalancer_db.Member, id,
                           constants.PENDING_UPDATE)
        LOG.debug(_("Update member: %s"), m['id'])
        # TODO notify lbagent
        m_rt = self.get_member(context, id)
        return m_rt

    def delete_member(self, context, id):
        self.update_status(context, loadbalancer_db.Member, id,
                           constants.PENDING_DELETE)
        LOG.debug(_("Delete member: %s"), id)
        # TODO notify lbagent
        super(LoadBalancerPlugin, self).delete_member(context, id)

    def get_health_monitor(self, context, id, fields=None):
        res = super(LoadBalancerPlugin, self).get_health_monitor(
            context, id, fields)
        LOG.debug(_("Get health_monitor: %s"), id)
        return res

    def get_health_monitors(self, context, filters=None, fields=None):
        res = super(LoadBalancerPlugin, self).get_health_monitors(
            context, filters, fields)
        LOG.debug(_("Get health_monitors"))
        return res

    def create_health_monitor(self, context, health_monitor):
        h = super(LoadBalancerPlugin, self).create_health_monitor(
            context, health_monitor)
        self.update_status(context, loadbalancer_db.HealthMonitor, h['id'],
                           constants.PENDING_CREATE)
        LOG.debug(_("Create health_monitor: %s"), h['id'])
        # TODO notify lbagent
        h_rt = self.get_health_monitor(context, h['id'])
        return h_rt

    def update_health_monitor(self, context, id, health_monitor):
        h_query = self.get_health_monitor(context, id, fields=["status"])
        if h_query['status'] in [
            constants.PENDING_DELETE, constants.ERROR]:
            raise loadbalancer.StateInvalid(id=id,
                                            state=h_query['status'])
        h = super(LoadBalancerPlugin, self).update_health_monitor(
            context, id, health_monitor)
        self.update_status(context, loadbalancer_db.HealthMonitor, id,
                           constants.PENDING_UPDATE)
        LOG.debug(_("Update health_monitor: %s"), h['id'])
        # TODO notify lbagent
        h_rt = self.get_health_monitor(context, id)
        return h_rt

    def delete_health_monitor(self, context, id):
        self.update_status(context, loadbalancer_db.HealthMonitor, id,
                           constants.PENDING_DELETE)
        LOG.debug(_("Delete health_monitor: %s"), id)
        super(LoadBalancerPlugin, self).delete_health_monitor(context, id)
