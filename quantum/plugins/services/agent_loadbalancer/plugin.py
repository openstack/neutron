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

import uuid

from oslo.config import cfg

from quantum.common import exceptions as q_exc
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import api as qdbapi
from quantum.db.loadbalancer import loadbalancer_db
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.common import constants

LOG = logging.getLogger(__name__)

ACTIVE_PENDING = (
    constants.ACTIVE,
    constants.PENDING_CREATE,
    constants.PENDING_UPDATE
)


class LoadBalancerCallbacks(object):
    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])

    def get_ready_devices(self, context, host=None):
        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                loadbalancer_db.Vip, loadbalancer_db.Pool
            )
            qry = qry.filter(loadbalancer_db.Vip.status.in_(ACTIVE_PENDING))
            qry = qry.filter(loadbalancer_db.Pool.status.in_(ACTIVE_PENDING))
            up = True  # makes pep8 and sqlalchemy happy
            qry = qry.filter(loadbalancer_db.Vip.admin_state_up == up)
            qry = qry.filter(loadbalancer_db.Pool.admin_state_up == up)
            return [p.id for v, p in qry.all()]

    def get_logical_device(self, context, pool_id=None, activate=True,
                           **kwargs):
        with context.session.begin(subtransactions=True):
            qry = context.session.query(loadbalancer_db.Pool)
            qry = qry.filter_by(id=pool_id)
            pool = qry.one()

            if activate:
                # set all resources to active
                if pool.status in ACTIVE_PENDING:
                    pool.status = constants.ACTIVE

                if pool.vip.status in ACTIVE_PENDING:
                    pool.vip.status = constants.ACTIVE

                for m in pool.members:
                    if m.status in ACTIVE_PENDING:
                        m.status = constants.ACTIVE

                for hm in pool.monitors:
                    if hm.monitor.status in ACTIVE_PENDING:
                        hm.monitor.status = constants.ACTIVE

            if (pool.status != constants.ACTIVE
                or pool.vip.status != constants.ACTIVE):
                raise Exception(_('Expected active pool and vip'))

            retval = {}
            retval['pool'] = self.plugin._make_pool_dict(pool)
            retval['vip'] = self.plugin._make_vip_dict(pool.vip)
            retval['vip']['port'] = (
                self.plugin._core_plugin._make_port_dict(pool.vip.port)
            )
            for fixed_ip in retval['vip']['port']['fixed_ips']:
                fixed_ip['subnet'] = (
                    self.plugin._core_plugin.get_subnet(
                        context,
                        fixed_ip['subnet_id']
                    )
                )
            retval['members'] = [
                self.plugin._make_member_dict(m)
                for m in pool.members if m.status == constants.ACTIVE
            ]
            retval['healthmonitors'] = [
                self.plugin._make_health_monitor_dict(hm.monitor)
                for hm in pool.monitors
                if hm.monitor.status == constants.ACTIVE
            ]

            return retval

    def pool_destroyed(self, context, pool_id=None, host=None):
        """Agent confirmation hook that a pool has been destroyed.

           This method exists for subclasses to change the deletion
           behavior.
        """
        pass

    def plug_vip_port(self, context, port_id=None, host=None):
        if not port_id:
            return

        try:
            port = self.plugin._core_plugin.get_port(
                context,
                port_id
            )
        except q_exc.PortNotFound:
            msg = _('Unable to find port %s to plug.')
            LOG.debug(msg, port_id)
            return

        port['admin_state_up'] = True
        port['device_owner'] = 'quantum:' + constants.LOADBALANCER
        port['device_id'] = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(host)))

        self.plugin._core_plugin.update_port(
            context,
            port_id,
            {'port': port}
        )

    def unplug_vip_port(self, context, port_id=None, host=None):
        if not port_id:
            return

        try:
            port = self.plugin._core_plugin.get_port(
                context,
                port_id
            )
        except q_exc.PortNotFound:
            msg = _('Unable to find port %s to unplug.  This can occur when '
                    'the Vip has been deleted first.')
            LOG.debug(msg, port_id)
            return

        port['admin_state_up'] = False
        port['device_owner'] = ''
        port['device_id'] = ''

        try:
            self.plugin._core_plugin.update_port(
                context,
                port_id,
                {'port': port}
            )

        except q_exc.PortNotFound:
            msg = _('Unable to find port %s to unplug.  This can occur when '
                    'the Vip has been deleted first.')
            LOG.debug(msg, port_id)

    def update_pool_stats(self, context, pool_id=None, stats=None, host=None):
        # TODO (markmcclain): add stats collection
        pass


class LoadBalancerAgentApi(proxy.RpcProxy):
    """Plugin side of plugin to agent RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(LoadBalancerAgentApi, self).__init__(topic, self.API_VERSION)
        self.host = host

    def reload_pool(self, context, pool_id):
        return self.cast(
            context,
            self.make_msg('reload_pool', pool_id=pool_id, host=self.host),
            topic=self.topic
        )

    def destroy_pool(self, context, pool_id):
        return self.cast(
            context,
            self.make_msg('destroy_pool', pool_id=pool_id, host=self.host),
            topic=self.topic
        )

    def modify_pool(self, context, pool_id):
        return self.cast(
            context,
            self.make_msg('modify_pool', pool_id=pool_id, host=self.host),
            topic=self.topic
        )


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
        qdbapi.register_models()

        self.callbacks = LoadBalancerCallbacks(self)

        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.LOADBALANCER_PLUGIN,
            self.callbacks.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()

        self.agent_rpc = LoadBalancerAgentApi(
            topics.LOADBALANCER_AGENT,
            cfg.CONF.host
        )

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return "Quantum LoadBalancer Service Plugin"

    def create_vip(self, context, vip):
        vip['vip']['status'] = constants.PENDING_CREATE
        v = super(LoadBalancerPlugin, self).create_vip(context, vip)
        self.agent_rpc.reload_pool(context, v['pool_id'])
        return v

    def update_vip(self, context, id, vip):
        if 'status' not in vip['vip']:
            vip['vip']['status'] = constants.PENDING_UPDATE
        v = super(LoadBalancerPlugin, self).update_vip(context, id, vip)
        if v['status'] in ACTIVE_PENDING:
            self.agent_rpc.reload_pool(context, v['pool_id'])
        else:
            self.agent_rpc.destroy_pool(context, v['pool_id'])
        return v

    def delete_vip(self, context, id):
        vip = self.get_vip(context, id)
        super(LoadBalancerPlugin, self).delete_vip(context, id)
        self.agent_rpc.destroy_pool(context, vip['pool_id'])

    def create_pool(self, context, pool):
        p = super(LoadBalancerPlugin, self).create_pool(context, pool)
        # don't notify here because a pool needs a vip to be useful
        return p

    def update_pool(self, context, id, pool):
        if 'status' not in pool['pool']:
            pool['pool']['status'] = constants.PENDING_UPDATE
        p = super(LoadBalancerPlugin, self).update_pool(context, id, pool)
        if p['status'] in ACTIVE_PENDING:
            self.agent_rpc.reload_pool(context, p['id'])
        else:
            self.agent_rpc.destroy_pool(context, p['id'])
        return p

    def delete_pool(self, context, id):
        super(LoadBalancerPlugin, self).delete_pool(context, id)
        self.agent_rpc.destroy_pool(context, id)

    def create_member(self, context, member):
        m = super(LoadBalancerPlugin, self).create_member(context, member)
        self.agent_rpc.modify_pool(context, m['pool_id'])
        return m

    def update_member(self, context, id, member):
        if 'status' not in member['member']:
            member['member']['status'] = constants.PENDING_UPDATE
        m = super(LoadBalancerPlugin, self).update_member(context, id, member)
        self.agent_rpc.modify_pool(context, m['pool_id'])
        return m

    def delete_member(self, context, id):
        m = self.get_member(context, id)
        super(LoadBalancerPlugin, self).delete_member(context, id)
        self.agent_rpc.modify_pool(context, m['pool_id'])

    def update_health_monitor(self, context, id, health_monitor):
        if 'status' not in health_monitor['health_monitor']:
            health_monitor['health_monitor']['status'] = (
                constants.PENDING_UPDATE
            )
        hm = super(LoadBalancerPlugin, self).update_health_monitor(
            context,
            id,
            health_monitor
        )

        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                loadbalancer_db.PoolMonitorAssociation
            )
            qry = qry.filter_by(monitor_id=hm['id'])

            for assoc in qry.all():
                self.agent_rpc.modify_pool(context, assoc['pool_id'])
        return hm

    def delete_health_monitor(self, context, id):
        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                loadbalancer_db.PoolMonitorAssociation
            )
            qry = qry.filter_by(monitor_id=id)

            pool_ids = [a['pool_id'] for a in qry.all()]
            super(LoadBalancerPlugin, self).delete_health_monitor(context, id)
        for pid in pool_ids:
            self.agent_rpc.modify_pool(context, pid)

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        retval = super(LoadBalancerPlugin, self).create_pool_health_monitor(
            context,
            health_monitor,
            pool_id
        )
        self.agent_rpc.modify_pool(context, pool_id)

        return retval
