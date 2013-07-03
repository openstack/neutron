# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
# @author: Mark McClain, DreamHost

import uuid

from oslo.config import cfg

from neutron.common import exceptions as q_exc
from neutron.common import rpc as q_rpc
from neutron.db.loadbalancer import loadbalancer_db
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers import abstract_driver

LOG = logging.getLogger(__name__)

ACTIVE_PENDING = (
    constants.ACTIVE,
    constants.PENDING_CREATE,
    constants.PENDING_UPDATE
)

# topic name for this particular agent implementation
TOPIC_PROCESS_ON_HOST = 'q-lbaas-process-on-host'
TOPIC_LOADBALANCER_AGENT = 'lbaas_process_on_host_agent'


class LoadBalancerCallbacks(object):
    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])

    def get_ready_devices(self, context, host=None):
        with context.session.begin(subtransactions=True):
            qry = (context.session.query(loadbalancer_db.Pool.id).
                   join(loadbalancer_db.Vip))

            qry = qry.filter(loadbalancer_db.Vip.status.in_(ACTIVE_PENDING))
            qry = qry.filter(loadbalancer_db.Pool.status.in_(ACTIVE_PENDING))
            up = True  # makes pep8 and sqlalchemy happy
            qry = qry.filter(loadbalancer_db.Vip.admin_state_up == up)
            qry = qry.filter(loadbalancer_db.Pool.admin_state_up == up)
            return [id for id, in qry]

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
                    if hm.healthmonitor.status in ACTIVE_PENDING:
                        hm.healthmonitor.status = constants.ACTIVE

            if (pool.status != constants.ACTIVE
                or pool.vip.status != constants.ACTIVE):
                raise q_exc.Invalid(_('Expected active pool and vip'))

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
                self.plugin._make_health_monitor_dict(hm.healthmonitor)
                for hm in pool.monitors
                if hm.healthmonitor.status == constants.ACTIVE
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
        port['device_owner'] = 'neutron:' + constants.LOADBALANCER
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
        # TODO(markmcclain): add stats collection
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


class HaproxyOnHostPluginDriver(abstract_driver.LoadBalancerAbstractDriver):
    def __init__(self, plugin):
        self.agent_rpc = LoadBalancerAgentApi(
            TOPIC_LOADBALANCER_AGENT,
            cfg.CONF.host
        )
        self.callbacks = LoadBalancerCallbacks(plugin)

        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            TOPIC_PROCESS_ON_HOST,
            self.callbacks.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()
        self.plugin = plugin

    def create_vip(self, context, vip):
        self.agent_rpc.reload_pool(context, vip['pool_id'])

    def update_vip(self, context, old_vip, vip):
        if vip['status'] in ACTIVE_PENDING:
            self.agent_rpc.reload_pool(context, vip['pool_id'])
        else:
            self.agent_rpc.destroy_pool(context, vip['pool_id'])

    def delete_vip(self, context, vip):
        self.plugin._delete_db_vip(context, vip['id'])
        self.agent_rpc.destroy_pool(context, vip['pool_id'])

    def create_pool(self, context, pool):
        # don't notify here because a pool needs a vip to be useful
        pass

    def update_pool(self, context, old_pool, pool):
        if pool['status'] in ACTIVE_PENDING:
            if pool['vip_id'] is not None:
                self.agent_rpc.reload_pool(context, pool['id'])
        else:
            self.agent_rpc.destroy_pool(context, pool['id'])

    def delete_pool(self, context, pool):
        self.plugin._delete_db_pool(context, pool['id'])
        self.agent_rpc.destroy_pool(context, pool['id'])

    def create_member(self, context, member):
        self.agent_rpc.modify_pool(context, member['pool_id'])

    def update_member(self, context, old_member, member):
        # member may change pool id
        if member['pool_id'] != old_member['pool_id']:
            self.agent_rpc.modify_pool(context, old_member['pool_id'])
        self.agent_rpc.modify_pool(context, member['pool_id'])

    def delete_member(self, context, member):
        self.plugin._delete_db_member(context, member['id'])
        self.agent_rpc.modify_pool(context, member['pool_id'])

    def update_health_monitor(self, context, old_health_monitor,
                              health_monitor, pool_id):
        # monitors are unused here because agent will fetch what is necessary
        self.agent_rpc.modify_pool(context, pool_id)

    def delete_health_monitor(self, context, healthmon_id, pool_id):
        # healthmon_id is not used in this driver
        self.agent_rpc.modify_pool(context, pool_id)

    def create_pool_health_monitor(self, context, healthmon, pool_id):
        # healthmon is not used here
        self.agent_rpc.modify_pool(context, pool_id)

    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        self.plugin._delete_db_pool_health_monitor(
            context, health_monitor['id'], pool_id
        )

        # healthmon_id is not used here
        self.agent_rpc.modify_pool(context, pool_id)

    def create_health_monitor(self, context, health_monitor):
        pass

    def stats(self, context, pool_id):
        pass
