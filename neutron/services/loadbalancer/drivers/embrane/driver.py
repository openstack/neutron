# Copyright 2014 Embrane, Inc.
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

from heleosapi import backend_operations as h_op
from heleosapi import constants as h_con
from heleosapi import info as h_info
from oslo.config import cfg

from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.db.loadbalancer import loadbalancer_db as ldb
from neutron.extensions import loadbalancer as lb_ext
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as pcon
from neutron.plugins.embrane.common import contexts as embrane_ctx
from neutron.plugins.embrane.common import exceptions as h_exc
from neutron.plugins.embrane.common import utils
from neutron.services.loadbalancer import constants as lbcon
from neutron.services.loadbalancer.drivers import abstract_driver
from neutron.services.loadbalancer.drivers.embrane.agent import dispatcher
from neutron.services.loadbalancer.drivers.embrane import config  # noqa
from neutron.services.loadbalancer.drivers.embrane import constants as econ
from neutron.services.loadbalancer.drivers.embrane import db as edb
from neutron.services.loadbalancer.drivers.embrane import poller

LOG = logging.getLogger(__name__)
conf = cfg.CONF.heleoslb
confh = {}

try:
    confh = cfg.CONF.heleos
except cfg.NoSuchOptError:
    pass


def get_conf(x):
    try:
        return conf.get(x) or confh.get(x)
    except cfg.NoSuchOptError:
        return


class EmbraneLbaas(abstract_driver.LoadBalancerAbstractDriver):
    def __init__(self, plugin):
        config_esm_mgmt = get_conf('esm_mgmt')
        config_admin_username = get_conf('admin_username')
        config_admin_password = get_conf('admin_password')
        config_lb_image_id = get_conf('lb_image')
        config_security_zones = {h_con.SzType.IB: get_conf('inband_id'),
                                 h_con.SzType.OOB: get_conf('oob_id'),
                                 h_con.SzType.MGMT: get_conf('mgmt_id'),
                                 h_con.SzType.DUMMY: get_conf('dummy_utif_id')}
        config_resource_pool = get_conf('resource_pool_id')
        self._heleos_api = h_op.BackendOperations(
            esm_mgmt=config_esm_mgmt,
            admin_username=config_admin_username,
            admin_password=config_admin_password,
            lb_image_id=config_lb_image_id,
            security_zones=config_security_zones,
            resource_pool=config_resource_pool)
        self._dispatcher = dispatcher.Dispatcher(
            self, get_conf("async_requests"))
        self.plugin = plugin
        poll_interval = conf.get('sync_interval')
        if poll_interval > 0:
            self._loop_call = poller.Poller(self)
            self._loop_call.start_polling(conf.get('sync_interval'))
        self._flavor = get_conf('lb_flavor')

    def _validate_vip(self, vip):
        if vip.get('connection_limit') and vip['connection_limit'] != -1:
            raise h_exc.UnsupportedException(
                err_msg=_('Connection limit is not supported by Embrane LB'))
        persistence = vip.get('session_persistence')
        if (persistence and persistence.get('type') ==
                lbcon.SESSION_PERSISTENCE_APP_COOKIE):
            p_type = vip['session_persistence']['type']
            raise h_exc.UnsupportedException(
                err_msg=_('Session persistence %s '
                          'not supported by Embrane LBaaS') % p_type)

    def _delete_vip(self, context, vip):
        with context.session.begin(subtransactions=True):
            self.plugin._delete_db_vip(context, vip['id'])
            return econ.DELETED

    def _delete_member(self, context, member):
        self.plugin._delete_db_member(context, member['id'])

    def _delete_pool_hm(self, context, health_monitor, pool_id):
        self.plugin._delete_db_pool_health_monitor(context,
                                                   health_monitor['id'],
                                                   pool_id)

    def _update_vip_graph_state(self, context, vip):
        self._heleos_api.update_vip_status(vip)
        self.plugin.update_status(context, ldb.Vip, vip['id'],
                                  vip['status'])
        if vip['status'] != pcon.ERROR:
            pool = self.plugin.get_pool(context, vip['pool_id'])
            pool_members = pool['members']
            # Manages possible manual changes and monitor actions
            self._heleos_api.update_pool_status(vip['id'], pool)
            self._heleos_api.update_members_status(vip['id'], pool['id'],
                                                   pool_members)
            self.plugin.update_status(context, ldb.Pool, pool['id'],
                                      pool['status'])
            for member in pool_members:
                self.plugin.update_status(context, ldb.Member,
                                          member['id'], member['status'])

    def _create_backend_port(self, context, db_pool):
        try:
            subnet = self.plugin._core_plugin.get_subnet(context,
                                                         db_pool["subnet_id"])
        except n_exc.SubnetNotFound:
            LOG.warning(_("Subnet assigned to pool %s doesn't exist, "
                          "backend port can't be created"), db_pool['id'])
            return

        fixed_ip = {'subnet_id': subnet['id'],
                    'fixed_ips': attributes.ATTR_NOT_SPECIFIED}

        port_data = {
            'tenant_id': db_pool['tenant_id'],
            'name': 'pool-' + db_pool['id'],
            'network_id': subnet['network_id'],
            'mac_address': attributes.ATTR_NOT_SPECIFIED,
            'admin_state_up': False,
            'device_id': '',
            'device_owner': '',
            'fixed_ips': [fixed_ip]
        }

        port = self.plugin._core_plugin.create_port(context,
                                                    {'port': port_data})
        return edb.add_pool_port(context, db_pool['id'], port['id'])

    def _retrieve_utif_info(self, context, neutron_port):
        network = self.plugin._core_plugin.get_network(
            context, neutron_port['network_id'])
        result = h_info.UtifInfo(network.get('provider:segmentation_id'),
                                 network['name'],
                                 network['id'],
                                 False,
                                 network['tenant_id'],
                                 neutron_port['id'],
                                 neutron_port['mac_address'],
                                 network.get('provider:network_type'))
        return result

    def create_vip(self, context, vip):
        self._validate_vip(vip)
        db_vip = self.plugin.populate_vip_graph(context, vip)
        vip_port = self.plugin._core_plugin._get_port(context,
                                                      db_vip['port_id'])
        vip_utif_info = self._retrieve_utif_info(context, vip_port)
        vip_ip_allocation_info = utils.retrieve_ip_allocation_info(
            context, vip_port)
        vip_ip_allocation_info.is_gw = True
        db_pool = pool_utif_info = pool_ip_allocation_info = None
        members = monitors = []
        if db_vip['pool_id']:
            db_pool = self.plugin.get_pool(
                context, db_vip['pool_id'])
            pool_port = edb.get_pool_port(context, db_pool["id"])
            if pool_port:
                db_port = self.plugin._core_plugin._get_port(
                    context, pool_port["port_id"])
                pool_utif_info = self._retrieve_utif_info(context, db_port)
                pool_ip_allocation_info = utils.retrieve_ip_allocation_info(
                    context, db_port)
            members = self.plugin.get_members(
                context, filters={'id': db_pool['members']})
            monitors = self.plugin.get_members(
                context, filters={'id': db_pool['health_monitors']})
        self._dispatcher.dispatch_lb(
            embrane_ctx.DispatcherContext(econ.Events.CREATE_VIP,
                                          db_vip, context, None),
            self._flavor, vip_utif_info, vip_ip_allocation_info,
            pool_utif_info, pool_ip_allocation_info, db_pool, members,
            monitors)

    def update_vip(self, context, old_vip, vip):
        new_pool = old_port_id = removed_ip = None
        new_pool_utif = new_pool_ip_allocation = None
        old_pool = {}
        members = monitors = []
        if old_vip['pool_id'] != vip['pool_id']:
            new_pool = self.plugin.get_pool(
                context, vip['pool_id'])
            members = self.plugin.get_members(
                context, filters={'id': new_pool['members']})
            monitors = self.plugin.get_members(
                context, filters={'id': new_pool['health_monitors']})
            new_pool_port = edb.get_pool_port(context, new_pool["id"])
            if new_pool_port:
                db_port = self.plugin._core_plugin._get_port(
                    context, new_pool_port["port_id"])
                new_pool_utif = self._retrieve_utif_info(context, db_port)
                new_pool_ip_allocation = utils.retrieve_ip_allocation_info(
                    context, db_port)
            old_pool = self.plugin.get_pool(
                context, old_vip['pool_id'])
            old_pool_port = edb.get_pool_port(context, old_pool["id"])
            if old_pool_port:
                old_port = self.plugin._core_plugin._get_port(
                    context, old_pool_port['port_id'])
                # remove that subnet ip
                removed_ip = old_port['fixed_ips'][0]['ip_address']
                old_port_id = old_port['id']

        self._dispatcher.dispatch_lb(
            embrane_ctx.DispatcherContext(econ.Events.UPDATE_VIP, vip,
                                          context, None),
            old_pool.get('id'), old_port_id, removed_ip, new_pool_utif,
            new_pool_ip_allocation, new_pool, members, monitors)

    def delete_vip(self, context, vip):
        db_vip = self.plugin.populate_vip_graph(context, vip)
        self._dispatcher.dispatch_lb(
            embrane_ctx.DispatcherContext(
                econ.Events.DELETE_VIP, db_vip, context, None))

    def create_pool(self, context, pool):
        if pool['subnet_id']:
            self._create_backend_port(context, pool)

    def update_pool(self, context, old_pool, pool):
        with context.session.begin(subtransactions=True):
            if old_pool['vip_id']:
                try:
                    db_vip = self.plugin._get_resource(
                        context, ldb.Vip, old_pool['vip_id'])
                except lb_ext.VipNotFound:
                    return
                monitors = self.plugin.get_members(
                    context, filters={'id': old_pool['health_monitors']})
                self._dispatcher.dispatch_lb(
                    embrane_ctx.DispatcherContext(econ.Events.UPDATE_POOL,
                                                  db_vip, context, None),
                    pool, monitors)

    def delete_pool(self, context, pool):
        edb.delete_pool_backend(context, pool['id'])
        self.plugin._delete_db_pool(context, pool['id'])

    def create_member(self, context, member):
        db_pool = self.plugin.get_pool(context, member['pool_id'])
        if db_pool['vip_id']:
            db_vip = self.plugin._get_resource(context, ldb.Vip,
                                               db_pool['vip_id'])
            self._dispatcher.dispatch_lb(
                embrane_ctx.DispatcherContext(
                    econ.Events.ADD_OR_UPDATE_MEMBER, db_vip, context, None),
                member, db_pool['protocol'])

    def update_member(self, context, old_member, member):
        db_pool = self.plugin.get_pool(context, member['pool_id'])
        if member['pool_id'] != old_member['pool_id']:
            old_pool = self.plugin.get_pool(context, old_member['pool_id'])
            if old_pool['vip_id']:
                db_vip = self.plugin._get_resource(context, ldb.Vip,
                                                   old_pool['vip_id'])
                self._dispatcher.dispatch_lb(
                    embrane_ctx.DispatcherContext(
                        econ.Events.REMOVE_MEMBER, db_vip, context, None),
                    old_member)
        if db_pool['vip_id']:
            db_vip = self.plugin._get_resource(
                context, ldb.Vip, db_pool['vip_id'])
            self._dispatcher.dispatch_lb(
                embrane_ctx.DispatcherContext(
                    econ.Events.ADD_OR_UPDATE_MEMBER, db_vip, context, None),
                member, db_pool['protocol'])

    def delete_member(self, context, member):
        db_pool = self.plugin.get_pool(context, member['pool_id'])
        if db_pool['vip_id']:
            db_vip = self.plugin._get_resource(context, ldb.Vip,
                                               db_pool['vip_id'])
            self._dispatcher.dispatch_lb(
                embrane_ctx.DispatcherContext(
                    econ.Events.DELETE_MEMBER, db_vip, context, None),
                member)
        else:
            self._delete_member(context, member)

    def stats(self, context, pool_id):
        return {'bytes_in': 0,
                'bytes_out': 0,
                'active_connections': 0,
                'total_connections': 0}

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        db_pool = self.plugin.get_pool(context, pool_id)
        # API call only if vip exists
        if db_pool['vip_id']:
            db_vip = self.plugin._get_resource(context, ldb.Vip,
                                               db_pool['vip_id'])
            self._dispatcher.dispatch_lb(
                embrane_ctx.DispatcherContext(
                    econ.Events.ADD_POOL_HM, db_vip, context, None),
                health_monitor, pool_id)

    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor, pool_id):
        db_pool = self.plugin.get_pool(context, pool_id)
        if db_pool['vip_id']:
            db_vip = self.plugin._get_resource(context, ldb.Vip,
                                               db_pool['vip_id'])
            self._dispatcher.dispatch_lb(
                embrane_ctx.DispatcherContext(
                    econ.Events.UPDATE_POOL_HM, db_vip, context, None),
                health_monitor, pool_id)

    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        db_pool = self.plugin.get_pool(context, pool_id)
        if db_pool['vip_id']:
            db_vip = self.plugin._get_resource(context, ldb.Vip,
                                               db_pool['vip_id'])
            self._dispatcher.dispatch_lb(
                embrane_ctx.DispatcherContext(
                    econ.Events.DELETE_POOL_HM, db_vip, context, None),
                health_monitor, pool_id)
        else:
            self._delete_pool_hm(context, health_monitor, pool_id)
