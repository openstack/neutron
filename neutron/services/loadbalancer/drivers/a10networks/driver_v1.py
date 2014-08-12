# Copyright 2014, Doug Wiegley (dougwig), A10 Networks
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

import a10_neutron_lbaas

from neutron.db import l3_db
from neutron.db.loadbalancer import loadbalancer_db as lb_db
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers import abstract_driver

VERSION = "1.0.0"
LOG = logging.getLogger(__name__)


# Most driver calls below are straight passthroughs to the A10 package
# 'a10_neutron_lbaas'.  Any function that has not been fully abstracted
# into the openstack driver/plugin interface is NOT passed through, to
# make it obvious which hidden interfaces/db calls that we rely on.

class ThunderDriver(abstract_driver.LoadBalancerAbstractDriver):

    def __init__(self, plugin):
        LOG.debug("A10Driver: init version=%s", VERSION)
        self.plugin = plugin

        # Map the string types to neutron classes/functions, in order to keep
        # from reaching into the bowels of Neutron from anywhere but this file.
        self.neutron_map = {
            'member': {
                'model': lb_db.Member,
                'delete_func': self.plugin._delete_db_member,
            },
            'pool': {
                'model': lb_db.Pool,
                'delete_func': self.plugin._delete_db_pool,
            },
            'vip': {
                'model': lb_db.Vip,
                'delete_func': self.plugin._delete_db_vip,
            },
        }

        LOG.debug("A10Driver: initializing, version=%s, lbaas_manager=%s",
                  VERSION, a10_neutron_lbaas.VERSION)

        self.a10 = a10_neutron_lbaas.A10OpenstackLBV1(self)

    # The following private helper methods are used by a10_neutron_lbaas,
    # and reflect the neutron interfaces required by that package.

    def _hm_binding_count(self, context, hm_id):
        return context.session.query(lb_db.PoolMonitorAssociation).filter_by(
            monitor_id=hm_id).join(lb_db.Pool).count()

    def _member_count(self, context, member):
        return context.session.query(lb_db.Member).filter_by(
            tenant_id=member['tenant_id'],
            address=member['address']).count()

    def _member_get(self, context, member_id):
        return self.plugin.get_member(context, member_id)

    def _member_get_ip(self, context, member, use_float=False):
        ip_address = member['address']
        if use_float:
            fip_qry = context.session.query(l3_db.FloatingIP)
            if (fip_qry.filter_by(fixed_ip_address=ip_address).count() > 0):
                float_address = fip_qry.filter_by(
                    fixed_ip_address=ip_address).first()
                ip_address = str(float_address.floating_ip_address)
        return ip_address

    def _pool_get_hm(self, context, hm_id):
        return self.plugin.get_health_monitor(context, hm_id)

    def _pool_get_tenant_id(self, context, pool_id):
        pool_qry = context.session.query(lb_db.Pool).filter_by(id=pool_id)
        z = pool_qry.first()
        if z:
            return z.tenant_id
        else:
            return ''

    def _pool_get_vip_id(self, context, pool_id):
        pool_qry = context.session.query(lb_db.Pool).filter_by(id=pool_id)
        z = pool_qry.first()
        if z:
            return z.vip_id
        else:
            return ''

    def _pool_total(self, context, tenant_id):
        return context.session.query(lb_db.Pool).filter_by(
            tenant_id=tenant_id).count()

    def _vip_get(self, context, vip_id):
        return self.plugin.get_vip(context, vip_id)

    def _active(self, context, model_type, model_id):
        self.plugin.update_status(context,
                                  self.neutron_map[model_type]['model'],
                                  model_id,
                                  constants.ACTIVE)

    def _failed(self, context, model_type, model_id):
        self.plugin.update_status(context,
                                  self.neutron_map[model_type]['model'],
                                  model_id,
                                  constants.ERROR)

    def _db_delete(self, context, model_type, model_id):
        self.neutron_map[model_type]['delete_func'](context, model_id)

    def _hm_active(self, context, hm_id, pool_id):
        self.plugin.update_pool_health_monitor(context, hm_id, pool_id,
                                               constants.ACTIVE)

    def _hm_failed(self, context, hm_id, pool_id):
        self.plugin.update_pool_health_monitor(context, hm_id, pool_id,
                                               constants.ERROR)

    def _hm_db_delete(self, context, hm_id, pool_id):
        self.plugin._delete_db_pool_health_monitor(context, hm_id, pool_id)

    # Pass-through driver

    def create_vip(self, context, vip):
        self.a10.vip.create(context, vip)

    def update_vip(self, context, old_vip, vip):
        self.a10.vip.update(context, old_vip, vip)

    def delete_vip(self, context, vip):
        self.a10.vip.delete(context, vip)

    def create_pool(self, context, pool):
        self.a10.pool.create(context, pool)

    def update_pool(self, context, old_pool, pool):
        self.a10.pool.update(context, old_pool, pool)

    def delete_pool(self, context, pool):
        self.a10.pool.delete(context, pool)

    def stats(self, context, pool_id):
        return self.a10.pool.stats(context, pool_id)

    def create_member(self, context, member):
        self.a10.member.create(context, member)

    def update_member(self, context, old_member, member):
        self.a10.member.update(context, old_member, member)

    def delete_member(self, context, member):
        self.a10.member.delete(context, member)

    def update_pool_health_monitor(self, context, old_hm, hm, pool_id):
        self.a10.hm.update(context, old_hm, hm, pool_id)

    def create_pool_health_monitor(self, context, hm, pool_id):
        self.a10.hm.create(context, hm, pool_id)

    def delete_pool_health_monitor(self, context, hm, pool_id):
        self.a10.hm.delete(context, hm, pool_id)
