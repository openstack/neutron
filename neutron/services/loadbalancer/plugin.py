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

from neutron.api.v2 import attributes as attrs
from neutron.common import exceptions as n_exc
from neutron import context
from neutron.db import api as qdbapi
from neutron.db.loadbalancer import loadbalancer_db as ldb
from neutron.db.loadbalancer import loadbalancer_dbv2 as ldbv2
from neutron.db import servicetype_db as st_db
from neutron.extensions import loadbalancer
from neutron.extensions import loadbalancerv2
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer import agent_scheduler
from neutron.services import provider_configuration as pconf
from neutron.services import service_base

LOG = logging.getLogger(__name__)


class LoadBalancerPlugin(ldb.LoadBalancerPluginDb,
                         agent_scheduler.LbaasAgentSchedulerDbMixin):
    """Implementation of the Neutron Loadbalancer Service Plugin.

    This class manages the workflow of LBaaS request/response.
    Most DB related works are implemented in class
    loadbalancer_db.LoadBalancerPluginDb.
    """
    supported_extension_aliases = ["lbaas",
                                   "lbaas_agent_scheduler",
                                   "service-type"]

    # lbaas agent notifiers to handle agent update operations;
    # can be updated by plugin drivers while loading;
    # will be extracted by neutron manager when loading service plugins;
    agent_notifiers = {}

    def __init__(self):
        """Initialization for the loadbalancer service plugin."""

        qdbapi.register_models()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        self._load_drivers()

    def _load_drivers(self):
        """Loads plugin-drivers specified in configuration."""
        self.drivers, self.default_provider = service_base.load_drivers(
            constants.LOADBALANCER, self)

        # we're at the point when extensions are not loaded yet
        # so prevent policy from being loaded
        ctx = context.get_admin_context(load_admin_roles=False)
        # stop service in case provider was removed, but resources were not
        self._check_orphan_pool_associations(ctx, self.drivers.keys())

    def _check_orphan_pool_associations(self, context, provider_names):
        """Checks remaining associations between pools and providers.

        If admin has not undeployed resources with provider that was deleted
        from configuration, neutron service is stopped. Admin must delete
        resources prior to removing providers from configuration.
        """
        pools = self.get_pools(context)
        lost_providers = set([pool['provider'] for pool in pools
                              if pool['provider'] not in provider_names])
        # resources are left without provider - stop the service
        if lost_providers:
            msg = _("Delete associated loadbalancer pools before "
                    "removing providers %s") % list(lost_providers)
            LOG.exception(msg)
            raise SystemExit(1)

    def _get_driver_for_provider(self, provider):
        if provider in self.drivers:
            return self.drivers[provider]
        # raise if not associated (should never be reached)
        raise n_exc.Invalid(_("Error retrieving driver for provider %s") %
                            provider)

    def _get_driver_for_pool(self, context, pool_id):
        pool = self.get_pool(context, pool_id)
        try:
            return self.drivers[pool['provider']]
        except KeyError:
            raise n_exc.Invalid(_("Error retrieving provider for pool %s") %
                                pool_id)

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return "Neutron LoadBalancer Service Plugin"

    def create_vip(self, context, vip):
        v = super(LoadBalancerPlugin, self).create_vip(context, vip)
        driver = self._get_driver_for_pool(context, v['pool_id'])
        driver.create_vip(context, v)
        return v

    def update_vip(self, context, id, vip):
        if 'status' not in vip['vip']:
            vip['vip']['status'] = constants.PENDING_UPDATE
        old_vip = self.get_vip(context, id)
        v = super(LoadBalancerPlugin, self).update_vip(context, id, vip)
        driver = self._get_driver_for_pool(context, v['pool_id'])
        driver.update_vip(context, old_vip, v)
        return v

    def _delete_db_vip(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_vip(context, id)

    def delete_vip(self, context, id):
        self.update_status(context, ldb.Vip,
                           id, constants.PENDING_DELETE)
        v = self.get_vip(context, id)
        driver = self._get_driver_for_pool(context, v['pool_id'])
        driver.delete_vip(context, v)

    def _get_provider_name(self, context, pool):
        if ('provider' in pool and
            pool['provider'] != attrs.ATTR_NOT_SPECIFIED):
            provider_name = pconf.normalize_provider_name(pool['provider'])
            self.validate_provider(provider_name)
            return provider_name
        else:
            if not self.default_provider:
                raise pconf.DefaultServiceProviderNotFound(
                    service_type=constants.LOADBALANCER)
            return self.default_provider

    def create_pool(self, context, pool):
        #This validation is because the new API version also has a resource
        #called pool and these attributes have to be optional in the old API
        #so they are not required attributes of the new.  Its complicated.
        if (pool['pool']['lb_method'] == attrs.ATTR_NOT_SPECIFIED):
            raise loadbalancerv2.RequiredAttributeNotSpecified(
                attr_name='lb_method')
        if (pool['pool']['subnet_id'] == attrs.ATTR_NOT_SPECIFIED):
            raise loadbalancerv2.RequiredAttributeNotSpecified(
                attr_name='subnet_id')

        provider_name = self._get_provider_name(context, pool['pool'])
        p = super(LoadBalancerPlugin, self).create_pool(context, pool)

        self.service_type_manager.add_resource_association(
            context,
            constants.LOADBALANCER,
            provider_name, p['id'])
        #need to add provider name to pool dict,
        #because provider was not known to db plugin at pool creation
        p['provider'] = provider_name
        driver = self.drivers[provider_name]
        try:
            driver.create_pool(context, p)
        except loadbalancer.NoEligibleBackend:
            # that should catch cases when backend of any kind
            # is not available (agent, appliance, etc)
            self.update_status(context, ldb.Pool,
                               p['id'], constants.ERROR,
                               "No eligible backend")
            raise loadbalancer.NoEligibleBackend(pool_id=p['id'])
        return p

    def update_pool(self, context, id, pool):
        if 'status' not in pool['pool']:
            pool['pool']['status'] = constants.PENDING_UPDATE
        old_pool = self.get_pool(context, id)
        p = super(LoadBalancerPlugin, self).update_pool(context, id, pool)
        driver = self._get_driver_for_provider(p['provider'])
        driver.update_pool(context, old_pool, p)
        return p

    def _delete_db_pool(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        # rely on uuid uniqueness:
        try:
            with context.session.begin(subtransactions=True):
                self.service_type_manager.del_resource_associations(
                    context, [id])
                super(LoadBalancerPlugin, self).delete_pool(context, id)
        except Exception:
            # that should not happen
            # if it's still a case - something goes wrong
            # log the error and mark the pool as ERROR
            LOG.error(_('Failed to delete pool %s, putting it in ERROR state'),
                      id)
            with excutils.save_and_reraise_exception():
                self.update_status(context, ldb.Pool,
                                   id, constants.ERROR)

    def delete_pool(self, context, id):
        # check for delete conditions and update the status
        # within a transaction to avoid a race
        with context.session.begin(subtransactions=True):
            self.update_status(context, ldb.Pool,
                               id, constants.PENDING_DELETE)
            self._ensure_pool_delete_conditions(context, id)
        p = self.get_pool(context, id)
        driver = self._get_driver_for_provider(p['provider'])
        driver.delete_pool(context, p)

    def create_member(self, context, member):
        m = super(LoadBalancerPlugin, self).create_member(context, member)
        driver = self._get_driver_for_pool(context, m['pool_id'])
        driver.create_member(context, m)
        return m

    def update_member(self, context, id, member):
        if 'status' not in member['member']:
            member['member']['status'] = constants.PENDING_UPDATE
        old_member = self.get_member(context, id)
        m = super(LoadBalancerPlugin, self).update_member(context, id, member)
        driver = self._get_driver_for_pool(context, m['pool_id'])
        driver.update_member(context, old_member, m)
        return m

    def _delete_db_member(self, context, id):
        # proxy the call until plugin inherits from DBPlugin
        super(LoadBalancerPlugin, self).delete_member(context, id)

    def delete_member(self, context, id):
        self.update_status(context, ldb.Member,
                           id, constants.PENDING_DELETE)
        m = self.get_member(context, id)
        driver = self._get_driver_for_pool(context, m['pool_id'])
        driver.delete_member(context, m)

    def _validate_hm_parameters(self, delay, timeout):
        if delay < timeout:
            raise loadbalancer.DelayOrTimeoutInvalid()

    def create_health_monitor(self, context, health_monitor):
        new_hm = health_monitor['health_monitor']
        self._validate_hm_parameters(new_hm['delay'], new_hm['timeout'])

        hm = super(LoadBalancerPlugin, self).create_health_monitor(
            context,
            health_monitor
        )
        return hm

    def update_health_monitor(self, context, id, health_monitor):
        new_hm = health_monitor['health_monitor']
        old_hm = self.get_health_monitor(context, id)
        delay = new_hm.get('delay', old_hm.get('delay'))
        timeout = new_hm.get('timeout', old_hm.get('timeout'))
        self._validate_hm_parameters(delay, timeout)

        hm = super(LoadBalancerPlugin, self).update_health_monitor(
            context,
            id,
            health_monitor
        )

        with context.session.begin(subtransactions=True):
            qry = context.session.query(
                ldb.PoolMonitorAssociation
            ).filter_by(monitor_id=hm['id']).join(ldb.Pool)
            for assoc in qry:
                driver = self._get_driver_for_pool(context, assoc['pool_id'])
                driver.update_pool_health_monitor(context, old_hm,
                                                  hm, assoc['pool_id'])
        return hm

    def _delete_db_pool_health_monitor(self, context, hm_id, pool_id):
        super(LoadBalancerPlugin, self).delete_pool_health_monitor(context,
                                                                   hm_id,
                                                                   pool_id)

    def _delete_db_health_monitor(self, context, id):
        super(LoadBalancerPlugin, self).delete_health_monitor(context, id)

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        retval = super(LoadBalancerPlugin, self).create_pool_health_monitor(
            context,
            health_monitor,
            pool_id
        )
        monitor_id = health_monitor['health_monitor']['id']
        hm = self.get_health_monitor(context, monitor_id)
        driver = self._get_driver_for_pool(context, pool_id)
        driver.create_pool_health_monitor(context, hm, pool_id)
        return retval

    def delete_pool_health_monitor(self, context, id, pool_id):
        self.update_pool_health_monitor(context, id, pool_id,
                                        constants.PENDING_DELETE)
        hm = self.get_health_monitor(context, id)
        driver = self._get_driver_for_pool(context, pool_id)
        driver.delete_pool_health_monitor(context, hm, pool_id)

    def stats(self, context, pool_id):
        driver = self._get_driver_for_pool(context, pool_id)
        stats_data = driver.stats(context, pool_id)
        # if we get something from the driver -
        # update the db and return the value from db
        # else - return what we have in db
        if stats_data:
            super(LoadBalancerPlugin, self).update_pool_stats(
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
        vip['members'] = [self.get_member(context, member_id)
                          for member_id in pool['members']]
        vip['health_monitors'] = [self.get_health_monitor(context, hm_id)
                                  for hm_id in pool['health_monitors']]
        return vip

    def validate_provider(self, provider):
        if provider not in self.drivers:
            raise pconf.ServiceProviderNotFound(
                provider=provider, service_type=constants.LOADBALANCER)


class LoadBalancerPluginv2(ldbv2.LoadBalancerPluginDbv2,
                           agent_scheduler.LbaasAgentSchedulerDbMixin):
    """Implementation of the Neutron Loadbalancer Service Plugin.

    This class manages the workflow of LBaaS request/response.
    Most DB related works are implemented in class
    loadbalancer_db.LoadBalancerPluginDb.
    """
    supported_extension_aliases = ["lbaasv2",
                                   "lbaas_agent_scheduler",
                                   "service-type"]

    # lbaas agent notifiers to handle agent update operations;
    # can be updated by plugin drivers while loading;
    # will be extracted by neutron manager when loading service plugins;
    agent_notifiers = {}

    def __init__(self):
        """Initialization for the loadbalancer service plugin."""

        qdbapi.register_models()
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        self._load_drivers()

    def _load_drivers(self):
        """Loads plugin-drivers specified in configuration."""
        self.drivers, self.default_provider = service_base.load_drivers(
            constants.LOADBALANCERv2, self)

        # we're at the point when extensions are not loaded yet
        # so prevent policy from being loaded
        ctx = context.get_admin_context(load_admin_roles=False)
        # stop service in case provider was removed, but resources were not
        self._check_orphan_pool_associations(ctx, self.drivers.keys())

    def _check_orphan_pool_associations(self, context, provider_names):
        """Checks remaining associations between pools and providers.

        If admin has not undeployed resources with provider that was deleted
        from configuration, neutron service is stopped. Admin must delete
        resources prior to removing providers from configuration.
        """
        loadbalancers = super(LoadBalancerPluginv2, self).get_loadbalancers(
            context)
        lost_providers = set(
            [loadbalancer.provider.provider_name
             for loadbalancer in loadbalancers
             if loadbalancer.provider.provider_name not in provider_names])
        # resources are left without provider - stop the service
        if lost_providers:
            msg = _("Delete associated load balancers before "
                    "removing providers %s") % list(lost_providers)
            LOG.exception(msg)
            raise SystemExit(1)

    def _get_driver_for_provider(self, provider):
        if provider in self.drivers:
            return self.drivers[provider]
        # raise if not associated (should never be reached)
        raise n_exc.Invalid(_("Error retrieving driver for provider %s") %
                            provider)

    def _get_driver_for_loadbalancer(self, context, loadbalancer_id):
        loadbalancer = super(LoadBalancerPluginv2, self).get_loadbalancer(
            context, loadbalancer_id)
        try:
            return self.drivers[loadbalancer.provider.provider_name]
        except KeyError:
            raise n_exc.Invalid(_("Error retrieving provider for load balancer"
                                  " %s") % loadbalancer_id)

    def _get_provider_name(self, entity):
        if ('provider' in entity and
                entity['provider'] != attrs.ATTR_NOT_SPECIFIED):
            provider_name = pconf.normalize_provider_name(entity['provider'])
            self.validate_provider(provider_name)
            return provider_name
        else:
            if not self.default_provider:
                raise pconf.DefaultServiceProviderNotFound(
                    service_type=constants.LOADBALANCER)
            return self.default_provider

    def _is_driver_new_style(self, driver):
        return not hasattr(driver, 'create_vip')

    def _call_driver_operation(self, context, driver_method, db_entity,
                               old_db_entity=None):
        try:
            if old_db_entity:
                driver_method(context, old_db_entity, db_entity)
            else:
                driver_method(context, db_entity)
        except Exception as driver_exception:
            self.update_status(context, db_entity.__class__, db_entity.id,
                               constants.ERROR)
            raise loadbalancerv2.DriverError(
                message=driver_exception.message)

    def get_plugin_type(self):
        return constants.LOADBALANCERv2

    def get_plugin_description(self):
        return "Neutron LoadBalancer Service Plugin v2"

    def create_loadbalancer(self, context, loadbalancer):
        loadbalancer = loadbalancer.get('loadbalancer')
        provider_name = self._get_provider_name(loadbalancer)
        lb_db = super(LoadBalancerPluginv2, self).create_loadbalancer(
            context, loadbalancer)
        self.service_type_manager.add_resource_association(
            context,
            constants.LOADBALANCERv2,
            provider_name, lb_db.id)
        driver = self.drivers[provider_name]
        if self._is_driver_new_style(driver):
            self._call_driver_operation(
                context, driver.load_balancer.create, lb_db)
        return lb_db.to_dict()

    def update_loadbalancer(self, context, id, loadbalancer):
        self.test_and_set_status(context, ldbv2.LoadBalancer, id,
                                 constants.PENDING_UPDATE)
        loadbalancer = loadbalancer.get('loadbalancer')
        old_lb = super(LoadBalancerPluginv2, self).get_loadbalancer(
            context, id)
        updated_lb = super(LoadBalancerPluginv2, self).update_loadbalancer(
            context, id, loadbalancer)
        driver = self._get_driver_for_provider(old_lb.provider.provider_name)
        if self._is_driver_new_style(driver):
            self._call_driver_operation(context,
                                        driver.load_balancer.update,
                                        updated_lb, old_db_entity=old_lb)
        return updated_lb.to_dict()

    def _delete_db_loadbalancer(self, context, id):
        super(LoadBalancerPluginv2, self).delete_loadbalancer(context, id)

    def delete_loadbalancer(self, context, id, body=None):
        self.test_and_set_status(context, ldbv2.LoadBalancer, id,
                                 constants.PENDING_DELETE)
        old_lb = super(LoadBalancerPluginv2, self).get_loadbalancer(
            context, id)
        driver = self._get_driver_for_provider(old_lb.provider.provider_name)
        if self._is_driver_new_style(driver):
            self._call_driver_operation(
                context, driver.load_balancer.delete, old_lb)

    def get_loadbalancer(self, context, id, fields=None):
        lb_db = super(LoadBalancerPluginv2, self).get_loadbalancer(
            context, id, fields)
        return self._fields(lb_db.to_dict(), fields)

    def get_loadbalancers(self, context, filters=None, fields=None):
        loadbalancers = super(LoadBalancerPluginv2, self).get_loadbalancers(
            context, filters=filters, fields=fields)
        lb_dicts = [self._fields(lb.to_dict(), fields) for lb in loadbalancers]
        return lb_dicts

    def create_listener(self, context, listener):
        listener = listener.get('listener')

        listener_db = super(LoadBalancerPluginv2, self).create_listener(
            context, listener)

        #if listener is associated with a load balancer then send to driver
        #if not then just set status to ACTIVE
        if listener_db.loadbalancer:
            driver = self._get_driver_for_loadbalancer(
                context, listener_db.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(
                    context, driver.listener.create, listener_db)
        else:
            self.update_status(context, ldbv2.Listener, listener_db.id,
                               constants.ACTIVE)

        return listener_db.to_dict()

    def update_listener(self, context, id, listener):
        self.test_and_set_status(context, ldbv2.Listener, id,
                                 constants.PENDING_UPDATE)
        listener = listener.get('listener')
        old_listener = super(LoadBalancerPluginv2, self).get_listener(
            context, id)

        listener_db = super(LoadBalancerPluginv2, self).update_listener(
            context, id, listener)

        #if listener is associated with a load balancer then send to driver
        #if not then update status to ACTIVE
        if listener_db.loadbalancer:
            driver = self._get_driver_for_loadbalancer(
                context, listener_db.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(
                    context,
                    driver.listener.update,
                    listener_db,
                    old_db_entity=old_listener)
        else:
            self.update_status(context, ldbv2.Listener, id, constants.ACTIVE)

        return listener_db.to_dict()

    def _delete_db_listener(self, context, id):
        super(LoadBalancerPluginv2, self).delete_listener(context, id)

    def delete_listener(self, context, id, body=None):
        self.test_and_set_status(context, ldbv2.Listener, id,
                                 constants.PENDING_DELETE)
        listener_db = super(LoadBalancerPluginv2, self).get_listener(
            context, id)

        #if listener is associated with a load balancer then send to driver
        #if not just delete from database
        if listener_db.loadbalancer:
            driver = self._get_driver_for_loadbalancer(
                context, listener_db.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(
                    context, driver.listener.delete, listener_db)
        else:
            super(LoadBalancerPluginv2, self).delete_listener(context, id)

    def get_listener(self, context, id, fields=None):
        listener_db = super(LoadBalancerPluginv2, self).get_listener(
            context, id, fields)
        return self._fields(listener_db.to_dict(), fields)

    def get_listeners(self, context, filters=None, fields=None):
        listeners = super(LoadBalancerPluginv2, self).get_listeners(
            context, filters=filters, fields=fields)
        listener_dicts = [self._fields(listener.to_dict(), fields)
                          for listener in listeners]
        return listener_dicts

    def create_pool(self, context, pool):
        pool = pool.get('pool')

        #This validation should only exist while the old version of the API
        #exists.
        if ('lb_algorithm' not in pool or
                pool['lb_algorithm'] == attrs.ATTR_NOT_SPECIFIED):
            raise loadbalancerv2.RequiredAttributeNotSpecified(
                attr_name='lb_algorithm')

        db_pool = super(LoadBalancerPluginv2, self).create_pool(
            context, pool)
        #no need to call driver since on create it cannot be linked to a load
        #balancer, but will still update status to ACTIVE
        self.update_status(context, ldbv2.PoolV2, db_pool.id,
                           constants.ACTIVE)
        return db_pool.to_dict()

    def update_pool(self, context, id, pool):
        self.test_and_set_status(context, ldbv2.PoolV2, id,
                                 constants.PENDING_UPDATE)
        pool = pool.get('pool')
        old_pool = super(LoadBalancerPluginv2, self).get_pool(
            context, id)
        updated_pool = super(LoadBalancerPluginv2, self).update_pool(
            context, id, pool)

        #if pool is associated with a load balancer then send to driver
        #if not then update status to ACTIVE
        if (updated_pool.listener and
                updated_pool.listener.loadbalancer):
            driver = self._get_driver_for_loadbalancer(
                context, updated_pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(context,
                                            driver.pool.update,
                                            updated_pool,
                                            old_db_entity=old_pool)
        else:
            self.update_status(context, ldbv2.PoolV2, id, constants.ACTIVE)

        return updated_pool.to_dict()

    def _delete_db_nodepool(self, context, id):
        super(LoadBalancerPluginv2, self).delete_pool(context, id)

    def delete_pool(self, context, id, body=None):
        self.test_and_set_status(context, ldbv2.PoolV2, id,
                                 constants.PENDING_DELETE)
        db_pool = super(LoadBalancerPluginv2, self).get_pool(context, id)

        #if pool is associated with a load balancer then send to driver,
        #if not just delete from the database
        if db_pool.listener and db_pool.listener.loadbalancer:
            driver = self._get_driver_for_loadbalancer(
                context, db_pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(context, driver.pool.delete,
                                            db_pool)
        else:
            super(LoadBalancerPluginv2, self).delete_pool(context, id)

    def get_pools(self, context, filters=None, fields=None):
        pools = super(LoadBalancerPluginv2, self).get_pools(
            context, filters=filters, fields=fields)
        pool_dict = [self._fields(pool.to_dict(), fields) for pool in pools]
        return pool_dict

    def get_pool(self, context, id, fields=None):
        pool_db = super(LoadBalancerPluginv2, self).get_pool(context,
                                                             id,
                                                             fields)
        return self._fields(pool_db.to_dict(members=True), fields)

    def create_pool_member(self, context, member, pool_id):
        #TODO(do we want to set the status of the pool as well?)
        member = member.get('member')
        member_db = super(LoadBalancerPluginv2, self).create_pool_member(
            context, member, pool_id)

        #if member's pool is associated with a load balancer then send to
        #driver, if not just update the status to ACTIVE
        if (member_db.pool and member_db.pool.listener and
                member_db.pool.listener.loadbalancer):
            driver = self._get_driver_for_loadbalancer(
                context, member_db.pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(context,
                                            driver.member.create,
                                            member_db)
        else:
            self.update_status(context, ldbv2.MemberV2, member_db.id,
                               constants.ACTIVE)

        return member_db.to_dict()

    def update_pool_member(self, context, id, member, pool_id):
        #TODO(do we want to set the status of the pool as well?)
        self.test_and_set_status(context, ldbv2.MemberV2, id,
                                 constants.PENDING_UPDATE)
        member = member.get('member')
        old_member = super(LoadBalancerPluginv2, self).get_pool_member(
            context, id, pool_id)
        updated_member = super(LoadBalancerPluginv2,
                               self).update_pool_member(context, id,
                                                        member,
                                                        pool_id)
        if (updated_member.pool and updated_member.pool.listener and
                updated_member.pool.listener.loadbalancer):
            driver = self._get_driver_for_loadbalancer(
                context, updated_member.pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(context,
                                            driver.member.update,
                                            updated_member,
                                            old_db_entity=old_member)
        else:
            self.update_status(context, ldbv2.MemberV2, id, constants.ACTIVE)

        return updated_member.to_dict()

    def delete_pool_member(self, context, id, pool_id, body=None):
        #TODO(do we want to set the status of the pool as well?)
        self.test_and_set_status(context, ldbv2.MemberV2, id,
                                 constants.PENDING_DELETE)
        db_member = super(LoadBalancerPluginv2, self).get_pool_member(
            context, id, pool_id)

        #if member's pool is associated with a load balancer then send to
        #driver, if not then just delete it from the database
        if db_member.pool.listener and db_member.pool.listener.loadbalancer:
            driver = self._get_driver_for_loadbalancer(
                context, db_member.pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(context,
                                            driver.member.delete_member,
                                            db_member)
        else:
            super(LoadBalancerPluginv2, self).delete_pool_member(
                context, id, pool_id)

    def get_pool_members(self, context, pool_id, filters=None, fields=None):
        members = super(LoadBalancerPluginv2, self).get_pool_members(
            context, pool_id, filters=filters, fields=fields)
        member_dict = [self._fields(member.to_dict(), fields)
                       for member in members]
        return member_dict

    def get_pool_member(self, context, id, pool_id, filters=None, fields=None):
        member = super(LoadBalancerPluginv2, self).get_pool_member(
            context, id, pool_id, filters=filters, fields=fields)
        return member.to_dict()

    def get_member(self, context, id, fields=None):
        pass

    def get_members(self, context, filters=None, fields=None):
        pass

    def create_healthmonitor(self, context, healthmonitor):
        healthmonitor = healthmonitor.get('healthmonitor')
        db_hm = super(LoadBalancerPluginv2, self).create_healthmonitor(
            context, healthmonitor)

        #no need to call driver since on create it cannot be linked to a load
        #balancer, but will still update status to ACTIVE
        self.update_status(context, ldbv2.HealthMonitorV2, db_hm.id,
                           constants.ACTIVE)
        return db_hm.to_dict()

    def update_healthmonitor(self, context, id, healthmonitor):
        self.test_and_set_status(context, ldbv2.HealthMonitorV2, id,
                                 constants.PENDING_UPDATE)
        old_hm = super(LoadBalancerPluginv2, self).get_healthmonitor(
            context, id)
        healthmonitor = healthmonitor.get('healthmonitor')
        updated_hm = super(LoadBalancerPluginv2, self).update_healthmonitor(
            context, id, healthmonitor)

        #if healthmonitor is associated with a load balancer then send to
        #driver if not then update status to ACTIVE
        if (updated_hm.pool and updated_hm.pool.listener and
                updated_hm.pool.listener.loadbalancer):
            driver = self._get_driver_for_loadbalancer(
                context, updated_hm.pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(context,
                                            driver.healthmonitor.update,
                                            updated_hm,
                                            old_db_entity=old_hm)
        else:
            self.update_status(context, ldbv2.HealthMonitorV2, id,
                               constants.ACTIVE)

        return updated_hm.to_dict()

    def _delete_db_healthmonitor(self, context, id):
        super(LoadBalancerPluginv2, self).delete_healthmonitor(context, id)

    def delete_healthmonitor(self, context, id, body=None):
        self.test_and_set_status(context, ldbv2.HealthMonitorV2, id,
                                 constants.PENDING_DELETE)
        db_hm = super(LoadBalancerPluginv2, self).get_healthmonitor(
            context, id)

        #if healthmonitor is associated with a load balancer then send to
        #driver, if not just delete from the database
        if (db_hm.pool and db_hm.pool.listener and
                db_hm.pool.listener.loadbalancer):
            driver = self._get_driver_for_loadbalancer(
                context, db_hm.pool.listener.loadbalancer_id)
            if self._is_driver_new_style(driver):
                self._call_driver_operation(
                    context, driver.healthmonitor.delete, db_hm)
        else:
            super(LoadBalancerPluginv2, self).delete_healthmonitor(context, id)

    def get_healthmonitor(self, context, id, fields=None):
        hm_db = super(LoadBalancerPluginv2, self).get_healthmonitor(
            context, id, fields)
        return self._fields(hm_db.to_dict(), fields)

    def get_healthmonitors(self, context, filters=None, fields=None):
        healthmonitors = super(LoadBalancerPluginv2, self).get_healthmonitors(
            context, filters=filters, fields=fields)
        hm_dicts = [self._fields(healthmonitor.to_dict(), fields)
                    for healthmonitor in healthmonitors]
        return hm_dicts

    def stats(self, context, loadbalancer_id):
        driver = self._get_driver_for_loadbalancer(context, loadbalancer_id)
        stats_data = None
        if self._is_driver_new_style(driver):
            stats_data = driver.load_balancer.stats(context, loadbalancer_id)
        # if we get something from the driver -
        # update the db and return the value from db
        # else - return what we have in db
        if stats_data:
            super(LoadBalancerPluginv2, self).update_loadbalancer_stats(
                context,
                loadbalancer_id,
                stats_data
            )
        db_stats = super(LoadBalancerPluginv2, self).stats(context,
                                                           loadbalancer_id)
        return {'stats': db_stats.to_dict()}
