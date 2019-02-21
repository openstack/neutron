# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

import functools

import netaddr
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import l3_ext_ha_mode as l3_ext_ha_apidef
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as providernet
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import priority_group
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.exceptions import l3_ext_ha_mode as l3ha_exc
from neutron_lib.objects import exceptions as obj_base
from neutron_lib.plugins import utils as p_utils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils
import six
import sqlalchemy as sa
from sqlalchemy import exc as sql_exc
from sqlalchemy import orm

from neutron._i18n import _
from neutron.common import constants as n_const
from neutron.common import utils as n_utils
from neutron.conf.db import l3_hamode_db
from neutron.db import _utils as db_utils
from neutron.db.availability_zone import router as router_az_db
from neutron.db import l3_dvr_db
from neutron.objects import base
from neutron.objects import l3_hamode
from neutron.objects import router as l3_obj


VR_ID_RANGE = set(range(1, 255))
MAX_ALLOCATION_TRIES = 10
UNLIMITED_AGENTS_PER_ROUTER = 0

LOG = logging.getLogger(__name__)

l3_hamode_db.register_db_l3_hamode_opts()


@registry.has_registry_receivers
class L3_HA_NAT_db_mixin(l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                         router_az_db.RouterAvailabilityZoneMixin):
    """Mixin class to add high availability capability to routers."""

    def _verify_configuration(self):
        self.ha_cidr = cfg.CONF.l3_ha_net_cidr
        try:
            net = netaddr.IPNetwork(self.ha_cidr)
        except netaddr.AddrFormatError:
            raise l3ha_exc.HANetworkCIDRNotValid(cidr=self.ha_cidr)
        if ('/' not in self.ha_cidr or net.network != net.ip):
            raise l3ha_exc.HANetworkCIDRNotValid(cidr=self.ha_cidr)

        self._check_num_agents_per_router()

    def _check_num_agents_per_router(self):
        max_agents = cfg.CONF.max_l3_agents_per_router

        if max_agents != UNLIMITED_AGENTS_PER_ROUTER and max_agents < 1:
            raise l3ha_exc.HAMaximumAgentsNumberNotValid(max_agents=max_agents)

    def __new__(cls, *args, **kwargs):
        inst = super(L3_HA_NAT_db_mixin, cls).__new__(cls, *args, **kwargs)
        inst._verify_configuration()
        return inst

    def get_ha_network(self, context, tenant_id):
        pager = base.Pager(limit=1)
        results = l3_hamode.L3HARouterNetwork.get_objects(
            context, _pager=pager, project_id=tenant_id)
        return results.pop() if results else None

    def _get_allocated_vr_id(self, context, network_id):
        vr_id_objs = l3_hamode.L3HARouterVRIdAllocation.get_objects(
            context, network_id=network_id)

        allocated_vr_ids = set(a.vr_id for a in vr_id_objs) - set([0])
        return allocated_vr_ids

    @db_api.retry_if_session_inactive()
    def _ensure_vr_id(self, context, router_db, ha_network):
        router_id = router_db.id
        network_id = ha_network.network_id

        # TODO(kevinbenton): let decorator handle duplicate retry
        # like in review.openstack.org/#/c/367179/1/neutron/db/l3_hamode_db.py
        for count in range(MAX_ALLOCATION_TRIES):
            try:
                # NOTE(kevinbenton): we disallow subtransactions because the
                # retry logic will bust any parent transactions
                with context.session.begin():
                    if router_db.extra_attributes.ha_vr_id:
                        LOG.debug(
                            "Router %(router_id)s has already been "
                            "allocated a ha_vr_id %(ha_vr_id)d!",
                            {'router_id': router_id,
                             'ha_vr_id': router_db.extra_attributes.ha_vr_id})
                        return

                    old_router = self._make_router_dict(router_db)
                    allocated_vr_ids = self._get_allocated_vr_id(context,
                                                                 network_id)
                    available_vr_ids = VR_ID_RANGE - allocated_vr_ids

                    if not available_vr_ids:
                        raise l3ha_exc.NoVRIDAvailable(router_id=router_id)

                    allocation = l3_hamode.L3HARouterVRIdAllocation(
                        context, network_id=network_id,
                        vr_id=available_vr_ids.pop())
                    allocation.create()

                    router_db.extra_attributes.ha_vr_id = allocation.vr_id
                    LOG.debug(
                        "Router %(router_id)s has been allocated a ha_vr_id "
                        "%(ha_vr_id)d.",
                        {'router_id': router_id, 'ha_vr_id': allocation.vr_id})
                    router_body = {l3_apidef.ROUTER:
                                   {l3_ext_ha_apidef.HA_INFO: True,
                                    'ha_vr_id': allocation.vr_id}}
                    registry.publish(resources.ROUTER, events.PRECOMMIT_UPDATE,
                                     self, payload=events.DBEventPayload(
                                         context, request_body=router_body,
                                         states=(old_router,),
                                         resource_id=router_id,
                                         desired_state=router_db))

                    return allocation.vr_id

            except obj_base.NeutronDbObjectDuplicateEntry:
                LOG.info("Attempt %(count)s to allocate a VRID in the "
                         "network %(network)s for the router %(router)s",
                         {'count': count, 'network': network_id,
                          'router': router_id})

        raise l3ha_exc.MaxVRIDAllocationTriesReached(
            network_id=network_id, router_id=router_id,
            max_tries=MAX_ALLOCATION_TRIES)

    @db_api.retry_if_session_inactive()
    def _delete_vr_id_allocation(self, context, ha_network, vr_id):
        l3_hamode.L3HARouterVRIdAllocation.delete_objects(
            context, network_id=ha_network.network_id, vr_id=vr_id)

    def _create_ha_subnet(self, context, network_id, tenant_id):
        args = {'network_id': network_id,
                'tenant_id': '',
                'name': n_const.HA_SUBNET_NAME % tenant_id,
                'ip_version': 4,
                'cidr': cfg.CONF.l3_ha_net_cidr,
                'enable_dhcp': False,
                'gateway_ip': None}
        return p_utils.create_subnet(self._core_plugin, context,
                                     {'subnet': args})

    def _create_ha_network_tenant_binding(self, context, tenant_id,
                                          network_id):
        ha_network = l3_hamode.L3HARouterNetwork(
            context, project_id=tenant_id, network_id=network_id)
        ha_network.create()
        # we need to check if someone else just inserted at exactly the
        # same time as us because there is no constrain in L3HARouterNetwork
        # that prevents multiple networks per tenant
        if l3_hamode.L3HARouterNetwork.count(
                context, project_id=tenant_id) > 1:
            # we need to throw an error so our network is deleted
            # and the process is started over where the existing
            # network will be selected.
            raise db_exc.DBDuplicateEntry(columns=['tenant_id'])
        return ha_network

    def _add_ha_network_settings(self, network):
        if cfg.CONF.l3_ha_network_type:
            network[providernet.NETWORK_TYPE] = cfg.CONF.l3_ha_network_type

        if cfg.CONF.l3_ha_network_physical_name:
            network[providernet.PHYSICAL_NETWORK] = (
                cfg.CONF.l3_ha_network_physical_name)

    def _create_ha_network(self, context, tenant_id):
        admin_ctx = context.elevated()

        args = {'network':
                {'name': n_const.HA_NETWORK_NAME % tenant_id,
                 'tenant_id': '',
                 'shared': False,
                 'admin_state_up': True}}
        self._add_ha_network_settings(args['network'])
        creation = functools.partial(p_utils.create_network,
                                     self._core_plugin, admin_ctx, args)
        content = functools.partial(self._create_ha_network_tenant_binding,
                                    admin_ctx, tenant_id)
        deletion = functools.partial(self._core_plugin.delete_network,
                                     admin_ctx)

        network, ha_network = db_utils.safe_creation(
            context, creation, deletion, content, transaction=False)
        try:
            self._create_ha_subnet(admin_ctx, network['id'], tenant_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._core_plugin.delete_network(admin_ctx, network['id'])

        return ha_network

    def get_number_of_agents_for_scheduling(self, context):
        """Return number of agents on which the router will be scheduled."""

        num_agents = len(
            self.get_l3_agents(
                context, active=True,
                filters={'agent_modes': [constants.L3_AGENT_MODE_LEGACY,
                                         constants.L3_AGENT_MODE_DVR_SNAT]}))
        max_agents = cfg.CONF.max_l3_agents_per_router
        if max_agents:
            if max_agents > num_agents:
                LOG.info("Number of active agents lower than "
                         "max_l3_agents_per_router. L3 agents "
                         "available: %s", num_agents)
            else:
                num_agents = max_agents

        return num_agents

    @db_api.retry_if_session_inactive()
    def _create_ha_port_binding(self, context, router_id, port_id):
        try:
            with context.session.begin():
                l3_obj.RouterPort(
                    context,
                    port_id=port_id,
                    router_id=router_id,
                    port_type=constants.DEVICE_OWNER_ROUTER_HA_INTF).create()
                portbinding = l3_hamode.L3HARouterAgentPortBinding(
                    context, port_id=port_id, router_id=router_id)
                portbinding.create()

            return portbinding
        except db_exc.DBReferenceError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if isinstance(e.inner_exception, sql_exc.IntegrityError):
                    ctxt.reraise = False
                    LOG.debug(
                        'Failed to create HA router agent PortBinding, '
                        'Router %s has already been removed '
                        'by concurrent operation', router_id)
                    raise l3_exc.RouterNotFound(router_id=router_id)

    def add_ha_port(self, context, router_id, network_id, tenant_id):
        # NOTE(kevinbenton): we have to block any ongoing transactions because
        # our exception handling will try to delete the port using the normal
        # core plugin API. If this function is called inside of a transaction
        # the exception will mangle the state, cause the delete call to fail,
        # and end up relying on the DB rollback to remove the port instead of
        # proper delete_port call.
        if context.session.is_active:
            raise RuntimeError(_('add_ha_port cannot be called inside of a '
                                 'transaction.'))
        args = {'tenant_id': '',
                'network_id': network_id,
                'admin_state_up': True,
                'device_id': router_id,
                'device_owner': constants.DEVICE_OWNER_ROUTER_HA_INTF,
                'name': n_const.HA_PORT_NAME % tenant_id}
        creation = functools.partial(p_utils.create_port, self._core_plugin,
                                     context, {'port': args})
        content = functools.partial(self._create_ha_port_binding, context,
                                    router_id)
        deletion = functools.partial(self._core_plugin.delete_port, context,
                                     l3_port_check=False)
        port, binding = db_utils.safe_creation(context, creation,
                                               deletion, content,
                                               transaction=False)
        # _create_ha_port_binding returns the binding object now and
        # to populate agent relation db_obj is used.
        return binding.db_obj

    def _delete_ha_interfaces(self, context, router_id):
        admin_ctx = context.elevated()
        device_filter = {'device_id': [router_id],
                         'device_owner':
                         [constants.DEVICE_OWNER_ROUTER_HA_INTF]}
        ports = self._core_plugin.get_ports(admin_ctx, filters=device_filter)

        for port in ports:
            self._core_plugin.delete_port(admin_ctx, port['id'],
                                          l3_port_check=False)

    def delete_ha_interfaces_on_host(self, context, router_id, host):
        admin_ctx = context.elevated()
        port_ids = (binding.port_id for binding
                    in self.get_ha_router_port_bindings(admin_ctx,
                                                        [router_id], host))
        for port_id in port_ids:
            self._core_plugin.delete_port(admin_ctx, port_id,
                                          l3_port_check=False)

    def _notify_router_updated(self, context, router_id):
        self.l3_rpc_notifier.routers_updated(
            context, [router_id], shuffle_agents=True)

    @classmethod
    def _is_ha(cls, router):
        ha = router.get('ha')
        if not validators.is_attr_set(ha):
            ha = cfg.CONF.l3_ha
        return ha

    def _get_device_owner(self, context, router=None):
        """Get device_owner for the specified router."""
        router_is_uuid = isinstance(router, six.string_types)
        if router_is_uuid:
            router = self._get_router(context, router)
        if (is_ha_router(router) and not
                l3_dvr_db.is_distributed_router(router)):
            return constants.DEVICE_OWNER_HA_REPLICATED_INT
        return super(L3_HA_NAT_db_mixin,
                     self)._get_device_owner(context, router)

    @n_utils.transaction_guard
    def _ensure_vr_id_and_network(self, context, router_db):
        """Attach vr_id to router while tolerating network deletes."""
        creator = functools.partial(self._ensure_vr_id,
                                    context, router_db)
        dep_getter = functools.partial(self.get_ha_network,
                                       context, router_db.tenant_id)
        dep_creator = functools.partial(self._create_ha_network,
                                        context, router_db.tenant_id)
        dep_deleter = functools.partial(self._delete_ha_network, context)
        dep_id_attr = 'network_id'
        return n_utils.create_object_with_dependency(
            creator, dep_getter, dep_creator, dep_id_attr, dep_deleter)[1]

    @registry.receives(resources.ROUTER, [events.BEFORE_CREATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    @db_api.retry_if_session_inactive()
    def _before_router_create(self, resource, event, trigger,
                              context, router, **kwargs):
        """Event handler to create HA resources before router creation."""
        if not self._is_ha(router):
            return
        # ensure the HA network exists before we start router creation so
        # we can provide meaningful errors back to the user if no network
        # can be allocated
        if not self.get_ha_network(context, router['tenant_id']):
            self._create_ha_network(context, router['tenant_id'])

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _precommit_router_create(self, resource, event, trigger, context,
                                 router, router_db, **kwargs):
        """Event handler to set ha flag and status on creation."""
        is_ha = self._is_ha(router)
        router['ha'] = is_ha
        self.set_extra_attr_value(context, router_db, 'ha', is_ha)
        if not is_ha:
            return
        # This will throw an exception if there aren't enough agents to
        # handle this HA router
        self.get_number_of_agents_for_scheduling(context)
        ha_net = self.get_ha_network(context, router['tenant_id'])
        if not ha_net:
            # net was deleted, throw a retry to start over to create another
            raise db_exc.RetryRequest(
                l3ha_exc.HANetworkConcurrentDeletion(
                        tenant_id=router['tenant_id']))

    @registry.receives(resources.ROUTER, [events.AFTER_CREATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _after_router_create(self, resource, event, trigger, context,
                             router_id, router, router_db, **kwargs):
        if not router['ha']:
            return
        try:
            self.schedule_router(context, router_id)
            router['ha_vr_id'] = router_db.extra_attributes.ha_vr_id
            self._notify_router_updated(context, router_id)
        except Exception as e:
            with excutils.save_and_reraise_exception() as ctx:
                if isinstance(e, l3ha_exc.NoVRIDAvailable):
                    ctx.reraise = False
                    LOG.warning("No more VRIDs for router: %s", e)
                else:
                    LOG.exception("Failed to schedule HA router %s.",
                                  router_id)
                router['status'] = self._update_router_db(
                    context, router_id,
                    {'status': constants.ERROR})['status']

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_UPDATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _validate_migration(self, resource, event, trigger, payload=None):
        """Event handler on precommit update to validate migration."""

        original_ha_state = payload.states[0]['ha']
        requested_ha_state = payload.request_body.get('ha')

        ha_changed = (requested_ha_state is not None and
                      requested_ha_state != original_ha_state)
        if not ha_changed:
            return

        if payload.desired_state.admin_state_up:
            msg = _('Cannot change HA attribute of active routers. Please '
                    'set router admin_state_up to False prior to upgrade')
            raise n_exc.BadRequest(resource='router', msg=msg)

        if requested_ha_state:
            # This will throw HANotEnoughAvailableAgents if there aren't
            # enough l3 agents to handle this router.
            self.get_number_of_agents_for_scheduling(payload.context)
            old_owner = constants.DEVICE_OWNER_ROUTER_INTF
            new_owner = constants.DEVICE_OWNER_HA_REPLICATED_INT
        else:
            old_owner = constants.DEVICE_OWNER_HA_REPLICATED_INT
            new_owner = constants.DEVICE_OWNER_ROUTER_INTF

            ha_network = self.get_ha_network(payload.context,
                                             payload.desired_state.tenant_id)
            self._delete_vr_id_allocation(
                payload.context, ha_network,
                payload.desired_state.extra_attributes.ha_vr_id)
            payload.desired_state.extra_attributes.ha_vr_id = None
        if (payload.request_body.get('distributed') or
                payload.states[0]['distributed']):
            self.set_extra_attr_value(payload.context, payload.desired_state,
                                      'ha', requested_ha_state)
            return
        self._migrate_router_ports(
             payload.context, payload.desired_state,
             old_owner=old_owner, new_owner=new_owner)
        self.set_extra_attr_value(
            payload.context, payload.desired_state, 'ha', requested_ha_state)

    @registry.receives(resources.ROUTER, [events.AFTER_UPDATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _reconfigure_ha_resources(self, resource, event, trigger, context,
                                  router_id, old_router, router, router_db,
                                  **kwargs):
        """Event handler to react to changes after HA flag has been updated."""
        ha_changed = old_router['ha'] != router['ha']
        if not ha_changed:
            return
        requested_ha_state = router['ha']
        # The HA attribute has changed. First unbind the router from agents
        # to force a proper re-scheduling to agents.
        # TODO(jschwarz): This will have to be more selective to get HA + DVR
        # working (Only unbind from dvr_snat nodes).
        self._unbind_ha_router(context, router_id)

        if not requested_ha_state:
            self._delete_ha_interfaces(context, router_db.id)
            # always attempt to cleanup the network as the router is
            # deleted. the core plugin will stop us if its in use
            ha_network = self.get_ha_network(context,
                                             router_db.tenant_id)
            if ha_network:
                self.safe_delete_ha_network(context, ha_network,
                                            router_db.tenant_id)

        self.schedule_router(context, router_id)
        self._notify_router_updated(context, router_db.id)

    def _delete_ha_network(self, context, net):
        admin_ctx = context.elevated()
        self._core_plugin.delete_network(admin_ctx, net.network_id)

    def safe_delete_ha_network(self, context, ha_network, tenant_id):
        try:
            # reference the attr inside the try block before we attempt
            # to delete the network and potentially invalidate the
            # relationship
            net_id = ha_network.network_id
            self._delete_ha_network(context, ha_network)
        except (n_exc.NetworkNotFound,
                orm.exc.ObjectDeletedError):
            LOG.debug(
                "HA network for tenant %s was already deleted.", tenant_id)
        except sa.exc.InvalidRequestError:
            LOG.info("HA network %s can not be deleted.", net_id)
        except n_exc.NetworkInUse:
            # network is still in use, this is normal so we don't
            # log anything
            pass
        else:
            LOG.info("HA network %(network)s was deleted as "
                     "no HA routers are present in tenant "
                     "%(tenant)s.",
                     {'network': net_id, 'tenant': tenant_id})

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_DELETE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _release_router_vr_id(self, resource, event, trigger, context,
                              router_db, **kwargs):
        """Event handler for removal of VRID during router delete."""
        if router_db.extra_attributes.ha:
            ha_network = self.get_ha_network(context,
                                             router_db.tenant_id)
            if ha_network:
                self._delete_vr_id_allocation(
                    context, ha_network, router_db.extra_attributes.ha_vr_id)

    @registry.receives(resources.ROUTER, [events.AFTER_DELETE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    @db_api.retry_if_session_inactive()
    def _cleanup_ha_network(self, resource, event, trigger, context,
                            router_id, original, **kwargs):
        """Event handler to attempt HA network deletion after router delete."""
        if not original['ha']:
            return
        ha_network = self.get_ha_network(context, original['tenant_id'])
        if not ha_network:
            return
        # always attempt to cleanup the network as the router is
        # deleted. the core plugin will stop us if its in use
        self.safe_delete_ha_network(context, ha_network, original['tenant_id'])

    def _unbind_ha_router(self, context, router_id):
        for agent in self.get_l3_agents_hosting_routers(context, [router_id]):
            self.remove_router_from_l3_agent(context, agent['id'], router_id)

    def get_ha_router_port_bindings(self, context, router_ids, host=None):
        if not router_ids:
            return []
        return (
            l3_hamode.L3HARouterAgentPortBinding.get_l3ha_filter_host_router(
                context, router_ids, host))

    @staticmethod
    def _check_router_agent_ha_binding(context, router_id, agent_id):
        return l3_hamode.L3HARouterAgentPortBinding.objects_exist(
            context, router_id=router_id, l3_agent_id=agent_id)

    def _get_bindings_and_update_router_state_for_dead_agents(self, context,
                                                              router_id):
        """Return bindings. In case if dead agents were detected update router
           states on this agent.

        """
        with context.session.begin(subtransactions=True):
            bindings = self.get_ha_router_port_bindings(context, [router_id])
            router_active_agents_dead = []
            router_standby_agents_dead = []
            # List agents where router is active and agent is dead
            # and agents where router is standby and agent is dead
            for binding in bindings:
                if not (binding.agent.is_active and
                        binding.agent.admin_state_up):
                    if binding.state == n_const.HA_ROUTER_STATE_ACTIVE:
                        router_active_agents_dead.append(binding.agent)
                    elif binding.state == n_const.HA_ROUTER_STATE_STANDBY:
                        router_standby_agents_dead.append(binding.agent)
            if router_active_agents_dead:
                # Just check if all l3_agents are down
                # then assuming some communication issue
                if (len(router_active_agents_dead) +
                        len(router_standby_agents_dead) == len(bindings)):
                    # Make router status as unknown because
                    # agent communication may be issue but router
                    # may still be active. We do not know the
                    # exact status of router.
                    state = n_const.HA_ROUTER_STATE_UNKNOWN
                else:
                    # Make router status as standby on all dead agents
                    # as some other agents are alive , router can become
                    # active on them after some time
                    state = n_const.HA_ROUTER_STATE_STANDBY
                for dead_agent in router_active_agents_dead:
                    self.update_routers_states(context, {router_id: state},
                                               dead_agent.host)
        if router_active_agents_dead:
            return self.get_ha_router_port_bindings(context, [router_id])
        return bindings

    def get_l3_bindings_hosting_router_with_ha_states(
            self, context, router_id):
        """Return a list of [(agent, ha_state), ...]."""
        bindings = self._get_bindings_and_update_router_state_for_dead_agents(
            context, router_id)
        return [(binding.agent, binding.state) for binding in bindings
                if binding.agent is not None]

    def get_active_host_for_ha_router(self, context, router_id):
        bindings = self.get_l3_bindings_hosting_router_with_ha_states(
            context, router_id)
        # TODO(amuller): In case we have two or more actives, this method
        # needs to return the last agent to become active. This requires
        # timestamps for state changes. Otherwise, if a host goes down
        # and another takes over, we'll have two actives. In this case,
        # if an interface is added to a router, its binding might be wrong
        # and l2pop would not work correctly.
        return next(
            (agent.host for agent, state in bindings
             if state == n_const.HA_ROUTER_STATE_ACTIVE),
            None)

    @log_helpers.log_method_call
    def _process_sync_ha_data(self, context, routers, host, is_any_dvr_agent):
        routers_dict = dict((router['id'], router) for router in routers)

        bindings = self.get_ha_router_port_bindings(context,
                                                    routers_dict.keys(),
                                                    host)
        for binding in bindings:
            port = binding.port
            if not port:
                # Filter the HA router has no ha port here
                LOG.info("HA router %s is missing HA router port "
                         "bindings. Skipping it.",
                         binding.router_id)
                routers_dict.pop(binding.router_id)
                continue
            port_dict = self._core_plugin._make_port_dict(port)

            router = routers_dict.get(binding.router_id)
            router[constants.HA_INTERFACE_KEY] = port_dict
            router[n_const.HA_ROUTER_STATE_KEY] = binding.state

        interfaces = []
        for router in routers_dict.values():
            interface = router.get(constants.HA_INTERFACE_KEY)
            if interface:
                interfaces.append(interface)

        self._populate_mtu_and_subnets_for_ports(context, interfaces)

        # If this is a DVR+HA router, then we want to always return it even
        # though it's missing the '_ha_interface' key. The agent will have
        # to figure out what kind of router setup is needed.
        return [r for r in list(routers_dict.values())
                if (is_any_dvr_agent or
                    not r.get('ha') or r.get(constants.HA_INTERFACE_KEY))]

    @log_helpers.log_method_call
    def get_ha_sync_data_for_host(self, context, host, agent,
                                  router_ids=None, active=None):
        agent_mode = self._get_agent_mode(agent)
        dvr_agent_mode = (
            agent_mode in [constants.L3_AGENT_MODE_DVR_SNAT,
                           constants.L3_AGENT_MODE_DVR,
                           constants.L3_AGENT_MODE_DVR_NO_EXTERNAL])
        if (dvr_agent_mode and extensions.is_extension_supported(
                self, constants.L3_DISTRIBUTED_EXT_ALIAS)):
            # DVR has to be handled differently
            sync_data = self._get_dvr_sync_data(context, host, agent,
                                                router_ids, active)
        else:
            sync_data = super(L3_HA_NAT_db_mixin, self).get_sync_data(
                context, router_ids, active)
        return self._process_sync_ha_data(
            context, sync_data, host, dvr_agent_mode)

    @classmethod
    def _set_router_states(cls, context, bindings, states):
        for binding in bindings:
            try:
                with context.session.begin(subtransactions=True):
                    binding.state = states[binding.router_id]
            except (orm.exc.StaleDataError, orm.exc.ObjectDeletedError):
                # Take concurrently deleted routers in to account
                pass

    @db_api.retry_if_session_inactive()
    def update_routers_states(self, context, states, host):
        """Receive dict of router ID to state and update them all."""

        bindings = self.get_ha_router_port_bindings(
            context, router_ids=states.keys(), host=host)
        self._set_router_states(context, bindings, states)
        self._update_router_port_bindings(context, states, host)

    def _update_router_port_bindings(self, context, states, host):
        admin_ctx = context.elevated()
        device_filter = {'device_id': list(states.keys()),
                         'device_owner':
                         [constants.DEVICE_OWNER_HA_REPLICATED_INT,
                          constants.DEVICE_OWNER_ROUTER_SNAT,
                          constants.DEVICE_OWNER_ROUTER_GW]}
        ports = self._core_plugin.get_ports(admin_ctx, filters=device_filter)
        active_ports = (
            port for port in ports
            if states[port['device_id']] == n_const.HA_ROUTER_STATE_ACTIVE)

        for port in active_ports:
            try:
                self._core_plugin.update_port(
                    admin_ctx, port['id'],
                    {port_def.RESOURCE_NAME: {portbindings.HOST_ID: host}})
            except (orm.exc.StaleDataError, orm.exc.ObjectDeletedError,
                    n_exc.PortNotFound):
                # Take concurrently deleted interfaces in to account
                pass

    def _get_gateway_port_host(self, context, router, gw_ports):
        if not router.get('ha'):
            return super(L3_HA_NAT_db_mixin, self)._get_gateway_port_host(
                context, router, gw_ports)

        gw_port_id = router['gw_port_id']
        gateway_port = gw_ports.get(gw_port_id)
        if not gw_port_id or not gateway_port:
            return
        gateway_port_status = gateway_port['status']
        gateway_port_binding_host = gateway_port[portbindings.HOST_ID]

        admin_ctx = context.elevated()
        router_id = router['id']
        ha_bindings = self.get_l3_bindings_hosting_router_with_ha_states(
            admin_ctx, router_id)
        LOG.debug("HA router %(router_id)s gateway port %(gw_port_id)s "
                  "binding host: %(host)s, status: %(status)s",
                  {"router_id": router_id,
                   "gw_port_id": gateway_port['id'],
                   "host": gateway_port_binding_host,
                   "status": gateway_port_status})
        for ha_binding_agent, ha_binding_state in ha_bindings:
            if ha_binding_state != n_const.HA_ROUTER_STATE_ACTIVE:
                continue
            # For create router gateway, the gateway port may not be ACTIVE
            # yet, so we return 'master' host directly.
            if gateway_port_status != constants.PORT_STATUS_ACTIVE:
                return ha_binding_agent.host
            # Do not let the original 'master' (current is backup) host,
            # override the gateway port binding host.
            if (gateway_port_status == constants.PORT_STATUS_ACTIVE and
                    ha_binding_agent.host == gateway_port_binding_host):
                return ha_binding_agent.host


def is_ha_router(router):
    """Return True if router to be handled is ha."""
    try:
        # See if router is a DB object first
        requested_router_type = router.extra_attributes.ha
    except AttributeError:
        # if not, try to see if it is a request body
        requested_router_type = router.get('ha')
    if validators.is_attr_set(requested_router_type):
        return requested_router_type
    return cfg.CONF.l3_ha


def is_ha_router_port(context, device_owner, router_id):
    if device_owner == constants.DEVICE_OWNER_HA_REPLICATED_INT:
        return True
    elif device_owner == constants.DEVICE_OWNER_ROUTER_SNAT:
        return l3_obj.RouterExtraAttributes.objects_exist(
            context, router_id=router_id, ha=True)
    else:
        return False
