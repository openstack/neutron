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
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import excutils
import six
import sqlalchemy as sa
from sqlalchemy import exc as sql_exc
from sqlalchemy import orm

from neutron._i18n import _, _LI
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import utils as n_utils
from neutron.db import agents_db
from neutron.db.availability_zone import router as router_az_db
from neutron.db import common_db_mixin
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import l3_dvr_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.extensions import l3_ext_ha_mode as l3_ha
from neutron.extensions import portbindings
from neutron.extensions import providernet
from neutron.plugins.common import utils as p_utils


VR_ID_RANGE = set(range(1, 255))
MAX_ALLOCATION_TRIES = 10
UNLIMITED_AGENTS_PER_ROUTER = 0

LOG = logging.getLogger(__name__)

L3_HA_OPTS = [
    cfg.BoolOpt('l3_ha',
                default=False,
                help=_('Enable HA mode for virtual routers.')),
    cfg.IntOpt('max_l3_agents_per_router',
               default=3,
               help=_("Maximum number of L3 agents which a HA router will be "
                      "scheduled on. If it is set to 0 then the router will "
                      "be scheduled on every agent.")),
    cfg.IntOpt('min_l3_agents_per_router',
               default=constants.MINIMUM_AGENTS_FOR_HA,
               help=_("Minimum number of L3 agents which a HA router will be "
                      "scheduled on. If it is set to 0 then the router will "
                      "be scheduled on every agent.")),
    cfg.StrOpt('l3_ha_net_cidr',
               default='169.254.192.0/18',
               help=_('Subnet used for the l3 HA admin network.')),
    cfg.StrOpt('l3_ha_network_type', default='',
               help=_("The network type to use when creating the HA network "
                      "for an HA router. By default or if empty, the first "
                      "'tenant_network_types' is used. This is helpful when "
                      "the VRRP traffic should use a specific network which "
                      "is not the default one.")),
    cfg.StrOpt('l3_ha_network_physical_name', default='',
               help=_("The physical network name with which the HA network "
                      "can be created."))
]
cfg.CONF.register_opts(L3_HA_OPTS)


class L3HARouterAgentPortBinding(model_base.BASEV2):
    """Represent agent binding state of a HA router port.

    A HA Router has one HA port per agent on which it is spawned.
    This binding table stores which port is used for a HA router by a
    L3 agent.
    """

    __tablename__ = 'ha_router_agent_port_bindings'
    __table_args__ = (
        sa.UniqueConstraint(
            'router_id', 'l3_agent_id',
            name='uniq_ha_router_agent_port_bindings0port_id0l3_agent_id'),
        model_base.BASEV2.__table_args__
    )
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                     ondelete='CASCADE'),
                        nullable=False, primary_key=True)
    port = orm.relationship(models_v2.Port)

    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id',
                                                       ondelete='CASCADE'),
                          nullable=False)

    l3_agent_id = sa.Column(sa.String(36),
                            sa.ForeignKey("agents.id",
                                          ondelete='CASCADE'))
    agent = orm.relationship(agents_db.Agent)

    state = sa.Column(sa.Enum(constants.HA_ROUTER_STATE_ACTIVE,
                              constants.HA_ROUTER_STATE_STANDBY,
                              name='l3_ha_states'),
                      default=constants.HA_ROUTER_STATE_STANDBY,
                      server_default=constants.HA_ROUTER_STATE_STANDBY)


class L3HARouterNetwork(model_base.BASEV2):
    """Host HA network for a tenant.

    One HA Network is used per tenant, all HA router ports are created
    on this network.
    """

    __tablename__ = 'ha_router_networks'

    tenant_id = sa.Column(sa.String(attributes.TENANT_ID_MAX_LEN),
                          primary_key=True, nullable=False)
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False, primary_key=True)
    network = orm.relationship(models_v2.Network)


class L3HARouterVRIdAllocation(model_base.BASEV2):
    """VRID allocation per HA network.

    Keep a track of the VRID allocations per HA network.
    """

    __tablename__ = 'ha_router_vrid_allocations'

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           nullable=False, primary_key=True)
    vr_id = sa.Column(sa.Integer(), nullable=False, primary_key=True)


class L3_HA_NAT_db_mixin(l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                         router_az_db.RouterAvailabilityZoneMixin):
    """Mixin class to add high availability capability to routers."""

    extra_attributes = (
        l3_dvr_db.L3_NAT_with_dvr_db_mixin.extra_attributes +
        router_az_db.RouterAvailabilityZoneMixin.extra_attributes + [
            {'name': 'ha', 'default': cfg.CONF.l3_ha},
            {'name': 'ha_vr_id', 'default': 0}])

    def _verify_configuration(self):
        self.ha_cidr = cfg.CONF.l3_ha_net_cidr
        try:
            net = netaddr.IPNetwork(self.ha_cidr)
        except netaddr.AddrFormatError:
            raise l3_ha.HANetworkCIDRNotValid(cidr=self.ha_cidr)
        if ('/' not in self.ha_cidr or net.network != net.ip):
            raise l3_ha.HANetworkCIDRNotValid(cidr=self.ha_cidr)

        self._check_num_agents_per_router()

    def _check_num_agents_per_router(self):
        max_agents = cfg.CONF.max_l3_agents_per_router
        min_agents = cfg.CONF.min_l3_agents_per_router

        if (max_agents != UNLIMITED_AGENTS_PER_ROUTER
            and max_agents < min_agents):
            raise l3_ha.HAMaximumAgentsNumberNotValid(
                max_agents=max_agents, min_agents=min_agents)

        if min_agents < constants.MINIMUM_AGENTS_FOR_HA:
            raise l3_ha.HAMinimumAgentsNumberNotValid()

    def __init__(self):
        self._verify_configuration()
        super(L3_HA_NAT_db_mixin, self).__init__()

    def get_ha_network(self, context, tenant_id):
        return (context.session.query(L3HARouterNetwork).
                filter(L3HARouterNetwork.tenant_id == tenant_id).
                first())

    def _get_allocated_vr_id(self, context, network_id):
        with context.session.begin(subtransactions=True):
            query = (context.session.query(L3HARouterVRIdAllocation).
                     filter(L3HARouterVRIdAllocation.network_id == network_id))

            allocated_vr_ids = set(a.vr_id for a in query) - set([0])

        return allocated_vr_ids

    def _allocate_vr_id(self, context, network_id, router_id):
        for count in range(MAX_ALLOCATION_TRIES):
            try:
                # NOTE(kevinbenton): we disallow subtransactions because the
                # retry logic will bust any parent transactions
                with context.session.begin():
                    allocated_vr_ids = self._get_allocated_vr_id(context,
                                                                 network_id)
                    available_vr_ids = VR_ID_RANGE - allocated_vr_ids

                    if not available_vr_ids:
                        raise l3_ha.NoVRIDAvailable(router_id=router_id)

                    allocation = L3HARouterVRIdAllocation()
                    allocation.network_id = network_id
                    allocation.vr_id = available_vr_ids.pop()

                    context.session.add(allocation)

                    return allocation.vr_id

            except db_exc.DBDuplicateEntry:
                LOG.info(_LI("Attempt %(count)s to allocate a VRID in the "
                             "network %(network)s for the router %(router)s"),
                         {'count': count, 'network': network_id,
                          'router': router_id})

        raise l3_ha.MaxVRIDAllocationTriesReached(
            network_id=network_id, router_id=router_id,
            max_tries=MAX_ALLOCATION_TRIES)

    def _delete_vr_id_allocation(self, context, ha_network, vr_id):
        with context.session.begin(subtransactions=True):
            context.session.query(L3HARouterVRIdAllocation).filter_by(
                network_id=ha_network.network_id,
                vr_id=vr_id).delete()

    def _set_vr_id(self, context, router, ha_network):
        router.extra_attributes.ha_vr_id = self._allocate_vr_id(
            context, ha_network.network_id, router.id)

    def _create_ha_subnet(self, context, network_id, tenant_id):
        args = {'network_id': network_id,
                'tenant_id': '',
                'name': constants.HA_SUBNET_NAME % tenant_id,
                'ip_version': 4,
                'cidr': cfg.CONF.l3_ha_net_cidr,
                'enable_dhcp': False,
                'gateway_ip': None}
        return p_utils.create_subnet(self._core_plugin, context,
                                     {'subnet': args})

    def _create_ha_network_tenant_binding(self, context, tenant_id,
                                          network_id):
        with context.session.begin():
            ha_network = L3HARouterNetwork(tenant_id=tenant_id,
                                           network_id=network_id)
            context.session.add(ha_network)
        # we need to check if someone else just inserted at exactly the
        # same time as us because there is no constrain in L3HARouterNetwork
        # that prevents multiple networks per tenant
        with context.session.begin(subtransactions=True):
            items = (context.session.query(L3HARouterNetwork).
                     filter_by(tenant_id=tenant_id).all())
            if len(items) > 1:
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
                {'name': constants.HA_NETWORK_NAME % tenant_id,
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

        network, ha_network = common_db_mixin.safe_creation(
            context, creation, deletion, content, transaction=False)
        try:
            self._create_ha_subnet(admin_ctx, network['id'], tenant_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._core_plugin.delete_network(admin_ctx, network['id'])

        return ha_network

    def get_number_of_agents_for_scheduling(self, context):
        """Return the number of agents on which the router will be scheduled.

        Raises an exception if there are not enough agents available to honor
        the min_agents config parameter. If the max_agents parameter is set to
        0 all the agents will be used.
        """

        min_agents = cfg.CONF.min_l3_agents_per_router
        num_agents = len(self.get_l3_agents(context, active=True,
            filters={'agent_modes': [constants.L3_AGENT_MODE_LEGACY,
                                     constants.L3_AGENT_MODE_DVR_SNAT]}))
        max_agents = cfg.CONF.max_l3_agents_per_router
        if max_agents:
            if max_agents > num_agents:
                LOG.info(_LI("Number of active agents lower than "
                             "max_l3_agents_per_router. L3 agents "
                             "available: %s"), num_agents)
            else:
                num_agents = max_agents

        if num_agents < min_agents:
            raise l3_ha.HANotEnoughAvailableAgents(min_agents=min_agents,
                                                   num_agents=num_agents)

        return num_agents

    def _create_ha_port_binding(self, context, router_id, port_id):
        try:
            with context.session.begin():
                portbinding = L3HARouterAgentPortBinding(port_id=port_id,
                                                         router_id=router_id)
                context.session.add(portbinding)

            return portbinding
        except db_exc.DBReferenceError as e:
            with excutils.save_and_reraise_exception() as ctxt:
                if isinstance(e.inner_exception, sql_exc.IntegrityError):
                    ctxt.reraise = False
                    LOG.debug(
                        'Failed to create HA router agent PortBinding, '
                        'Router %s has already been removed '
                        'by concurrent operation', router_id)
                    raise l3.RouterNotFound(router_id=router_id)

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
                'name': constants.HA_PORT_NAME % tenant_id}
        creation = functools.partial(p_utils.create_port, self._core_plugin,
                                     context, {'port': args})
        content = functools.partial(self._create_ha_port_binding, context,
                                    router_id)
        deletion = functools.partial(self._core_plugin.delete_port, context,
                                     l3_port_check=False)
        port, bindings = common_db_mixin.safe_creation(context, creation,
                                                       deletion, content,
                                                       transaction=False)
        return bindings

    def _create_ha_interfaces(self, context, router, ha_network):
        admin_ctx = context.elevated()

        num_agents = self.get_number_of_agents_for_scheduling(context)

        port_ids = []
        try:
            for index in range(num_agents):
                binding = self.add_ha_port(admin_ctx, router.id,
                                           ha_network.network['id'],
                                           router.tenant_id)
                port_ids.append(binding.port_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                for port_id in port_ids:
                    self._core_plugin.delete_port(admin_ctx, port_id,
                                                  l3_port_check=False)

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

    def _notify_ha_interfaces_updated(self, context, router_id):
        self.l3_rpc_notifier.routers_updated(
            context, [router_id], shuffle_agents=True)

    @classmethod
    def _is_ha(cls, router):
        ha = router.get('ha')
        if not attributes.is_attr_set(ha):
            ha = cfg.CONF.l3_ha
        return ha

    def _get_device_owner(self, context, router=None):
        """Get device_owner for the specified router."""
        router_is_uuid = isinstance(router, six.string_types)
        if router_is_uuid:
            router = self._get_router(context, router)
        if is_ha_router(router):
            return constants.DEVICE_OWNER_HA_REPLICATED_INT
        return super(L3_HA_NAT_db_mixin,
                     self)._get_device_owner(context, router)

    @n_utils.transaction_guard
    def _create_ha_interfaces_and_ensure_network(self, context, router_db):
        """Attach interfaces to a network while tolerating network deletes."""
        creator = functools.partial(self._create_ha_interfaces,
                                    context, router_db)
        dep_getter = functools.partial(self.get_ha_network,
                                       context, router_db.tenant_id)
        dep_creator = functools.partial(self._create_ha_network,
                                        context, router_db.tenant_id)
        dep_id_attr = 'network_id'
        return n_utils.create_object_with_dependency(
            creator, dep_getter, dep_creator, dep_id_attr)

    def create_router(self, context, router):
        is_ha = self._is_ha(router['router'])
        router['router']['ha'] = is_ha
        router_dict = super(L3_HA_NAT_db_mixin,
                            self).create_router(context, router)
        if is_ha:
            try:
                router_db = self._get_router(context, router_dict['id'])
                # the following returns interfaces and the network we only
                # care about the network
                ha_network = self._create_ha_interfaces_and_ensure_network(
                    context, router_db)[1]

                self._set_vr_id(context, router_db, ha_network)
                self._notify_ha_interfaces_updated(context, router_db.id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self.delete_router(context, router_dict['id'])
            router_dict['ha_vr_id'] = router_db.extra_attributes.ha_vr_id
        return router_dict

    def _update_router_db(self, context, router_id, data):
        router_db = self._get_router(context, router_id)

        original_distributed_state = router_db.extra_attributes.distributed
        original_ha_state = router_db.extra_attributes.ha

        requested_ha_state = data.pop('ha', None)
        requested_distributed_state = data.get('distributed', None)
        # cvr to dvrha
        if not original_distributed_state and not original_ha_state:
            if (requested_ha_state is True and
                    requested_distributed_state is True):
                raise l3_ha.UpdateToDvrHamodeNotSupported()

        # cvrha to any dvr...
        elif not original_distributed_state and original_ha_state:
            if requested_distributed_state is True:
                raise l3_ha.DVRmodeUpdateOfHaNotSupported()

        # dvr to any ha...
        elif original_distributed_state and not original_ha_state:
            if requested_ha_state is True:
                raise l3_ha.HAmodeUpdateOfDvrNotSupported()

        #dvrha to any cvr...
        elif original_distributed_state and original_ha_state:
            if requested_distributed_state is False:
                raise l3_ha.DVRmodeUpdateOfDvrHaNotSupported()
            #elif dvrha to dvr
            if requested_ha_state is False:
                raise l3_ha.HAmodeUpdateOfDvrHaNotSupported()

        with context.session.begin(subtransactions=True):
            router_db = super(L3_HA_NAT_db_mixin, self)._update_router_db(
                context, router_id, data)

            ha_not_changed = (requested_ha_state is None or
                              requested_ha_state == original_ha_state)
            if ha_not_changed:
                return router_db

            if router_db.admin_state_up:
                msg = _('Cannot change HA attribute of active routers. Please '
                        'set router admin_state_up to False prior to upgrade.')
                raise n_exc.BadRequest(resource='router', msg=msg)

            ha_network = self.get_ha_network(context,
                                             router_db.tenant_id)
            router_db.extra_attributes.ha = requested_ha_state
            if not requested_ha_state:
                self._delete_vr_id_allocation(
                    context, ha_network, router_db.extra_attributes.ha_vr_id)
                router_db.extra_attributes.ha_vr_id = None

        # The HA attribute has changed. First unbind the router from agents
        # to force a proper re-scheduling to agents.
        # TODO(jschwarz): This will have to be more selective to get HA + DVR
        # working (Only unbind from dvr_snat nodes).
        self._unbind_ha_router(context, router_id)

        if requested_ha_state:
            ha_network = self._create_ha_interfaces_and_ensure_network(
                context, router_db)[1]
            self._set_vr_id(context, router_db, ha_network)
            self._notify_ha_interfaces_updated(context, router_db.id)
        else:
            self._delete_ha_interfaces(context, router_db.id)
            self._notify_ha_interfaces_updated(context, router_db.id)

        return router_db

    def _delete_ha_network(self, context, net):
        admin_ctx = context.elevated()
        self._core_plugin.delete_network(admin_ctx, net.network_id)

    def _ha_routers_present(self, context, tenant_id):
        ha = True
        routers = context.session.query(l3_db.Router).filter(
            l3_db.Router.tenant_id == tenant_id).subquery()
        ha_routers = context.session.query(
            l3_attrs_db.RouterExtraAttributes).join(
            routers,
            l3_attrs_db.RouterExtraAttributes.router_id == routers.c.id
        ).filter(l3_attrs_db.RouterExtraAttributes.ha == ha).first()
        return ha_routers is not None

    def delete_router(self, context, id):
        router_db = self._get_router(context, id)
        super(L3_HA_NAT_db_mixin, self).delete_router(context, id)

        if router_db.extra_attributes.ha:
            ha_network = self.get_ha_network(context,
                                             router_db.tenant_id)
            if ha_network:
                self._delete_vr_id_allocation(
                    context, ha_network, router_db.extra_attributes.ha_vr_id)
                self._delete_ha_interfaces(context, router_db.id)

                # In case that create HA router failed because of the failure
                # in HA network creation. So here put this deleting HA network
                # procedure under 'if ha_network' block.
                if not self._ha_routers_present(context,
                                                router_db.tenant_id):
                    try:
                        self._delete_ha_network(context, ha_network)
                    except (n_exc.NetworkNotFound,
                            orm.exc.ObjectDeletedError):
                        LOG.debug(
                            "HA network for tenant %s was already deleted.",
                            router_db.tenant_id)
                    except sa.exc.InvalidRequestError:
                        LOG.info(_LI("HA network %s can not be deleted."),
                                 ha_network.network_id)
                    except n_exc.NetworkInUse:
                        LOG.debug("HA network %s is still in use.",
                                  ha_network.network_id)
                    else:
                        LOG.info(_LI("HA network %(network)s was deleted as "
                                     "no HA routers are present in tenant "
                                     "%(tenant)s."),
                                 {'network': ha_network.network_id,
                                  'tenant': router_db.tenant_id})

    def _unbind_ha_router(self, context, router_id):
        for agent in self.get_l3_agents_hosting_routers(context, [router_id]):
            self.remove_router_from_l3_agent(context, agent['id'], router_id)

    def get_ha_router_port_bindings(self, context, router_ids, host=None):
        if not router_ids:
            return []
        query = context.session.query(L3HARouterAgentPortBinding)

        if host:
            query = query.join(agents_db.Agent).filter(
                agents_db.Agent.host == host)

        query = query.filter(
            L3HARouterAgentPortBinding.router_id.in_(router_ids))

        return query.all()

    @staticmethod
    def _check_router_agent_ha_binding(context, router_id, agent_id):
        query = context.session.query(L3HARouterAgentPortBinding)
        query = query.filter(
            L3HARouterAgentPortBinding.router_id == router_id,
            L3HARouterAgentPortBinding.l3_agent_id == agent_id)
        return query.first() is not None

    def _get_bindings_and_update_router_state_for_dead_agents(self, context,
                                                              router_id):
        """Return bindings. In case if dead agents were detected update router
           states on this agent.

        """
        with context.session.begin(subtransactions=True):
            bindings = self.get_ha_router_port_bindings(context, [router_id])
            dead_agents = [
                binding.agent for binding in bindings
                if binding.state == constants.HA_ROUTER_STATE_ACTIVE and
                not binding.agent.is_active]
            for dead_agent in dead_agents:
                self.update_routers_states(
                    context, {router_id: constants.HA_ROUTER_STATE_STANDBY},
                    dead_agent.host)

        if dead_agents:
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
             if state == constants.HA_ROUTER_STATE_ACTIVE),
            None)

    @log_helpers.log_method_call
    def _process_sync_ha_data(self, context, routers, host):
        routers_dict = dict((router['id'], router) for router in routers)

        bindings = self.get_ha_router_port_bindings(context,
                                                    routers_dict.keys(),
                                                    host)
        for binding in bindings:
            port_dict = self._core_plugin._make_port_dict(binding.port)

            router = routers_dict.get(binding.router_id)
            router[constants.HA_INTERFACE_KEY] = port_dict
            router[constants.HA_ROUTER_STATE_KEY] = binding.state

        for router in routers_dict.values():
            interface = router.get(constants.HA_INTERFACE_KEY)
            if interface:
                self._populate_mtu_and_subnets_for_ports(context, [interface])

        # we don't want to return HA routers without HA interfaces created yet
        return [r for r in list(routers_dict.values())
                if not r.get('ha') or r.get(constants.HA_INTERFACE_KEY)]

    @log_helpers.log_method_call
    def get_ha_sync_data_for_host(self, context, host, agent,
                                  router_ids=None, active=None):
        agent_mode = self._get_agent_mode(agent)
        dvr_agent_mode = (agent_mode in [constants.L3_AGENT_MODE_DVR_SNAT,
                                         constants.L3_AGENT_MODE_DVR])
        if (dvr_agent_mode and n_utils.is_extension_supported(
                self, constants.L3_DISTRIBUTED_EXT_ALIAS)):
            # DVR has to be handled differently
            sync_data = self._get_dvr_sync_data(context, host, agent,
                                                router_ids, active)
        else:
            sync_data = super(L3_HA_NAT_db_mixin, self).get_sync_data(context,
                                                            router_ids, active)
        return self._process_sync_ha_data(context, sync_data, host)

    @classmethod
    def _set_router_states(cls, context, bindings, states):
        for binding in bindings:
            try:
                with context.session.begin(subtransactions=True):
                    binding.state = states[binding.router_id]
            except (orm.exc.StaleDataError, orm.exc.ObjectDeletedError):
                # Take concurrently deleted routers in to account
                pass

    def update_routers_states(self, context, states, host):
        """Receive dict of router ID to state and update them all."""

        bindings = self.get_ha_router_port_bindings(
            context, router_ids=states.keys(), host=host)
        self._set_router_states(context, bindings, states)
        self._update_router_port_bindings(context, states, host)

    def _update_router_port_bindings(self, context, states, host):
        admin_ctx = context.elevated()
        device_filter = {'device_id': states.keys(),
                         'device_owner':
                         [constants.DEVICE_OWNER_HA_REPLICATED_INT,
                          constants.DEVICE_OWNER_ROUTER_SNAT]}
        ports = self._core_plugin.get_ports(admin_ctx, filters=device_filter)
        active_ports = (port for port in ports
            if states[port['device_id']] == constants.HA_ROUTER_STATE_ACTIVE)

        for port in active_ports:
            port[portbindings.HOST_ID] = host
            try:
                self._core_plugin.update_port(admin_ctx, port['id'],
                                              {attributes.PORT: port})
            except (orm.exc.StaleDataError, orm.exc.ObjectDeletedError,
                    n_exc.PortNotFound):
                # Take concurrently deleted interfaces in to account
                pass


def is_ha_router(router):
    """Return True if router to be handled is ha."""
    try:
        # See if router is a DB object first
        requested_router_type = router.extra_attributes.ha
    except AttributeError:
        # if not, try to see if it is a request body
        requested_router_type = router.get('ha')
    if attributes.is_attr_set(requested_router_type):
        return requested_router_type
    return cfg.CONF.l3_ha
