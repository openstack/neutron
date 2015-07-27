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

import netaddr
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import utils as n_utils
from neutron.db import agents_db
from neutron.db import l3_dvr_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import l3_ext_ha_mode as l3_ha
from neutron.i18n import _LI

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
               help=_('Maximum number of agents on which a router will be '
                      'scheduled.')),
    cfg.IntOpt('min_l3_agents_per_router',
               default=constants.MINIMUM_AGENTS_FOR_HA,
               help=_('Minimum number of agents on which a router will be '
                      'scheduled.')),
    cfg.StrOpt('l3_ha_net_cidr',
               default='169.254.192.0/18',
               help=_('Subnet used for the l3 HA admin network.')),
]
cfg.CONF.register_opts(L3_HA_OPTS)


class L3HARouterAgentPortBinding(model_base.BASEV2):
    """Represent agent binding state of a HA router port.

    A HA Router has one HA port per agent on which it is spawned.
    This binding table stores which port is used for a HA router by a
    L3 agent.
    """

    __tablename__ = 'ha_router_agent_port_bindings'

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

    state = sa.Column(sa.Enum('active', 'standby', name='l3_ha_states'),
                      default='standby',
                      server_default='standby')


class L3HARouterNetwork(model_base.BASEV2):
    """Host HA network for a tenant.

    One HA Network is used per tenant, all HA router ports are created
    on this network.
    """

    __tablename__ = 'ha_router_networks'

    tenant_id = sa.Column(sa.String(255), primary_key=True,
                          nullable=False)
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


class L3_HA_NAT_db_mixin(l3_dvr_db.L3_NAT_with_dvr_db_mixin):
    """Mixin class to add high availability capability to routers."""

    extra_attributes = (
        l3_dvr_db.L3_NAT_with_dvr_db_mixin.extra_attributes + [
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
                with context.session.begin(subtransactions=True):
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
        with context.session.begin(subtransactions=True):
            router.extra_attributes.ha_vr_id = self._allocate_vr_id(
                context, ha_network.network_id, router.id)

    def _create_ha_subnet(self, context, network_id, tenant_id):
        args = {'subnet':
                {'network_id': network_id,
                 'tenant_id': '',
                 'name': constants.HA_SUBNET_NAME % tenant_id,
                 'ip_version': 4,
                 'cidr': cfg.CONF.l3_ha_net_cidr,
                 'enable_dhcp': False,
                 'host_routes': attributes.ATTR_NOT_SPECIFIED,
                 'dns_nameservers': attributes.ATTR_NOT_SPECIFIED,
                 'allocation_pools': attributes.ATTR_NOT_SPECIFIED,
                 'gateway_ip': None}}
        return self._core_plugin.create_subnet(context, args)

    def _create_ha_network_tenant_binding(self, context, tenant_id,
                                          network_id):
        with context.session.begin(subtransactions=True):
            ha_network = L3HARouterNetwork(tenant_id=tenant_id,
                                           network_id=network_id)
            context.session.add(ha_network)
        return ha_network

    def _create_ha_network(self, context, tenant_id):
        admin_ctx = context.elevated()

        args = {'network':
                {'name': constants.HA_NETWORK_NAME % tenant_id,
                 'tenant_id': '',
                 'shared': False,
                 'admin_state_up': True,
                 'status': constants.NET_STATUS_ACTIVE}}
        network = self._core_plugin.create_network(admin_ctx, args)
        try:
            ha_network = self._create_ha_network_tenant_binding(admin_ctx,
                                                                tenant_id,
                                                                network['id'])
        except Exception:
            with excutils.save_and_reraise_exception():
                self._core_plugin.delete_network(admin_ctx, network['id'])

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

    def _create_ha_port_binding(self, context, port_id, router_id):
        with context.session.begin(subtransactions=True):
            portbinding = L3HARouterAgentPortBinding(port_id=port_id,
                                                     router_id=router_id)
            context.session.add(portbinding)

        return portbinding

    def add_ha_port(self, context, router_id, network_id, tenant_id):
        port = self._core_plugin.create_port(context, {
            'port':
            {'tenant_id': '',
             'network_id': network_id,
             'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
             'mac_address': attributes.ATTR_NOT_SPECIFIED,
             'admin_state_up': True,
             'device_id': router_id,
             'device_owner': constants.DEVICE_OWNER_ROUTER_HA_INTF,
             'name': constants.HA_PORT_NAME % tenant_id}})

        try:
            return self._create_ha_port_binding(context, port['id'], router_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._core_plugin.delete_port(context, port['id'],
                                              l3_port_check=False)

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

    def create_router(self, context, router):
        is_ha = self._is_ha(router['router'])

        if is_ha and l3_dvr_db.is_distributed_router(router['router']):
            raise l3_ha.DistributedHARouterNotSupported()

        router['router']['ha'] = is_ha
        router_dict = super(L3_HA_NAT_db_mixin,
                            self).create_router(context, router)

        if is_ha:
            try:
                router_db = self._get_router(context, router_dict['id'])
                ha_network = self.get_ha_network(context,
                                                 router_db.tenant_id)
                if not ha_network:
                    ha_network = self._create_ha_network(context,
                                                         router_db.tenant_id)

                self._set_vr_id(context, router_db, ha_network)
                self._create_ha_interfaces(context, router_db, ha_network)
                self._notify_ha_interfaces_updated(context, router_db.id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self.delete_router(context, router_dict['id'])
            router_dict['ha_vr_id'] = router_db.extra_attributes.ha_vr_id
        return router_dict

    def _update_router_db(self, context, router_id, data, gw_info):
        ha = data.pop('ha', None)

        if ha and data.get('distributed'):
            raise l3_ha.DistributedHARouterNotSupported()

        with context.session.begin(subtransactions=True):
            router_db = super(L3_HA_NAT_db_mixin, self)._update_router_db(
                context, router_id, data, gw_info)

            ha_not_changed = ha is None or ha == router_db.extra_attributes.ha
            if ha_not_changed:
                return router_db

            ha_network = self.get_ha_network(context,
                                             router_db.tenant_id)
            router_db.extra_attributes.ha = ha
            if not ha:
                self._delete_vr_id_allocation(
                    context, ha_network, router_db.extra_attributes.ha_vr_id)
                router_db.extra_attributes.ha_vr_id = None

        if ha:
            if not ha_network:
                ha_network = self._create_ha_network(context,
                                                     router_db.tenant_id)

            self._set_vr_id(context, router_db, ha_network)
            self._create_ha_interfaces(context, router_db, ha_network)
            self._notify_ha_interfaces_updated(context, router_db.id)
        else:
            self._delete_ha_interfaces(context, router_db.id)
            self._notify_ha_interfaces_updated(context, router_db.id)

        return router_db

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

    def get_l3_bindings_hosting_router_with_ha_states(
            self, context, router_id):
        """Return a list of [(agent, ha_state), ...]."""
        bindings = self.get_ha_router_port_bindings(context, [router_id])
        return [(binding.agent, binding.state) for binding in bindings]

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
                self._populate_subnets_for_ports(context, [interface])

        return list(routers_dict.values())

    def get_ha_sync_data_for_host(self, context, host=None, router_ids=None,
                                  active=None):
        if n_utils.is_extension_supported(self,
                                          constants.L3_DISTRIBUTED_EXT_ALIAS):
            # DVR has to be handled differently
            agent = self._get_agent_by_type_and_host(context,
                                                     constants.AGENT_TYPE_L3,
                                                     host)
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
