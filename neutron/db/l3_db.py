# Copyright 2012 VMware, Inc.  All rights reserved.
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

import itertools

import netaddr
from neutron_lib.api import validators
from neutron_lib import constants as l3_constants
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
import six
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron._i18n import _, _LI
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as n_const
from neutron.common import ipv6_utils
from neutron.common import rpc as n_rpc
from neutron.common import utils
from neutron.db import l3_agentschedulers_db as l3_agt
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import standardattrdescription_db as st_attr
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants
from neutron.plugins.common import utils as p_utils

LOG = logging.getLogger(__name__)


DEVICE_OWNER_HA_REPLICATED_INT = l3_constants.DEVICE_OWNER_HA_REPLICATED_INT
DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP
EXTERNAL_GW_INFO = l3.EXTERNAL_GW_INFO

# Maps API field to DB column
# API parameter name and Database column names may differ.
# Useful to keep the filtering between API and Database.
API_TO_DB_COLUMN_MAP = {'port_id': 'fixed_port_id'}
CORE_ROUTER_ATTRS = ('id', 'name', 'tenant_id', 'admin_state_up', 'status')


class RouterPort(model_base.BASEV2):
    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
    port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete="CASCADE"),
        primary_key=True)
    # The port_type attribute is redundant as the port table already specifies
    # it in DEVICE_OWNER.However, this redundancy enables more efficient
    # queries on router ports, and also prevents potential error-prone
    # conditions which might originate from users altering the DEVICE_OWNER
    # property of router ports.
    port_type = sa.Column(sa.String(attributes.DEVICE_OWNER_MAX_LEN))
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref('routerport', uselist=False, cascade="all,delete"),
        lazy='joined')


class Router(model_base.HasStandardAttributes, model_base.BASEV2,
             model_base.HasId, model_base.HasTenant):
    """Represents a v2 neutron router."""

    name = sa.Column(sa.String(attributes.NAME_MAX_LEN))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    gw_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    gw_port = orm.relationship(models_v2.Port, lazy='joined')
    attached_ports = orm.relationship(
        RouterPort,
        backref='router',
        lazy='dynamic')
    l3_agents = orm.relationship(
        'Agent', lazy='joined', viewonly=True,
        secondary=l3_agt.RouterL3AgentBinding.__table__)


class FloatingIP(model_base.HasStandardAttributes, model_base.BASEV2,
                 model_base.HasId, model_base.HasTenant):
    """Represents a floating IP address.

    This IP address may or may not be allocated to a tenant, and may or
    may not be associated with an internal port/ip address/router.
    """

    floating_ip_address = sa.Column(sa.String(64), nullable=False)
    floating_network_id = sa.Column(sa.String(36), nullable=False)
    floating_port_id = sa.Column(sa.String(36),
                                 sa.ForeignKey('ports.id', ondelete="CASCADE"),
                                 nullable=False)

    # The ORM-level "delete" cascade relationship between port and floating_ip
    # is required for causing the in-Python event "after_delete" that needs for
    # proper quota management in case when cascade removal of the floating_ip
    # happens after removal of the floating_port
    port = orm.relationship(models_v2.Port,
                            backref=orm.backref('floating_ips',
                                                cascade='all,delete-orphan'),
                            foreign_keys='FloatingIP.floating_port_id')
    fixed_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    fixed_ip_address = sa.Column(sa.String(64))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'))
    # Additional attribute for keeping track of the router where the floating
    # ip was associated in order to be able to ensure consistency even if an
    # asynchronous backend is unavailable when the floating IP is disassociated
    last_known_router_id = sa.Column(sa.String(36))
    status = sa.Column(sa.String(16))
    router = orm.relationship(Router, backref='floating_ips')


class L3_NAT_dbonly_mixin(l3.RouterPluginBase,
                          st_attr.StandardAttrDescriptionMixin):
    """Mixin class to add L3/NAT router methods to db_base_plugin_v2."""

    router_device_owners = (
        DEVICE_OWNER_HA_REPLICATED_INT,
        DEVICE_OWNER_ROUTER_INTF,
        DEVICE_OWNER_ROUTER_GW,
        DEVICE_OWNER_FLOATINGIP
    )

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_router(self, context, router_id):
        try:
            router = self._get_by_id(context, Router, router_id)
        except exc.NoResultFound:
            raise l3.RouterNotFound(router_id=router_id)
        return router

    def _make_router_dict(self, router, fields=None, process_extensions=True):
        res = dict((key, router[key]) for key in CORE_ROUTER_ATTRS)
        if router['gw_port_id']:
            ext_gw_info = {
                'network_id': router.gw_port['network_id'],
                'external_fixed_ips': [{'subnet_id': ip["subnet_id"],
                                        'ip_address': ip["ip_address"]}
                                       for ip in router.gw_port['fixed_ips']]}
        else:
            ext_gw_info = None
        res.update({
            EXTERNAL_GW_INFO: ext_gw_info,
            'gw_port_id': router['gw_port_id'],
        })
        # NOTE(salv-orlando): The following assumes this mixin is used in a
        # class inheriting from CommonDbMixin, which is true for all existing
        # plugins.
        if process_extensions:
            self._apply_dict_extend_functions(l3.ROUTERS, res, router)
        return self._fields(res, fields)

    def filter_allocating_and_missing_routers(self, context, routers):
        """Filter out routers that shouldn't go to the agent.

        Any routers in the ALLOCATING state will be excluded by
        this query because this indicates that the server is still
        building necessary dependent sub-resources for the router and it
        is not ready for consumption by the agent. It will also filter
        out any routers that no longer exist to prevent conditions where
        only part of a router's information was populated in sync_routers
        due to it being deleted during the sync.
        """
        router_ids = set(r['id'] for r in routers)
        query = (context.session.query(Router.id).
                 filter(
                     Router.id.in_(router_ids),
                     Router.status != n_const.ROUTER_STATUS_ALLOCATING))
        valid_routers = set(r.id for r in query)
        if router_ids - valid_routers:
            LOG.debug("Removing routers that were either concurrently "
                      "deleted or are in the ALLOCATING state: %s",
                      (router_ids - valid_routers))
        return [r for r in routers if r['id'] in valid_routers]

    def _create_router_db(self, context, router, tenant_id):
        """Create the DB object."""
        with context.session.begin(subtransactions=True):
            # pre-generate id so it will be available when
            # configuring external gw port
            status = router.get('status', n_const.ROUTER_STATUS_ACTIVE)
            router_db = Router(id=(router.get('id') or
                                   uuidutils.generate_uuid()),
                               tenant_id=tenant_id,
                               name=router['name'],
                               admin_state_up=router['admin_state_up'],
                               status=status,
                               description=router.get('description'))
            context.session.add(router_db)
            return router_db

    def create_router(self, context, router):
        r = router['router']
        gw_info = r.pop(EXTERNAL_GW_INFO, None)
        router_db = self._create_router_db(context, r, r['tenant_id'])
        try:
            if gw_info:
                self._update_router_gw_info(context, router_db['id'],
                                            gw_info, router=router_db)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.debug("Could not update gateway info, deleting router.")
                self.delete_router(context, router_db.id)

        return self._make_router_dict(router_db)

    def _update_router_db(self, context, router_id, data):
        """Update the DB object."""
        with context.session.begin(subtransactions=True):
            router_db = self._get_router(context, router_id)
            if data:
                router_db.update(data)
            return router_db

    def update_router(self, context, id, router):
        r = router['router']
        gw_info = r.pop(EXTERNAL_GW_INFO, l3_constants.ATTR_NOT_SPECIFIED)
        # check whether router needs and can be rescheduled to the proper
        # l3 agent (associated with given external network);
        # do check before update in DB as an exception will be raised
        # in case no proper l3 agent found
        if gw_info != l3_constants.ATTR_NOT_SPECIFIED:
            candidates = self._check_router_needs_rescheduling(
                context, id, gw_info)
            # Update the gateway outside of the DB update since it involves L2
            # calls that don't make sense to rollback and may cause deadlocks
            # in a transaction.
            self._update_router_gw_info(context, id, gw_info)
        else:
            candidates = None
        router_db = self._update_router_db(context, id, r)
        if candidates:
            l3_plugin = manager.NeutronManager.get_service_plugins().get(
                constants.L3_ROUTER_NAT)
            l3_plugin.reschedule_router(context, id, candidates)
        return self._make_router_dict(router_db)

    def _check_router_needs_rescheduling(self, context, router_id, gw_info):
        """Checks whether router's l3 agent can handle the given network

        When external_network_bridge is set, each L3 agent can be associated
        with at most one external network. If router's new external gateway
        is on other network then the router needs to be rescheduled to the
        proper l3 agent.
        If external_network_bridge is not set then the agent
        can support multiple external networks and rescheduling is not needed

        :return: list of candidate agents if rescheduling needed,
        None otherwise; raises exception if there is no eligible l3 agent
        associated with target external network
        """
        # TODO(obondarev): rethink placement of this func as l3 db manager is
        # not really a proper place for agent scheduling stuff
        network_id = gw_info.get('network_id') if gw_info else None
        if not network_id:
            return

        nets = self._core_plugin.get_networks(
            context, {external_net.EXTERNAL: [True]})
        # nothing to do if there is only one external network
        if len(nets) <= 1:
            return

        # first get plugin supporting l3 agent scheduling
        # (either l3 service plugin or core_plugin)
        l3_plugin = manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
        if (not utils.is_extension_supported(
                l3_plugin,
                l3_constants.L3_AGENT_SCHEDULER_EXT_ALIAS) or
            l3_plugin.router_scheduler is None):
            # that might mean that we are dealing with non-agent-based
            # implementation of l3 services
            return

        cur_agents = l3_plugin.list_l3_agents_hosting_router(
            context, router_id)['agents']
        for agent in cur_agents:
            ext_net_id = agent['configurations'].get(
                'gateway_external_network_id')
            ext_bridge = agent['configurations'].get(
                'external_network_bridge', 'br-ex')
            if (ext_net_id == network_id or
                    (not ext_net_id and not ext_bridge)):
                return

        # otherwise find l3 agent with matching gateway_external_network_id
        active_agents = l3_plugin.get_l3_agents(context, active=True)
        router = {
            'id': router_id,
            'external_gateway_info': {'network_id': network_id}
        }
        candidates = l3_plugin.get_l3_agent_candidates(context,
                                                       router,
                                                       active_agents)
        if not candidates:
            msg = (_('No eligible l3 agent associated with external network '
                     '%s found') % network_id)
            raise n_exc.BadRequest(resource='router', msg=msg)

        return candidates

    def _create_router_gw_port(self, context, router, network_id, ext_ips):
        # Port has no 'tenant-id', as it is hidden from user
        port_data = {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'fixed_ips': ext_ips or l3_constants.ATTR_NOT_SPECIFIED,
                     'device_id': router['id'],
                     'device_owner': DEVICE_OWNER_ROUTER_GW,
                     'admin_state_up': True,
                     'name': ''}
        gw_port = p_utils.create_port(self._core_plugin,
                                      context.elevated(), {'port': port_data})

        if not gw_port['fixed_ips']:
            LOG.debug('No IPs available for external network %s',
                      network_id)

        with context.session.begin(subtransactions=True):
            router.gw_port = self._core_plugin._get_port(context.elevated(),
                                                         gw_port['id'])
            router_port = RouterPort(
                router_id=router.id,
                port_id=gw_port['id'],
                port_type=DEVICE_OWNER_ROUTER_GW
            )
            context.session.add(router)
            context.session.add(router_port)

    def _validate_gw_info(self, context, gw_port, info, ext_ips):
        network_id = info['network_id'] if info else None
        if network_id:
            network_db = self._core_plugin._get_network(context, network_id)
            if not network_db.external:
                msg = _("Network %s is not an external network") % network_id
                raise n_exc.BadRequest(resource='router', msg=msg)
            if ext_ips:
                subnets = self._core_plugin.get_subnets_by_network(context,
                                                                   network_id)
                for s in subnets:
                    if not s['gateway_ip']:
                        continue
                    for ext_ip in ext_ips:
                        if ext_ip.get('ip_address') == s['gateway_ip']:
                            msg = _("External IP %s is the same as the "
                                    "gateway IP") % ext_ip.get('ip_address')
                            raise n_exc.BadRequest(resource='router', msg=msg)
        return network_id

    def _delete_current_gw_port(self, context, router_id, router,
                                new_network_id):
        """Delete gw port if attached to an old network."""
        port_requires_deletion = (
            router.gw_port and router.gw_port['network_id'] != new_network_id)
        if not port_requires_deletion:
            return
        admin_ctx = context.elevated()
        old_network_id = router.gw_port['network_id']

        if self.get_floatingips_count(
            admin_ctx, {'router_id': [router_id]}):
            raise l3.RouterExternalGatewayInUseByFloatingIp(
                router_id=router_id, net_id=router.gw_port['network_id'])
        gw_ips = [x['ip_address'] for x in router.gw_port.fixed_ips]
        with context.session.begin(subtransactions=True):
            gw_port = router.gw_port
            router.gw_port = None
            context.session.add(router)
            context.session.expire(gw_port)
            self._check_router_gw_port_in_use(context, router_id)
        self._core_plugin.delete_port(
            admin_ctx, gw_port['id'], l3_port_check=False)
        registry.notify(resources.ROUTER_GATEWAY,
                        events.AFTER_DELETE, self,
                        router_id=router_id,
                        network_id=old_network_id,
                        gateway_ips=gw_ips)

    def _check_router_gw_port_in_use(self, context, router_id):
        try:
            kwargs = {'context': context, 'router_id': router_id}
            registry.notify(
                resources.ROUTER_GATEWAY, events.BEFORE_DELETE, self, **kwargs)
        except exceptions.CallbackFailure as e:
            with excutils.save_and_reraise_exception():
                # NOTE(armax): preserve old check's behavior
                if len(e.errors) == 1:
                    raise e.errors[0].error
                raise l3.RouterInUse(router_id=router_id, reason=e)

    def _create_gw_port(self, context, router_id, router, new_network_id,
                        ext_ips):
        new_valid_gw_port_attachment = (
            new_network_id and (not router.gw_port or
                              router.gw_port['network_id'] != new_network_id))
        if new_valid_gw_port_attachment:
            subnets = self._core_plugin.get_subnets_by_network(context,
                                                               new_network_id)
            try:
                kwargs = {'context': context, 'router_id': router_id,
                          'network_id': new_network_id, 'subnets': subnets}
                registry.notify(
                    resources.ROUTER_GATEWAY, events.BEFORE_CREATE, self,
                    **kwargs)
            except exceptions.CallbackFailure as e:
                # raise the underlying exception
                raise e.errors[0].error

            self._check_for_dup_router_subnets(context, router,
                                               new_network_id, subnets)
            self._create_router_gw_port(context, router,
                                        new_network_id, ext_ips)
            registry.notify(resources.ROUTER_GATEWAY,
                            events.AFTER_CREATE,
                            self._create_gw_port,
                            gw_ips=ext_ips,
                            network_id=new_network_id,
                            router_id=router_id)

    def _update_current_gw_port(self, context, router_id, router, ext_ips):
        self._core_plugin.update_port(context, router.gw_port['id'], {'port':
                                      {'fixed_ips': ext_ips}})
        context.session.expire(router.gw_port)

    def _update_router_gw_info(self, context, router_id, info, router=None):
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        router = router or self._get_router(context, router_id)
        gw_port = router.gw_port
        ext_ips = info.get('external_fixed_ips') if info else []
        ext_ip_change = self._check_for_external_ip_change(
            context, gw_port, ext_ips)
        network_id = self._validate_gw_info(context, gw_port, info, ext_ips)
        if gw_port and ext_ip_change and gw_port['network_id'] == network_id:
            self._update_current_gw_port(context, router_id, router,
                                         ext_ips)
        else:
            self._delete_current_gw_port(context, router_id, router,
                                         network_id)
            self._create_gw_port(context, router_id, router, network_id,
                                 ext_ips)

    def _check_for_external_ip_change(self, context, gw_port, ext_ips):
        # determine if new external IPs differ from the existing fixed_ips
        if not ext_ips:
            # no external_fixed_ips were included
            return False
        if not gw_port:
            return True

        subnet_ids = set(ip['subnet_id'] for ip in gw_port['fixed_ips'])
        new_subnet_ids = set(f['subnet_id'] for f in ext_ips
                             if f.get('subnet_id'))
        subnet_change = not new_subnet_ids == subnet_ids
        if subnet_change:
            return True
        ip_addresses = set(ip['ip_address'] for ip in gw_port['fixed_ips'])
        new_ip_addresses = set(f['ip_address'] for f in ext_ips
                               if f.get('ip_address'))
        ip_address_change = not ip_addresses == new_ip_addresses
        return ip_address_change

    def _ensure_router_not_in_use(self, context, router_id):
        """Ensure that no internal network interface is attached
        to the router.
        """
        router = self._get_router(context, router_id)
        device_owner = self._get_device_owner(context, router)
        if any(rp.port_type == device_owner
               for rp in router.attached_ports.all()):
            raise l3.RouterInUse(router_id=router_id)
        return router

    def delete_router(self, context, id):

        #TODO(nati) Refactor here when we have router insertion model
        router = self._ensure_router_not_in_use(context, id)
        self._delete_current_gw_port(context, id, router, None)

        router_ports = router.attached_ports.all()
        for rp in router_ports:
            self._core_plugin.delete_port(context.elevated(),
                                          rp.port.id,
                                          l3_port_check=False)
        with context.session.begin(subtransactions=True):
            context.session.delete(router)

    def get_router(self, context, id, fields=None):
        router = self._get_router(context, id)
        return self._make_router_dict(router, fields)

    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'router', limit, marker)
        return self._get_collection(context, Router,
                                    self._make_router_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_routers_count(self, context, filters=None):
        return self._get_collection_count(context, Router,
                                          filters=filters)

    def _check_for_dup_router_subnets(self, context, router,
                                      network_id, new_subnets):
        # It's possible these ports are on the same network, but
        # different subnets.
        new_subnet_ids = {s['id'] for s in new_subnets}
        router_subnets = []
        for p in (rp.port for rp in router.attached_ports):
            for ip in p['fixed_ips']:
                if ip['subnet_id'] in new_subnet_ids:
                    msg = (_("Router already has a port on subnet %s")
                           % ip['subnet_id'])
                    raise n_exc.BadRequest(resource='router', msg=msg)
                router_subnets.append(ip['subnet_id'])
        # Ignore temporary Prefix Delegation CIDRs
        new_subnets = [s for s in new_subnets
                       if s['cidr'] != n_const.PROVISIONAL_IPV6_PD_PREFIX]
        id_filter = {'id': router_subnets}
        subnets = self._core_plugin.get_subnets(context.elevated(),
                                                filters=id_filter)
        for sub in subnets:
            cidr = sub['cidr']
            ipnet = netaddr.IPNetwork(cidr)
            for s in new_subnets:
                new_cidr = s['cidr']
                new_ipnet = netaddr.IPNetwork(new_cidr)
                match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                match2 = netaddr.all_matching_cidrs(ipnet, [new_cidr])
                if match1 or match2:
                    data = {'subnet_cidr': new_cidr,
                            'subnet_id': s['id'],
                            'cidr': cidr,
                            'sub_id': sub['id']}
                    msg = (_("Cidr %(subnet_cidr)s of subnet "
                             "%(subnet_id)s overlaps with cidr %(cidr)s "
                             "of subnet %(sub_id)s") % data)
                    raise n_exc.BadRequest(resource='router', msg=msg)

    def _get_device_owner(self, context, router=None):
        """Get device_owner for the specified router."""
        # NOTE(armando-migliaccio): in the base case this is invariant
        return DEVICE_OWNER_ROUTER_INTF

    def _validate_interface_info(self, interface_info, for_removal=False):
        port_id_specified = interface_info and 'port_id' in interface_info
        subnet_id_specified = interface_info and 'subnet_id' in interface_info
        if not (port_id_specified or subnet_id_specified):
            msg = _("Either subnet_id or port_id must be specified")
            raise n_exc.BadRequest(resource='router', msg=msg)
        for key in ('port_id', 'subnet_id'):
            if key not in interface_info:
                continue
            err = validators.validate_uuid(interface_info[key])
            if err:
                raise n_exc.BadRequest(resource='router', msg=err)
        if not for_removal:
            if port_id_specified and subnet_id_specified:
                msg = _("Cannot specify both subnet-id and port-id")
                raise n_exc.BadRequest(resource='router', msg=msg)
        return port_id_specified, subnet_id_specified

    def _check_router_port(self, context, port_id, device_id):
        port = self._core_plugin.get_port(context, port_id)
        if port['device_id'] != device_id:
            raise n_exc.PortInUse(net_id=port['network_id'],
                                  port_id=port['id'],
                                  device_id=port['device_id'])
        if not port['fixed_ips']:
            msg = _('Router port must have at least one fixed IP')
            raise n_exc.BadRequest(resource='router', msg=msg)
        return port

    def _add_interface_by_port(self, context, router, port_id, owner):
        # Update owner before actual process in order to avoid the
        # case where a port might get attached to a router without the
        # owner successfully updating due to an unavailable backend.
        self._check_router_port(context, port_id, '')
        self._core_plugin.update_port(
            context, port_id, {'port': {'device_id': router.id,
                                        'device_owner': owner}})

        with context.session.begin(subtransactions=True):
            # check again within transaction to mitigate race
            port = self._check_router_port(context, port_id, router.id)

            # Only allow one router port with IPv6 subnets per network id
            if self._port_has_ipv6_address(port):
                for existing_port in (rp.port for rp in router.attached_ports):
                    if (existing_port['network_id'] == port['network_id'] and
                            self._port_has_ipv6_address(existing_port)):
                        msg = _("Cannot have multiple router ports with the "
                                "same network id if both contain IPv6 "
                                "subnets. Existing port %(p)s has IPv6 "
                                "subnet(s) and network id %(nid)s")
                        raise n_exc.BadRequest(resource='router', msg=msg % {
                            'p': existing_port['id'],
                            'nid': existing_port['network_id']})

            fixed_ips = [ip for ip in port['fixed_ips']]
            subnets = []
            for fixed_ip in fixed_ips:
                subnet = self._core_plugin.get_subnet(context,
                                                      fixed_ip['subnet_id'])
                subnets.append(subnet)

            if subnets:
                self._check_for_dup_router_subnets(context, router,
                                                   port['network_id'],
                                                   subnets)

            # Keep the restriction against multiple IPv4 subnets
            if len([s for s in subnets if s['ip_version'] == 4]) > 1:
                msg = _("Cannot have multiple "
                        "IPv4 subnets on router port")
                raise n_exc.BadRequest(resource='router', msg=msg)
            return port, subnets

    def _port_has_ipv6_address(self, port):
        for fixed_ip in port['fixed_ips']:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 6:
                return True

    def _find_ipv6_router_port_by_network(self, router, net_id):
        for port in router.attached_ports:
            p = port['port']
            if p['network_id'] == net_id and self._port_has_ipv6_address(p):
                return port

    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        if not subnet['gateway_ip']:
            msg = _('Subnet for router interface must have a gateway IP')
            raise n_exc.BadRequest(resource='router', msg=msg)
        if (subnet['ip_version'] == 6 and subnet['ipv6_ra_mode'] is None
                and subnet['ipv6_address_mode'] is not None):
            msg = (_('IPv6 subnet %s configured to receive RAs from an '
                   'external router cannot be added to Neutron Router.') %
                   subnet['id'])
            raise n_exc.BadRequest(resource='router', msg=msg)
        self._check_for_dup_router_subnets(context, router,
                                           subnet['network_id'], [subnet])
        fixed_ip = {'ip_address': subnet['gateway_ip'],
                    'subnet_id': subnet['id']}

        if (subnet['ip_version'] == 6 and not
            ipv6_utils.is_ipv6_pd_enabled(subnet)):
            # Add new prefix to an existing ipv6 port with the same network id
            # if one exists
            port = self._find_ipv6_router_port_by_network(router,
                                                          subnet['network_id'])
            if port:
                fixed_ips = list(port['port']['fixed_ips'])
                fixed_ips.append(fixed_ip)
                return self._core_plugin.update_port(context,
                        port['port_id'], {'port':
                            {'fixed_ips': fixed_ips}}), [subnet], False

        port_data = {'tenant_id': subnet['tenant_id'],
                     'network_id': subnet['network_id'],
                     'fixed_ips': [fixed_ip],
                     'admin_state_up': True,
                     'device_id': router.id,
                     'device_owner': owner,
                     'name': ''}
        return p_utils.create_port(self._core_plugin, context,
                                   {'port': port_data}), [subnet], True

    @staticmethod
    def _make_router_interface_info(
            router_id, tenant_id, port_id, network_id, subnet_id, subnet_ids):
        return {
            'id': router_id,
            'tenant_id': tenant_id,
            'port_id': port_id,
            'network_id': network_id,
            'subnet_id': subnet_id,  # deprecated by IPv6 multi-prefix
            'subnet_ids': subnet_ids
        }

    def add_router_interface(self, context, router_id, interface_info):
        router = self._get_router(context, router_id)
        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        device_owner = self._get_device_owner(context, router_id)

        # This should be True unless adding an IPv6 prefix to an existing port
        new_port = True

        if add_by_port:
            port, subnets = self._add_interface_by_port(
                    context, router, interface_info['port_id'], device_owner)
        # add_by_subnet is not used here, because the validation logic of
        # _validate_interface_info ensures that either of add_by_* is True.
        else:
            port, subnets, new_port = self._add_interface_by_subnet(
                    context, router, interface_info['subnet_id'], device_owner)

        if new_port:
            with context.session.begin(subtransactions=True):
                router_port = RouterPort(
                    port_id=port['id'],
                    router_id=router.id,
                    port_type=device_owner
                )
                context.session.add(router_port)

        gw_ips = []
        gw_network_id = None
        if router.gw_port:
            gw_network_id = router.gw_port.network_id
            gw_ips = router.gw_port.fixed_ips

        registry.notify(resources.ROUTER_INTERFACE,
                        events.AFTER_CREATE,
                        self,
                        context=context,
                        network_id=gw_network_id,
                        gateway_ips=gw_ips,
                        cidrs=[x['cidr'] for x in subnets],
                        port_id=port['id'],
                        router_id=router_id,
                        port=port,
                        interface_info=interface_info)

        return self._make_router_interface_info(
            router.id, port['tenant_id'], port['id'], port['network_id'],
            subnets[-1]['id'], [subnet['id'] for subnet in subnets])

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet['cidr'])
        fip_qry = context.session.query(FloatingIP)
        try:
            kwargs = {'context': context, 'subnet_id': subnet_id}
            registry.notify(
                resources.ROUTER_INTERFACE,
                events.BEFORE_DELETE, self, **kwargs)
        except exceptions.CallbackFailure as e:
            with excutils.save_and_reraise_exception():
                # NOTE(armax): preserve old check's behavior
                if len(e.errors) == 1:
                    raise e.errors[0].error
                raise l3.RouterInUse(router_id=router_id, reason=e)
        for fip_db in fip_qry.filter_by(router_id=router_id):
            if netaddr.IPAddress(fip_db['fixed_ip_address']) in subnet_cidr:
                raise l3.RouterInterfaceInUseByFloatingIP(
                    router_id=router_id, subnet_id=subnet_id)

    def _remove_interface_by_port(self, context, router_id,
                                  port_id, subnet_id, owner):
        qry = context.session.query(RouterPort)
        qry = qry.filter_by(
            port_id=port_id,
            router_id=router_id,
            port_type=owner
        )
        try:
            port_db = qry.one().port
        except exc.NoResultFound:
            raise l3.RouterInterfaceNotFound(router_id=router_id,
                                             port_id=port_id)
        port_subnet_ids = [fixed_ip['subnet_id']
                           for fixed_ip in port_db['fixed_ips']]
        if subnet_id and subnet_id not in port_subnet_ids:
            raise n_exc.SubnetMismatchForPort(
                port_id=port_id, subnet_id=subnet_id)
        subnets = [self._core_plugin.get_subnet(context, port_subnet_id)
                   for port_subnet_id in port_subnet_ids]
        for port_subnet_id in port_subnet_ids:
            self._confirm_router_interface_not_in_use(
                    context, router_id, port_subnet_id)
        self._core_plugin.delete_port(context, port_db['id'],
                                      l3_port_check=False)
        return (port_db, subnets)

    def _remove_interface_by_subnet(self, context,
                                    router_id, subnet_id, owner):
        self._confirm_router_interface_not_in_use(
            context, router_id, subnet_id)
        subnet = self._core_plugin.get_subnet(context, subnet_id)

        try:
            rport_qry = context.session.query(models_v2.Port).join(RouterPort)
            ports = rport_qry.filter(
                RouterPort.router_id == router_id,
                RouterPort.port_type == owner,
                models_v2.Port.network_id == subnet['network_id']
            )

            for p in ports:
                port_subnets = [fip['subnet_id'] for fip in p['fixed_ips']]
                if subnet_id in port_subnets and len(port_subnets) > 1:
                    # multiple prefix port - delete prefix from port
                    fixed_ips = [fip for fip in p['fixed_ips'] if
                            fip['subnet_id'] != subnet_id]
                    self._core_plugin.update_port(context, p['id'],
                            {'port':
                                {'fixed_ips': fixed_ips}})
                    return (p, [subnet])
                elif subnet_id in port_subnets:
                    # only one subnet on port - delete the port
                    self._core_plugin.delete_port(context, p['id'],
                                                  l3_port_check=False)
                    return (p, [subnet])
        except exc.NoResultFound:
            pass
        raise l3.RouterInterfaceNotFoundForSubnet(router_id=router_id,
                                                  subnet_id=subnet_id)

    def remove_router_interface(self, context, router_id, interface_info):
        remove_by_port, remove_by_subnet = (
            self._validate_interface_info(interface_info, for_removal=True)
        )
        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')
        device_owner = self._get_device_owner(context, router_id)
        if remove_by_port:
            port, subnets = self._remove_interface_by_port(context, router_id,
                                                           port_id, subnet_id,
                                                           device_owner)
        # remove_by_subnet is not used here, because the validation logic of
        # _validate_interface_info ensures that at least one of remote_by_*
        # is True.
        else:
            port, subnets = self._remove_interface_by_subnet(
                    context, router_id, subnet_id, device_owner)

        gw_network_id = None
        gw_ips = []
        router = self._get_router(context, router_id)
        if router.gw_port:
            gw_network_id = router.gw_port.network_id
            gw_ips = [x['ip_address'] for x in router.gw_port.fixed_ips]

        registry.notify(resources.ROUTER_INTERFACE,
                        events.AFTER_DELETE,
                        self,
                        context=context,
                        cidrs=[x['cidr'] for x in subnets],
                        network_id=gw_network_id,
                        gateway_ips=gw_ips,
                        port=port)
        return self._make_router_interface_info(router_id, port['tenant_id'],
                                                port['id'], port['network_id'],
                                                subnets[0]['id'],
                                                [subnet['id'] for subnet in
                                                    subnets])

    def _get_floatingip(self, context, id):
        try:
            floatingip = self._get_by_id(context, FloatingIP, id)
        except exc.NoResultFound:
            raise l3.FloatingIPNotFound(floatingip_id=id)
        return floatingip

    def _make_floatingip_dict(self, floatingip, fields=None,
                              process_extensions=True):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address'],
               'status': floatingip['status']}
        # NOTE(mlavalle): The following assumes this mixin is used in a
        # class inheriting from CommonDbMixin, which is true for all existing
        # plugins.
        if process_extensions:
            self._apply_dict_extend_functions(l3.FLOATINGIPS, res, floatingip)
        return self._fields(res, fields)

    def _get_router_for_floatingip(self, context, internal_port,
                                   internal_subnet_id,
                                   external_network_id):
        subnet = self._core_plugin.get_subnet(context, internal_subnet_id)
        if not subnet['gateway_ip']:
            msg = (_('Cannot add floating IP to port on subnet %s '
                     'which has no gateway_ip') % internal_subnet_id)
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        # Find routers(with router_id and interface address) that
        # connect given internal subnet and the external network.
        # Among them, if the router's interface address matches
        # with subnet's gateway-ip, return that router.
        # Otherwise return the first router.
        gw_port = orm.aliased(models_v2.Port, name="gw_port")
        routerport_qry = context.session.query(
            RouterPort.router_id, models_v2.IPAllocation.ip_address).join(
            models_v2.Port, models_v2.IPAllocation).filter(
            models_v2.Port.network_id == internal_port['network_id'],
            RouterPort.port_type.in_(l3_constants.ROUTER_INTERFACE_OWNERS),
            models_v2.IPAllocation.subnet_id == internal_subnet_id
        ).join(gw_port, gw_port.device_id == RouterPort.router_id).filter(
            gw_port.network_id == external_network_id).distinct()

        first_router_id = None
        for router_id, interface_ip in routerport_qry:
            if interface_ip == subnet['gateway_ip']:
                return router_id
            if not first_router_id:
                first_router_id = router_id
        if first_router_id:
            return first_router_id

        raise l3.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet_id,
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def _port_ipv4_fixed_ips(self, port):
        return [ip for ip in port['fixed_ips']
                if netaddr.IPAddress(ip['ip_address']).version == 4]

    def _internal_fip_assoc_data(self, context, fip):
        """Retrieve internal port data for floating IP.

        Retrieve information concerning the internal port where
        the floating IP should be associated to.
        """
        internal_port = self._core_plugin.get_port(context, fip['port_id'])
        if not internal_port['tenant_id'] == fip['tenant_id']:
            port_id = fip['port_id']
            if 'id' in fip:
                floatingip_id = fip['id']
                data = {'port_id': port_id,
                        'floatingip_id': floatingip_id}
                msg = (_('Port %(port_id)s is associated with a different '
                         'tenant than Floating IP %(floatingip_id)s and '
                         'therefore cannot be bound.') % data)
            else:
                msg = (_('Cannot create floating IP and bind it to '
                         'Port %s, since that port is owned by a '
                         'different tenant.') % port_id)
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        internal_subnet_id = None
        if fip.get('fixed_ip_address'):
            internal_ip_address = fip['fixed_ip_address']
            if netaddr.IPAddress(internal_ip_address).version != 4:
                if 'id' in fip:
                    data = {'floatingip_id': fip['id'],
                            'internal_ip': internal_ip_address}
                    msg = (_('Floating IP %(floatingip_id)s is associated '
                             'with non-IPv4 address %s(internal_ip)s and '
                             'therefore cannot be bound.') % data)
                else:
                    msg = (_('Cannot create floating IP and bind it to %s, '
                             'since that is not an IPv4 address.') %
                           internal_ip_address)
                raise n_exc.BadRequest(resource='floatingip', msg=msg)
            for ip in internal_port['fixed_ips']:
                if ip['ip_address'] == internal_ip_address:
                    internal_subnet_id = ip['subnet_id']
            if not internal_subnet_id:
                msg = (_('Port %(id)s does not have fixed ip %(address)s') %
                       {'id': internal_port['id'],
                        'address': internal_ip_address})
                raise n_exc.BadRequest(resource='floatingip', msg=msg)
        else:
            ipv4_fixed_ips = self._port_ipv4_fixed_ips(internal_port)
            if not ipv4_fixed_ips:
                msg = (_('Cannot add floating IP to port %s that has '
                         'no fixed IPv4 addresses') % internal_port['id'])
                raise n_exc.BadRequest(resource='floatingip', msg=msg)
            if len(ipv4_fixed_ips) > 1:
                msg = (_('Port %s has multiple fixed IPv4 addresses.  Must '
                         'provide a specific IPv4 address when assigning a '
                         'floating IP') % internal_port['id'])
                raise n_exc.BadRequest(resource='floatingip', msg=msg)
            internal_ip_address = ipv4_fixed_ips[0]['ip_address']
            internal_subnet_id = ipv4_fixed_ips[0]['subnet_id']
        return internal_port, internal_subnet_id, internal_ip_address

    def _get_assoc_data(self, context, fip, floating_network_id):
        """Determine/extract data associated with the internal port.

        When a floating IP is associated with an internal port,
        we need to extract/determine some data associated with the
        internal port, including the internal_ip_address, and router_id.
        The confirmation of the internal port whether owned by the tenant who
        owns the floating IP will be confirmed by _get_router_for_floatingip.
        """
        (internal_port, internal_subnet_id,
         internal_ip_address) = self._internal_fip_assoc_data(context, fip)
        router_id = self._get_router_for_floatingip(context,
                                                    internal_port,
                                                    internal_subnet_id,
                                                    floating_network_id)

        return (fip['port_id'], internal_ip_address, router_id)

    def _check_and_get_fip_assoc(self, context, fip, floatingip_db):
        port_id = internal_ip_address = router_id = None
        if fip.get('fixed_ip_address') and not fip.get('port_id'):
            msg = _("fixed_ip_address cannot be specified without a port_id")
            raise n_exc.BadRequest(resource='floatingip', msg=msg)
        if fip.get('port_id'):
            port_id, internal_ip_address, router_id = self._get_assoc_data(
                context,
                fip,
                floatingip_db['floating_network_id'])
            fip_qry = context.session.query(FloatingIP)
            try:
                fip_qry.filter_by(
                    fixed_port_id=fip['port_id'],
                    floating_network_id=floatingip_db['floating_network_id'],
                    fixed_ip_address=internal_ip_address).one()
                raise l3.FloatingIPPortAlreadyAssociated(
                    port_id=fip['port_id'],
                    fip_id=floatingip_db['id'],
                    floating_ip_address=floatingip_db['floating_ip_address'],
                    fixed_ip=internal_ip_address,
                    net_id=floatingip_db['floating_network_id'])
            except exc.NoResultFound:
                pass
        return port_id, internal_ip_address, router_id

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        previous_router_id = floatingip_db.router_id
        port_id, internal_ip_address, router_id = (
            self._check_and_get_fip_assoc(context, fip, floatingip_db))
        update = {'fixed_ip_address': internal_ip_address,
                  'fixed_port_id': port_id,
                  'router_id': router_id,
                  'last_known_router_id': previous_router_id}
        if 'description' in fip:
            update['description'] = fip['description']
        floatingip_db.update(update)
        next_hop = None
        if router_id:
            # NOTE(tidwellr) use admin context here
            # tenant may not own the router and that's OK on a FIP association
            router = self._get_router(context.elevated(), router_id)
            gw_port = router.gw_port
            for fixed_ip in gw_port.fixed_ips:
                addr = netaddr.IPAddress(fixed_ip.ip_address)
                if addr.version == l3_constants.IP_VERSION_4:
                    next_hop = fixed_ip.ip_address
                    break
        args = {'fixed_ip_address': internal_ip_address,
                'fixed_port_id': port_id,
                'router_id': router_id,
                'last_known_router_id': previous_router_id,
                'floating_ip_address': floatingip_db.floating_ip_address,
                'floating_network_id': floatingip_db.floating_network_id,
                'next_hop': next_hop,
                'context': context}
        registry.notify(resources.FLOATING_IP,
                        events.AFTER_UPDATE,
                        self._update_fip_assoc,
                        **args)

    def _is_ipv4_network(self, context, net_id):
        net = self._core_plugin._get_network(context, net_id)
        return any(s.ip_version == 4 for s in net.subnets)

    def _create_floatingip(self, context, floatingip,
            initial_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        fip = floatingip['floatingip']
        fip_id = uuidutils.generate_uuid()

        f_net_id = fip['floating_network_id']
        if not self._core_plugin._network_is_external(context, f_net_id):
            msg = _("Network %s is not a valid external network") % f_net_id
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        if not self._is_ipv4_network(context, f_net_id):
            msg = _("Network %s does not contain any IPv4 subnet") % f_net_id
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        dns_integration = utils.is_extension_supported(self._core_plugin,
                                                       'dns-integration')
        with context.session.begin(subtransactions=True):
            # This external port is never exposed to the tenant.
            # it is used purely for internal system and admin use when
            # managing floating IPs.

            port = {'tenant_id': '',  # tenant intentionally not set
                    'network_id': f_net_id,
                    'admin_state_up': True,
                    'device_id': fip_id,
                    'device_owner': DEVICE_OWNER_FLOATINGIP,
                    'status': l3_constants.PORT_STATUS_NOTAPPLICABLE,
                    'name': ''}
            if fip.get('floating_ip_address'):
                port['fixed_ips'] = [
                    {'ip_address': fip['floating_ip_address']}]

            if fip.get('subnet_id'):
                port['fixed_ips'] = [
                    {'subnet_id': fip['subnet_id']}]

            # 'status' in port dict could not be updated by default, use
            # check_allow_post to stop the verification of system
            external_port = p_utils.create_port(self._core_plugin,
                                                context.elevated(),
                                                {'port': port},
                                                check_allow_post=False)
            # Ensure IPv4 addresses are allocated on external port
            external_ipv4_ips = self._port_ipv4_fixed_ips(external_port)
            if not external_ipv4_ips:
                raise n_exc.ExternalIpAddressExhausted(net_id=f_net_id)

            floating_fixed_ip = external_ipv4_ips[0]
            floating_ip_address = floating_fixed_ip['ip_address']
            floatingip_db = FloatingIP(
                id=fip_id,
                tenant_id=fip['tenant_id'],
                status=initial_status,
                floating_network_id=fip['floating_network_id'],
                floating_ip_address=floating_ip_address,
                floating_port_id=external_port['id'],
                description=fip.get('description'))
            # Update association with internal port
            # and define external IP address
            self._update_fip_assoc(context, fip,
                                   floatingip_db, external_port)
            context.session.add(floatingip_db)
            floatingip_dict = self._make_floatingip_dict(
                floatingip_db, process_extensions=False)
            if dns_integration:
                dns_data = self._process_dns_floatingip_create_precommit(
                    context, floatingip_dict, fip)

        if dns_integration:
            self._process_dns_floatingip_create_postcommit(context,
                                                           floatingip_dict,
                                                           dns_data)
        self._apply_dict_extend_functions(l3.FLOATINGIPS, floatingip_dict,
                                          floatingip_db)
        return floatingip_dict

    def create_floatingip(self, context, floatingip,
            initial_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        return self._create_floatingip(context, floatingip, initial_status)

    def _update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        dns_integration = utils.is_extension_supported(self._core_plugin,
                                                       'dns-integration')
        with context.session.begin(subtransactions=True):
            floatingip_db = self._get_floatingip(context, id)
            old_floatingip = self._make_floatingip_dict(floatingip_db)
            fip['tenant_id'] = floatingip_db['tenant_id']
            fip['id'] = id
            fip_port_id = floatingip_db['floating_port_id']
            self._update_fip_assoc(context, fip, floatingip_db,
                                   self._core_plugin.get_port(
                                       context.elevated(), fip_port_id))
            floatingip_dict = self._make_floatingip_dict(floatingip_db)
            if dns_integration:
                dns_data = self._process_dns_floatingip_update_precommit(
                    context, floatingip_dict)
        if dns_integration:
            self._process_dns_floatingip_update_postcommit(context,
                                                           floatingip_dict,
                                                           dns_data)
        return old_floatingip, floatingip_dict

    def _floatingips_to_router_ids(self, floatingips):
        return list(set([floatingip['router_id']
                         for floatingip in floatingips
                         if floatingip['router_id']]))

    def update_floatingip(self, context, id, floatingip):
        _old_floatingip, floatingip = self._update_floatingip(
            context, id, floatingip)
        return floatingip

    def update_floatingip_status(self, context, floatingip_id, status):
        """Update operational status for floating IP in neutron DB."""
        fip_query = self._model_query(context, FloatingIP).filter(
            FloatingIP.id == floatingip_id)
        fip_query.update({'status': status}, synchronize_session=False)

    def _delete_floatingip(self, context, id):
        floatingip = self._get_floatingip(context, id)
        floatingip_dict = self._make_floatingip_dict(floatingip)
        if utils.is_extension_supported(self._core_plugin, 'dns-integration'):
            self._process_dns_floatingip_delete(context, floatingip_dict)
        # Foreign key cascade will take care of the removal of the
        # floating IP record once the port is deleted. We can't start
        # a transaction first to remove it ourselves because the delete_port
        # method will yield in its post-commit activities.
        self._core_plugin.delete_port(context.elevated(),
                                      floatingip['floating_port_id'],
                                      l3_port_check=False)
        return floatingip_dict

    def delete_floatingip(self, context, id):
        self._delete_floatingip(context, id)

    def get_floatingip(self, context, id, fields=None):
        floatingip = self._get_floatingip(context, id)
        return self._make_floatingip_dict(floatingip, fields)

    def get_floatingips(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'floatingip', limit,
                                          marker)
        if filters is not None:
            for key, val in six.iteritems(API_TO_DB_COLUMN_MAP):
                if key in filters:
                    filters[val] = filters.pop(key)

        return self._get_collection(context, FloatingIP,
                                    self._make_floatingip_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def delete_disassociated_floatingips(self, context, network_id):
        query = self._model_query(context, FloatingIP)
        query = query.filter_by(floating_network_id=network_id,
                                fixed_port_id=None,
                                router_id=None)
        for fip in query:
            self.delete_floatingip(context, fip.id)

    def get_floatingips_count(self, context, filters=None):
        return self._get_collection_count(context, FloatingIP,
                                          filters=filters)

    def _router_exists(self, context, router_id):
        try:
            self.get_router(context.elevated(), router_id)
            return True
        except l3.RouterNotFound:
            return False

    def _floating_ip_exists(self, context, floating_ip_id):
        try:
            self.get_floatingip(context, floating_ip_id)
            return True
        except l3.FloatingIPNotFound:
            return False

    def prevent_l3_port_deletion(self, context, port_id):
        """Checks to make sure a port is allowed to be deleted.

        Raises an exception if this is not the case.  This should be called by
        any plugin when the API requests the deletion of a port, since some
        ports for L3 are not intended to be deleted directly via a DELETE
        to /ports, but rather via other API calls that perform the proper
        deletion checks.
        """
        try:
            port = self._core_plugin.get_port(context, port_id)
        except n_exc.PortNotFound:
            # non-existent ports don't need to be protected from deletion
            return
        if port['device_owner'] not in self.router_device_owners:
            return
        # Raise port in use only if the port has IP addresses
        # Otherwise it's a stale port that can be removed
        fixed_ips = port['fixed_ips']
        if not fixed_ips:
            LOG.debug("Port %(port_id)s has owner %(port_owner)s, but "
                      "no IP address, so it can be deleted",
                      {'port_id': port['id'],
                       'port_owner': port['device_owner']})
            return
        # NOTE(kevinbenton): we also check to make sure that the
        # router still exists. It's possible for HA router interfaces
        # to remain after the router is deleted if they encounter an
        # error during deletion.
        # Elevated context in case router is owned by another tenant
        if port['device_owner'] == DEVICE_OWNER_FLOATINGIP:
            if not self._floating_ip_exists(context, port['device_id']):
                LOG.debug("Floating IP %(f_id)s corresponding to port "
                          "%(port_id)s no longer exists, allowing deletion.",
                          {'f_id': port['device_id'], 'port_id': port['id']})
                return
        elif not self._router_exists(context, port['device_id']):
            LOG.debug("Router %(router_id)s corresponding to port "
                      "%(port_id)s  no longer exists, allowing deletion.",
                      {'router_id': port['device_id'],
                       'port_id': port['id']})
            return

        reason = _('has device owner %s') % port['device_owner']
        raise n_exc.ServicePortInUse(port_id=port['id'],
                                     reason=reason)

    def disassociate_floatingips(self, context, port_id):
        """Disassociate all floating IPs linked to specific port.

        @param port_id: ID of the port to disassociate floating IPs.
        @param do_notify: whether we should notify routers right away.
        @return: set of router-ids that require notification updates
                 if do_notify is False, otherwise None.
        """
        router_ids = set()

        with context.session.begin(subtransactions=True):
            fip_qry = context.session.query(FloatingIP)
            floating_ips = fip_qry.filter_by(fixed_port_id=port_id)
            for floating_ip in floating_ips:
                router_ids.add(floating_ip['router_id'])
                floating_ip.update({'fixed_port_id': None,
                                    'fixed_ip_address': None,
                                    'router_id': None})
        return router_ids

    def _build_routers_list(self, context, routers, gw_ports):
        """Subclasses can override this to add extra gateway info"""
        return routers

    def _make_router_dict_with_gw_port(self, router, fields):
        result = self._make_router_dict(router, fields)
        if router.get('gw_port'):
            result['gw_port'] = self._core_plugin._make_port_dict(
                router['gw_port'], None)
        return result

    def _get_sync_routers(self, context, router_ids=None, active=None):
        """Query routers and their gw ports for l3 agent.

        Query routers with the router_ids. The gateway ports, if any,
        will be queried too.
        l3 agent has an option to deal with only one router id. In addition,
        when we need to notify the agent the data about only one router
        (when modification of router, its interfaces, gw_port and floatingips),
        we will have router_ids.
        @param router_ids: the list of router ids which we want to query.
                           if it is None, all of routers will be queried.
        @return: a list of dicted routers with dicted gw_port populated if any
        """
        filters = {'id': router_ids} if router_ids else {}
        if active is not None:
            filters['admin_state_up'] = [active]
        router_dicts = self._get_collection(
            context, Router, self._make_router_dict_with_gw_port,
            filters=filters)
        if not router_dicts:
            return []
        gw_ports = dict((r['gw_port']['id'], r['gw_port'])
                        for r in router_dicts
                        if r.get('gw_port'))
        return self._build_routers_list(context, router_dicts, gw_ports)

    @staticmethod
    def _unique_floatingip_iterator(query):
        """Iterates over only one row per floating ip.  Ignores others."""
        # Group rows by fip id.  They must be sorted by same.
        q = query.order_by(FloatingIP.id)
        keyfunc = lambda row: row[0]['id']
        group_iterator = itertools.groupby(q, keyfunc)

        # Just hit the first row of each group
        for key, value in group_iterator:
            yield six.next(value)

    def _make_floatingip_dict_with_scope(self, floatingip_db, scope_id):
        d = self._make_floatingip_dict(floatingip_db)
        d['fixed_ip_address_scope'] = scope_id
        return d

    def _get_sync_floating_ips(self, context, router_ids):
        """Query floating_ips that relate to list of router_ids with scope.

        This is different than the regular get_floatingips in that it finds the
        address scope of the fixed IP.  The router needs to know this to
        distinguish it from other scopes.

        There are a few redirections to go through to discover the address
        scope from the floating ip.
        """
        if not router_ids:
            return []

        query = context.session.query(FloatingIP,
                                      models_v2.SubnetPool.address_scope_id)
        query = query.join(models_v2.Port,
            FloatingIP.fixed_port_id == models_v2.Port.id)
        # Outer join of Subnet can cause each ip to have more than one row.
        query = query.outerjoin(models_v2.Subnet,
            models_v2.Subnet.network_id == models_v2.Port.network_id)
        query = query.filter(models_v2.Subnet.ip_version == 4)
        query = query.outerjoin(models_v2.SubnetPool,
            models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)

        # Filter out on router_ids
        query = query.filter(FloatingIP.router_id.in_(router_ids))

        return [self._make_floatingip_dict_with_scope(*row)
                for row in self._unique_floatingip_iterator(query)]

    def _get_sync_interfaces(self, context, router_ids, device_owners=None):
        """Query router interfaces that relate to list of router_ids."""
        device_owners = device_owners or [DEVICE_OWNER_ROUTER_INTF,
                                          DEVICE_OWNER_HA_REPLICATED_INT]
        if not router_ids:
            return []
        qry = context.session.query(RouterPort)
        qry = qry.filter(
            RouterPort.router_id.in_(router_ids),
            RouterPort.port_type.in_(device_owners)
        )

        interfaces = [self._core_plugin._make_port_dict(rp.port, None)
                      for rp in qry]
        return interfaces

    @staticmethod
    def _each_port_having_fixed_ips(ports):
        for port in ports or []:
            fixed_ips = port.get('fixed_ips', [])
            if not fixed_ips:
                # Skip ports without IPs, which can occur if a subnet
                # attached to a router is deleted
                LOG.info(_LI("Skipping port %s as no IP is configure on "
                             "it"),
                         port['id'])
                continue
            yield port

    def _get_subnets_by_network_list(self, context, network_ids):
        if not network_ids:
            return {}

        query = context.session.query(models_v2.Subnet,
                                      models_v2.SubnetPool.address_scope_id)
        query = query.outerjoin(
            models_v2.SubnetPool,
            models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)
        query = query.filter(models_v2.Subnet.network_id.in_(network_ids))

        fields = ['id', 'cidr', 'gateway_ip', 'dns_nameservers',
                  'network_id', 'ipv6_ra_mode', 'subnetpool_id']

        def make_subnet_dict_with_scope(row):
            subnet_db, address_scope_id = row
            subnet = self._core_plugin._make_subnet_dict(
                subnet_db, fields, context=context)
            subnet['address_scope_id'] = address_scope_id
            return subnet

        subnets_by_network = dict((id, []) for id in network_ids)
        for subnet in (make_subnet_dict_with_scope(row) for row in query):
            subnets_by_network[subnet['network_id']].append(subnet)
        return subnets_by_network

    def _get_mtus_by_network_list(self, context, network_ids):
        if not network_ids:
            return {}
        filters = {'network_id': network_ids}
        fields = ['id', 'mtu']
        networks = self._core_plugin.get_networks(context, filters=filters,
                                                  fields=fields)
        mtus_by_network = dict((network['id'], network.get('mtu', 0))
                               for network in networks)
        return mtus_by_network

    def _populate_mtu_and_subnets_for_ports(self, context, ports):
        """Populate ports with subnets.

        These ports already have fixed_ips populated.
        """
        network_ids = [p['network_id']
                       for p in self._each_port_having_fixed_ips(ports)]

        mtus_by_network = self._get_mtus_by_network_list(context, network_ids)
        subnets_by_network = self._get_subnets_by_network_list(
            context, network_ids)

        for port in self._each_port_having_fixed_ips(ports):

            port['subnets'] = []
            port['extra_subnets'] = []
            port['address_scopes'] = {l3_constants.IP_VERSION_4: None,
                                      l3_constants.IP_VERSION_6: None}

            scopes = {}
            for subnet in subnets_by_network[port['network_id']]:
                scope = subnet['address_scope_id']
                cidr = netaddr.IPNetwork(subnet['cidr'])
                scopes[cidr.version] = scope

                # If this subnet is used by the port (has a matching entry
                # in the port's fixed_ips), then add this subnet to the
                # port's subnets list, and populate the fixed_ips entry
                # entry with the subnet's prefix length.
                subnet_info = {'id': subnet['id'],
                               'cidr': subnet['cidr'],
                               'gateway_ip': subnet['gateway_ip'],
                               'dns_nameservers': subnet['dns_nameservers'],
                               'ipv6_ra_mode': subnet['ipv6_ra_mode'],
                               'subnetpool_id': subnet['subnetpool_id']}
                for fixed_ip in port['fixed_ips']:
                    if fixed_ip['subnet_id'] == subnet['id']:
                        port['subnets'].append(subnet_info)
                        prefixlen = cidr.prefixlen
                        fixed_ip['prefixlen'] = prefixlen
                        break
                else:
                    # This subnet is not used by the port.
                    port['extra_subnets'].append(subnet_info)

            port['address_scopes'].update(scopes)
            port['mtu'] = mtus_by_network.get(port['network_id'], 0)

    def _process_floating_ips(self, context, routers_dict, floating_ips):
        for floating_ip in floating_ips:
            router = routers_dict.get(floating_ip['router_id'])
            if router:
                router_floatingips = router.get(l3_constants.FLOATINGIP_KEY,
                                                [])
                router_floatingips.append(floating_ip)
                router[l3_constants.FLOATINGIP_KEY] = router_floatingips

    def _process_interfaces(self, routers_dict, interfaces):
        for interface in interfaces:
            router = routers_dict.get(interface['device_id'])
            if router:
                router_interfaces = router.get(l3_constants.INTERFACE_KEY, [])
                router_interfaces.append(interface)
                router[l3_constants.INTERFACE_KEY] = router_interfaces

    def _get_router_info_list(self, context, router_ids=None, active=None,
                              device_owners=None):
        """Query routers and their related floating_ips, interfaces."""
        with context.session.begin(subtransactions=True):
            routers = self._get_sync_routers(context,
                                             router_ids=router_ids,
                                             active=active)
            router_ids = [router['id'] for router in routers]
            interfaces = self._get_sync_interfaces(
                context, router_ids, device_owners)
            floating_ips = self._get_sync_floating_ips(context, router_ids)
            return (routers, interfaces, floating_ips)

    def get_sync_data(self, context, router_ids=None, active=None):
        routers, interfaces, floating_ips = self._get_router_info_list(
            context, router_ids=router_ids, active=active)
        ports_to_populate = [router['gw_port'] for router in routers
                             if router.get('gw_port')] + interfaces
        self._populate_mtu_and_subnets_for_ports(context, ports_to_populate)
        routers_dict = dict((router['id'], router) for router in routers)
        self._process_floating_ips(context, routers_dict, floating_ips)
        self._process_interfaces(routers_dict, interfaces)
        return list(routers_dict.values())


class L3RpcNotifierMixin(object):
    """Mixin class to add rpc notifier attribute to db_base_plugin_v2."""

    @property
    def l3_rpc_notifier(self):
        if not hasattr(self, '_l3_rpc_notifier'):
            self._l3_rpc_notifier = l3_rpc_agent_api.L3AgentNotifyAPI()
        return self._l3_rpc_notifier

    @l3_rpc_notifier.setter
    def l3_rpc_notifier(self, value):
        self._l3_rpc_notifier = value

    def notify_router_updated(self, context, router_id,
                              operation=None):
        if router_id:
            self.l3_rpc_notifier.routers_updated(
                context, [router_id], operation)

    def notify_routers_updated(self, context, router_ids,
                               operation=None, data=None):
        if router_ids:
            self.l3_rpc_notifier.routers_updated(
                context, router_ids, operation, data)

    def notify_router_deleted(self, context, router_id):
        self.l3_rpc_notifier.router_deleted(context, router_id)


class L3_NAT_db_mixin(L3_NAT_dbonly_mixin, L3RpcNotifierMixin):
    """Mixin class to add rpc notifier methods to db_base_plugin_v2."""

    def create_router(self, context, router):
        router_dict = super(L3_NAT_db_mixin, self).create_router(context,
                                                                 router)
        if router_dict.get('external_gateway_info'):
            self.notify_router_updated(context, router_dict['id'], None)
        return router_dict

    def update_router(self, context, id, router):
        router_dict = super(L3_NAT_db_mixin, self).update_router(context,
                                                                 id, router)
        self.notify_router_updated(context, router_dict['id'], None)
        return router_dict

    def delete_router(self, context, id):
        super(L3_NAT_db_mixin, self).delete_router(context, id)
        self.notify_router_deleted(context, id)

    def notify_router_interface_action(
            self, context, router_interface_info, action):
        l3_method = '%s_router_interface' % action
        super(L3_NAT_db_mixin, self).notify_routers_updated(
            context, [router_interface_info['id']], l3_method,
            {'subnet_id': router_interface_info['subnet_id']})

        mapping = {'add': 'create', 'remove': 'delete'}
        notifier = n_rpc.get_notifier('network')
        router_event = 'router.interface.%s' % mapping[action]
        notifier.info(context, router_event,
                      {'router_interface': router_interface_info})

    def add_router_interface(self, context, router_id, interface_info):
        router_interface_info = super(
            L3_NAT_db_mixin, self).add_router_interface(
                context, router_id, interface_info)
        self.notify_router_interface_action(
            context, router_interface_info, 'add')
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = super(
            L3_NAT_db_mixin, self).remove_router_interface(
                context, router_id, interface_info)
        self.notify_router_interface_action(
            context, router_interface_info, 'remove')
        return router_interface_info

    def create_floatingip(self, context, floatingip,
            initial_status=l3_constants.FLOATINGIP_STATUS_ACTIVE):
        floatingip_dict = super(L3_NAT_db_mixin, self).create_floatingip(
            context, floatingip, initial_status)
        router_id = floatingip_dict['router_id']
        self.notify_router_updated(context, router_id, 'create_floatingip')
        return floatingip_dict

    def update_floatingip(self, context, id, floatingip):
        old_floatingip, floatingip = self._update_floatingip(
            context, id, floatingip)
        router_ids = self._floatingips_to_router_ids(
            [old_floatingip, floatingip])
        super(L3_NAT_db_mixin, self).notify_routers_updated(
            context, router_ids, 'update_floatingip', {})
        return floatingip

    def delete_floatingip(self, context, id):
        floating_ip = self._delete_floatingip(context, id)
        self.notify_router_updated(context, floating_ip['router_id'],
                                   'delete_floatingip')

    def disassociate_floatingips(self, context, port_id, do_notify=True):
        """Disassociate all floating IPs linked to specific port.

        @param port_id: ID of the port to disassociate floating IPs.
        @param do_notify: whether we should notify routers right away.
        @return: set of router-ids that require notification updates
                 if do_notify is False, otherwise None.
        """
        router_ids = super(L3_NAT_db_mixin, self).disassociate_floatingips(
            context, port_id)
        if do_notify:
            self.notify_routers_updated(context, router_ids)
            # since caller assumes that we handled notifications on its
            # behalf, return nothing
            return

        return router_ids

    def notify_routers_updated(self, context, router_ids):
        super(L3_NAT_db_mixin, self).notify_routers_updated(
            context, list(router_ids), 'disassociate_floatingips', {})


def _prevent_l3_port_delete_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    port_id = kwargs['port_id']
    port_check = kwargs['port_check']
    l3plugin = manager.NeutronManager.get_service_plugins().get(
        constants.L3_ROUTER_NAT)
    if l3plugin and port_check:
        l3plugin.prevent_l3_port_deletion(context, port_id)


def _notify_routers_callback(resource, event, trigger, **kwargs):
    context = kwargs['context']
    router_ids = kwargs['router_ids']
    l3plugin = manager.NeutronManager.get_service_plugins().get(
        constants.L3_ROUTER_NAT)
    l3plugin.notify_routers_updated(context, router_ids)


def _notify_subnet_gateway_ip_update(resource, event, trigger, **kwargs):
    l3plugin = manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)
    if not l3plugin:
        return
    context = kwargs['context']
    network_id = kwargs['network_id']
    subnet_id = kwargs['subnet_id']
    query = context.session.query(models_v2.Port).filter_by(
                network_id=network_id,
                device_owner=l3_constants.DEVICE_OWNER_ROUTER_GW)
    query = query.join(models_v2.Port.fixed_ips).filter(
                models_v2.IPAllocation.subnet_id == subnet_id)
    router_ids = set(port['device_id'] for port in query)
    for router_id in router_ids:
        l3plugin.notify_router_updated(context, router_id)


def _notify_subnetpool_address_scope_update(resource, event,
                                            trigger, **kwargs):
    context = kwargs['context']
    subnetpool_id = kwargs['subnetpool_id']

    query = context.session.query(RouterPort.router_id)
    query = query.join(models_v2.Port)
    query = query.join(
        models_v2.Subnet,
        models_v2.Subnet.network_id == models_v2.Port.network_id)
    query = query.filter(
        models_v2.Subnet.subnetpool_id == subnetpool_id,
        RouterPort.port_type.in_(n_const.ROUTER_PORT_OWNERS))
    query = query.distinct()

    router_ids = [r[0] for r in query]
    l3plugin = manager.NeutronManager.get_service_plugins().get(
        constants.L3_ROUTER_NAT)
    l3plugin.notify_routers_updated(context, router_ids)


def subscribe():
    registry.subscribe(
        _prevent_l3_port_delete_callback, resources.PORT, events.BEFORE_DELETE)
    registry.subscribe(
        _notify_routers_callback, resources.PORT, events.AFTER_DELETE)
    registry.subscribe(
        _notify_subnet_gateway_ip_update, resources.SUBNET_GATEWAY,
        events.AFTER_UPDATE)
    registry.subscribe(
        _notify_subnetpool_address_scope_update,
        resources.SUBNETPOOL_ADDRESS_SCOPE,
        events.AFTER_UPDATE)

# NOTE(armax): multiple l3 service plugins (potentially out of tree) inherit
# from l3_db and may need the callbacks to be processed. Having an implicit
# subscription (through the module import) preserves the existing behavior,
# and at the same time it avoids fixing it manually in each and every l3 plugin
# out there. That said, The subscription is also made explicit in the
# reference l3 plugin. The subscription operation is idempotent so there is no
# harm in registering the same callback multiple times.
subscribe()
