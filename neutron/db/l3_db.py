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

import functools
import itertools
import random

import netaddr
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import qos_fip as qos_fip_apidef
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as n_ctx
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as lib_db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as plugin_utils
from neutron_lib import rpc as n_rpc
from neutron_lib.services import base as base_services
from neutron_lib.services.qos import constants as qos_const
from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import ipv6_utils
from neutron.common import utils
from neutron.db import _utils as db_utils
from neutron.db import l3_attrs_db
from neutron.db.models import l3 as l3_models
from neutron.db.models import l3_attrs as l3_attrs_models
from neutron.db import models_v2
from neutron.db import rbac_db_models
from neutron.db import standardattrdescription_db as st_attr
from neutron.extensions import l3
from neutron.extensions import segment as segment_ext
from neutron.objects import base as base_obj
from neutron.objects import network as network_obj
from neutron.objects import port_forwarding
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj
from neutron.objects import subnet as subnet_obj
from neutron import worker as neutron_worker

LOG = logging.getLogger(__name__)


DEVICE_OWNER_HA_REPLICATED_INT = constants.DEVICE_OWNER_HA_REPLICATED_INT
DEVICE_OWNER_ROUTER_INTF = constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = constants.DEVICE_OWNER_FLOATINGIP
EXTERNAL_GW_INFO = l3_apidef.EXTERNAL_GW_INFO

# Maps API field to DB column
# API parameter name and Database column names may differ.
# Useful to keep the filtering between API and Database.
API_TO_DB_COLUMN_MAP = {'port_id': 'fixed_port_id'}
CORE_ROUTER_ATTRS = ('id', 'name', 'tenant_id', 'admin_state_up', 'status')
FIP_ASSOC_MSG = ('Floating IP %(fip_id)s %(assoc)s. External IP: %(ext_ip)s, '
                 'port: %(port_id)s.')


# TODO(froyo): Move this exception to neutron-lib as soon as possible, and when
# a new release is created and pointed to in the requirements remove this code.
class FipAssociated(n_exc.InUse):
    message = _('Unable to complete the operation on port "%(port_id)s" '
                'because the port still has an associated floating IP.')


@registry.has_registry_receivers
class L3_NAT_dbonly_mixin(l3.RouterPluginBase,
                          base_services.WorkerBase,
                          st_attr.StandardAttrDescriptionMixin):
    """Mixin class to add L3/NAT router methods to db_base_plugin_v2."""

    router_device_owners = (
        DEVICE_OWNER_HA_REPLICATED_INT,
        DEVICE_OWNER_ROUTER_INTF,
        DEVICE_OWNER_ROUTER_GW,
        DEVICE_OWNER_FLOATINGIP
    )

    _dns_integration = None

    _fip_qos = None

    def __new__(cls, *args, **kwargs):
        inst = super(L3_NAT_dbonly_mixin, cls).__new__(cls, *args, **kwargs)
        inst._start_janitor()
        return inst

    @staticmethod
    @registry.receives(resources.PORT, [events.BEFORE_DELETE])
    def _prevent_l3_port_delete_callback(resource, event,
                                         trigger, payload=None):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if l3plugin and payload.metadata['port_check']:
            l3plugin.prevent_l3_port_deletion(
                payload.context, payload.resource_id,
                port=payload.metadata.get('port'))

    @staticmethod
    @registry.receives(resources.PORT, [events.BEFORE_UPDATE])
    def _prevent_internal_ip_change_for_fip(resource, event,
                                            trigger, payload=None):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        new_port = payload.states[1]
        if (l3plugin and payload.metadata and
                payload.metadata.get('fixed_ips_updated', False)):
            l3plugin.prevent_internal_ip_change_for_fip(
                payload.context, payload.resource_id,
                new_port['fixed_ips'])

    @staticmethod
    def _validate_subnet_address_mode(subnet):
        if (subnet['ip_version'] == 6 and subnet['ipv6_ra_mode'] is None and
                subnet['ipv6_address_mode'] is not None):
            msg = (_('IPv6 subnet %s configured to receive RAs from an '
                     'external router cannot be added to Neutron Router.') %
                   subnet['id'])
            raise n_exc.BadRequest(resource='router', msg=msg)

    @property
    def _is_dns_integration_supported(self):
        if self._dns_integration is None:
            self._dns_integration = (
                extensions.is_extension_supported(
                    self._core_plugin, 'dns-integration') or
                extensions.is_extension_supported(
                    self._core_plugin, 'dns-domain-ports'))
        return self._dns_integration

    @property
    def _is_fip_qos_supported(self):
        if self._fip_qos is None:
            # Check L3 service plugin
            self._fip_qos = extensions.is_extension_supported(
                self, qos_fip_apidef.ALIAS)
        return self._fip_qos

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    def _start_janitor(self):
        """Starts the periodic job that cleans up broken complex resources.

        This job will look for things like floating IP ports without an
        associated floating IP and delete them 5 minutes after detection.
        """
        interval = 60 * 5  # only every 5 minutes. cleanups should be rare
        initial_delay = random.randint(0, interval)  # splay multiple servers
        janitor = neutron_worker.PeriodicWorker(self._clean_garbage, interval,
                                                initial_delay)
        self.add_worker(janitor)

    def _clean_garbage(self):
        if not hasattr(self, '_candidate_broken_fip_ports'):
            self._candidate_broken_fip_ports = set()
        context = n_ctx.get_admin_context()
        candidates = self._get_dead_floating_port_candidates(context)
        # just because a port is in 'candidates' doesn't necessarily mean
        # it's broken, we could have just caught it before it was updated.
        # We confirm by waiting until the next call of this function to see
        # if it persists.
        to_cleanup = candidates & self._candidate_broken_fip_ports
        self._candidate_broken_fip_ports = candidates - to_cleanup
        for port_id in to_cleanup:
            # ensure it wasn't just a failure to update device_id before we
            # delete it
            try:
                self._fix_or_kill_floating_port(context, port_id)
            except Exception:
                LOG.exception("Error cleaning up floating IP port: %s",
                              port_id)

    def _fix_or_kill_floating_port(self, context, port_id):
        pager = base_obj.Pager(limit=1)
        fips = l3_obj.FloatingIP.get_objects(
            context, _pager=pager, floating_port_id=port_id)
        if fips:
            LOG.warning("Found incorrect device_id on floating port "
                        "%(pid)s, correcting to %(fip)s.",
                        {'pid': port_id, 'fip': fips[0].id})
            self._core_plugin.update_port(
                context, port_id, {'port': {'device_id': fips[0].id}})
        else:
            LOG.warning("Found floating IP port %s without floating IP, "
                        "deleting.", port_id)
            self._core_plugin.delete_port(
                context, port_id, l3_port_check=False)

    def _get_dead_floating_port_candidates(self, context):
        filters = {'device_id': ['PENDING'],
                   'device_owner': [DEVICE_OWNER_FLOATINGIP]}
        return {p['id'] for p in self._core_plugin.get_ports(context, filters)}

    @db_api.CONTEXT_READER
    def _get_router(self, context, router_id):
        try:
            router = model_query.get_by_id(
                context, l3_models.Router, router_id)
        except exc.NoResultFound:
            raise l3_exc.RouterNotFound(router_id=router_id)
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
            resource_extend.apply_funcs(l3_apidef.ROUTERS, res, router)
        return lib_db_utils.resource_fields(res, fields)

    def _create_router_db(self, context, router, tenant_id):
        """Create the DB object."""
        router.setdefault('id', uuidutils.generate_uuid())
        router['tenant_id'] = tenant_id

        registry.publish(resources.ROUTER, events.BEFORE_CREATE, self,
                         payload=events.DBEventPayload(
                             context,
                             resource_id=router['id'],
                             states=(router,)))

        with db_api.CONTEXT_WRITER.using(context):
            # pre-generate id so it will be available when
            # configuring external gw port
            router_db = l3_models.Router(
                id=router['id'],
                tenant_id=router['tenant_id'],
                name=router['name'],
                admin_state_up=router['admin_state_up'],
                status=constants.ACTIVE,
                description=router.get('description'))
            context.session.add(router_db)
            l3_attrs_db.ExtraAttributesMixin.add_extra_attr(context, router_db)

            registry.publish(resources.ROUTER, events.PRECOMMIT_CREATE, self,
                             payload=events.DBEventPayload(
                                 context,
                                 resource_id=router['id'],
                                 metadata={'router_db': router_db},
                                 states=(router,)))
            return router_db

    def _update_gw_for_create_router(self, context, gw_info,
                                     request_body, router_id):
        if gw_info:
            with db_utils.context_if_transaction(
                    context, not db_api.is_session_active(context.session),
                    writer=False):
                router_db = self._get_router(context, router_id)
            self._update_router_gw_info(context, router_id,
                                        gw_info, request_body,
                                        router=router_db)

            return self._get_router(context, router_id), None
        return None, None

    def _get_stripped_router(self, router_body):
        stripped_router = {}
        for key in router_body:
            if getattr(l3_models.Router, key, None) or getattr(
                    l3_attrs_models.RouterExtraAttributes, key, None):
                stripped_router[key] = router_body[key]
        return stripped_router

    @db_api.retry_if_session_inactive()
    def create_router(self, context, router):
        r = router['router']
        gw_info = r.get(EXTERNAL_GW_INFO, None)
        # TODO(ralonsoh): migrate "tenant_id" to "project_id"
        # https://blueprints.launchpad.net/neutron/+spec/keystone-v3
        create = functools.partial(self._create_router_db, context, r,
                                   r['tenant_id'])
        delete = functools.partial(self.delete_router, context)
        update_gw = functools.partial(self._update_gw_for_create_router,
                                      context, gw_info, r)
        router_db, _unused = db_utils.safe_creation(context, create,
                                                    delete, update_gw,
                                                    transaction=False)
        new_router = self._make_router_dict(router_db)

        registry.publish(resources.ROUTER, events.AFTER_CREATE, self,
                         payload=events.DBEventPayload(
                             context,
                             resource_id=router_db.id,
                             metadata={'request_attrs': r,
                                       'router_db': router_db},
                             states=(new_router,)))
        return new_router

    @db_api.CONTEXT_WRITER
    def _update_router_db(self, context, router_id, data):
        """Update the DB object."""
        router_db = self._get_router(context, router_id)
        old_router = self._make_router_dict(router_db)
        if data:
            router_db.update(self._get_stripped_router(data))
        registry.publish(resources.ROUTER, events.PRECOMMIT_UPDATE, self,
                         payload=events.DBEventPayload(
                             context, request_body=data,
                             states=(old_router,), resource_id=router_id,
                             desired_state=router_db))
        return router_db

    @db_api.retry_if_session_inactive()
    def update_router(self, context, id, router):
        r = router['router']
        gw_info = r.get(EXTERNAL_GW_INFO, constants.ATTR_NOT_SPECIFIED)
        original = self.get_router(context, id)
        if gw_info != constants.ATTR_NOT_SPECIFIED:
            self._update_router_gw_info(context, id, gw_info, r)
        router_db = self._update_router_db(context, id, r)
        updated = self._make_router_dict(router_db)

        registry.publish(resources.ROUTER, events.AFTER_UPDATE, self,
                         payload=events.DBEventPayload(
                             context,
                             resource_id=id,
                             metadata={'request_attrs': r,
                                       'router_db': router_db},
                             states=(original, updated)))
        return updated

    def _create_router_gw_port(self, context, router, network_id, ext_ips,
                               update_gw_port=True):
        # Port has no 'tenant-id', as it is hidden from user
        port_data = {'tenant_id': '',  # intentionally not set
                     'network_id': network_id,
                     'fixed_ips': ext_ips or constants.ATTR_NOT_SPECIFIED,
                     'device_id': router['id'],
                     'device_owner': DEVICE_OWNER_ROUTER_GW,
                     'admin_state_up': True,
                     'name': ''}

        if db_api.is_session_active(context.session):
            # TODO(ralonsoh): ML2 plugin "create_port" should be called outside
            # a DB transaction. In this case an exception is made but in order
            # to prevent future errors, this call should be moved outside
            # the current transaction.
            context.GUARD_TRANSACTION = False
        gw_port = plugin_utils.create_port(
            self._core_plugin, context.elevated(), {'port': port_data})

        if not gw_port['fixed_ips']:
            LOG.debug('No IPs available for external network %s',
                      network_id)
        with plugin_utils.delete_port_on_error(
                self._core_plugin, context.elevated(), gw_port['id']):
            with db_api.CONTEXT_WRITER.using(context):
                router = self._get_router(context, router['id'])
                if update_gw_port:
                    router.gw_port = self._core_plugin._get_port(
                        context.elevated(), gw_port['id'])
                router_port = l3_obj.RouterPort(
                    context,
                    router_id=router.id,
                    port_id=gw_port['id'],
                    port_type=DEVICE_OWNER_ROUTER_GW
                )
                router_port.create()

    def _validate_gw_info(self, context, info, ext_ips, router):
        network_id = info['network_id'] if info else None
        gw_subnets = []
        if network_id:
            network_db = self._core_plugin._get_network(context, network_id)
            if not network_db.external:
                msg = _("Network %s is not an external network") % network_id
                raise n_exc.BadRequest(resource='router', msg=msg)

            gw_subnets = network_db.subnets
            for ext_ip in ext_ips:
                for subnet in network_db.subnets:
                    if not subnet.gateway_ip:
                        continue
                    if ext_ip.get('ip_address') == subnet.gateway_ip:
                        msg = _("External IP %s is the same as the "
                                "gateway IP") % ext_ip.get('ip_address')
                        raise n_exc.BadRequest(resource='router', msg=msg)

        method_validate_routes = getattr(self, '_validate_routes', None)
        if not method_validate_routes or not router.route_list:
            return network_id

        cidrs = []
        ip_addresses = []
        # All attached ports but the GW port, if exists, that will change
        # because the GW information is being updated.
        attached_ports = [rp.port for rp in router.attached_ports if
                          rp.port.id != router.gw_port_id]
        for port in attached_ports:
            for ip in port.fixed_ips:
                cidrs.append(self._core_plugin.get_subnet(
                    context.elevated(), ip.subnet_id)['cidr'])
                ip_addresses.append(ip.ip_address)

        # NOTE(ralonsoh): the GW port is not updated yet and the its IP address
        # won't be added to "ip_addresses", only the subnet CIDRs.
        for gw_subnet in gw_subnets:
            cidrs.append(gw_subnet.cidr)

        method_validate_routes(context, router.id, router.route_list,
                               cidrs=cidrs, ip_addresses=ip_addresses)
        return network_id

    # NOTE(yamamoto): This method is an override point for plugins
    # inheriting this class.  Do not optimize this out.
    def router_gw_port_has_floating_ips(self, context, router_id):
        """Return True if the router's gateway port is serving floating IPs."""
        return bool(self.get_floatingips_count(context,
                                               {'router_id': [router_id]}))

    def _delete_current_gw_port(self, context, router_id, router,
                                new_network_id, request_body=None):
        """Delete gw port if attached to an old network."""
        port_requires_deletion = (
            router.gw_port and router.gw_port['network_id'] != new_network_id)
        if not port_requires_deletion:
            return
        admin_ctx = context.elevated()
        old_network_id = router.gw_port['network_id']

        if self.router_gw_port_has_floating_ips(admin_ctx, router_id):
            raise l3_exc.RouterExternalGatewayInUseByFloatingIp(
                router_id=router_id, net_id=router.gw_port['network_id'])
        gw_ips = [x['ip_address'] for x in router.gw_port['fixed_ips']]
        gw_port_id = router.gw_port['id']
        self._delete_router_gw_port_db(context, router, request_body)
        if db_api.is_session_active(admin_ctx.session):
            # TODO(ralonsoh): ML2 plugin "delete_port" should be called outside
            # a DB transaction. In this case an exception is made but in order
            # to prevent future errors, this call should be moved outside
            # the current transaction.
            admin_ctx.GUARD_TRANSACTION = False
        self._core_plugin.delete_port(
            admin_ctx, gw_port_id, l3_port_check=False)
        # TODO(boden): normalize metadata
        metadata = {'network_id': old_network_id,
                    'new_network_id': new_network_id,
                    'gateway_ips': gw_ips}
        registry.publish(resources.ROUTER_GATEWAY,
                         events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context, states=(router,),
                             metadata=metadata,
                             resource_id=router_id))

    @db_api.CONTEXT_WRITER
    def _delete_router_gw_port_db(self, context, router, request_body):
        router.gw_port = None
        if router not in context.session:
            context.session.add(router)
        try:
            registry.publish(resources.ROUTER_GATEWAY,
                             events.BEFORE_DELETE, self,
                             payload=events.DBEventPayload(
                                 context, states=(router,),
                                 request_body=request_body,
                                 resource_id=router.id))
        except exceptions.CallbackFailure as e:
            # NOTE(armax): preserve old check's behavior
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise l3_exc.RouterInUse(router_id=router.id, reason=e)

    def _create_gw_port(self, context, router_id, router, new_network_id,
                        ext_ips):
        with db_api.CONTEXT_READER.using(context):
            router = self._get_router(context, router_id)
            new_valid_gw_port_attachment = (
                new_network_id and
                (not router.gw_port or
                 router.gw_port['network_id'] != new_network_id))
        if new_valid_gw_port_attachment:
            subnets = self._core_plugin.get_subnets_by_network(context,
                                                               new_network_id)
            try:
                registry.publish(
                    resources.ROUTER_GATEWAY, events.BEFORE_CREATE, self,
                    payload=events.DBEventPayload(
                        context,
                        metadata={
                            'network_id': new_network_id,
                            'subnets': subnets},
                        resource_id=router_id))
            except exceptions.CallbackFailure as e:
                # raise the underlying exception
                raise e.errors[0].error

            self._check_for_dup_router_subnets(
                context, router,
                subnets,
                constants.DEVICE_OWNER_ROUTER_GW
            )
            self._create_router_gw_port(context, router,
                                        new_network_id, ext_ips)

            with db_api.CONTEXT_READER.using(context):
                router = self._get_router(context, router_id)
                gw_ips = [x['ip_address'] for x in router.gw_port['fixed_ips']]

            registry.publish(resources.ROUTER_GATEWAY,
                             events.AFTER_CREATE,
                             self._create_gw_port,
                             payload=events.DBEventPayload(
                                 context, states=(router,),
                                 metadata={'gateway_ips': gw_ips,
                                           'network_id': new_network_id},
                                 resource_id=router_id))

    def _update_current_gw_port(self, context, router_id, router,
                                ext_ips, request_body):
        registry.publish(resources.ROUTER_GATEWAY, events.BEFORE_UPDATE, self,
                         payload=events.DBEventPayload(
                             context, request_body=request_body,
                             states=(router,)))
        self._core_plugin.update_port(context.elevated(), router.gw_port['id'],
                                      {'port': {'fixed_ips': ext_ips}})

    def _update_router_gw_info(self, context, router_id, info,
                               request_body, router=None):
        router = router or self._get_router(context, router_id)
        gw_port = router.gw_port
        ext_ips = info.get('external_fixed_ips', []) if info else []
        ext_ip_change = self._check_for_external_ip_change(
            context, gw_port, ext_ips)
        network_id = self._validate_gw_info(context, info, ext_ips, router)
        if gw_port and ext_ip_change and gw_port['network_id'] == network_id:
            self._update_current_gw_port(context, router_id, router,
                                         ext_ips, request_body)
        else:
            self._delete_current_gw_port(context, router_id, router,
                                         network_id, request_body)
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

    def _raise_on_subnets_overlap(self, subnet_1, subnet_2):
        cidr = subnet_1['cidr']
        ipnet = netaddr.IPNetwork(cidr)
        new_cidr = subnet_2['cidr']
        new_ipnet = netaddr.IPNetwork(new_cidr)
        match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
        match2 = netaddr.all_matching_cidrs(ipnet, [new_cidr])
        if match1 or match2:
            data = {'subnet_cidr': new_cidr,
                    'subnet_id': subnet_2['id'],
                    'cidr': cidr,
                    'sub_id': subnet_1['id']}
            msg = (_("Cidr %(subnet_cidr)s of subnet "
                     "%(subnet_id)s overlaps with cidr %(cidr)s "
                     "of subnet %(sub_id)s") % data)
            raise n_exc.BadRequest(resource='router', msg=msg)

    def _ensure_router_not_in_use(self, context, router_id):
        """Ensure that no internal network interface is attached
        to the router.
        """
        router = self._get_router(context, router_id)
        device_owner = self._get_device_owner(context, router)
        attached_ports = [rp.port_id for rp in router.attached_ports if
                          rp.port_type == device_owner]
        if attached_ports:
            reason = 'has ports still attached: ' + ', '.join(attached_ports)
            raise l3_exc.RouterInUse(router_id=router_id, reason=reason)
        return router

    @db_api.retry_if_session_inactive()
    def delete_router(self, context, id):
        registry.publish(resources.ROUTER, events.BEFORE_DELETE, self,
                         payload=events.DBEventPayload(
                             context, resource_id=id))

        # TODO(nati) Refactor here when we have router insertion model
        with db_api.CONTEXT_READER.using(context):
            router = self._ensure_router_not_in_use(context, id)
            original = self._make_router_dict(router)
        self._delete_current_gw_port(context, id, router, None)

        with db_api.CONTEXT_WRITER.using(context):
            # TODO(ralonsoh): move this section (port deletion) out of the DB
            # transaction.
            router_ports_ids = (rp.port_id for rp in
                                l3_obj.RouterPort.get_objects(context,
                                                              router_id=id))
            if db_api.is_session_active(context.session):
                context.GUARD_TRANSACTION = False
            for rp_id in router_ports_ids:
                self._core_plugin.delete_port(context.elevated(), rp_id,
                                              l3_port_check=False)

            router = self._get_router(context, id)
            registry.publish(resources.ROUTER, events.PRECOMMIT_DELETE, self,
                             payload=events.DBEventPayload(
                                 context,
                                 resource_id=id,
                                 states=(router,)))
            # we bump the revision even though we are about to delete to throw
            # staledataerror if something stuck in with a new interface
            router.bump_revision()
            context.session.flush()
            context.session.delete(router)

        registry.publish(resources.ROUTER, events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context, resource_id=id,
                             states=(original,)))

    @db_api.retry_if_session_inactive()
    def get_router(self, context, id, fields=None):
        router = self._get_router(context, id)
        return self._make_router_dict(router, fields)

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def get_routers(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None,
                    page_reverse=False):
        marker_obj = lib_db_utils.get_marker_obj(
            self, context, 'router', limit, marker)
        return model_query.get_collection(context, l3_models.Router,
                                          self._make_router_dict,
                                          filters=filters, fields=fields,
                                          sorts=sorts,
                                          limit=limit,
                                          marker_obj=marker_obj,
                                          page_reverse=page_reverse)

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def get_routers_count(self, context, filters=None):
        return model_query.get_collection_count(
            context, l3_models.Router, filters=filters,
            query_field=l3_models.Router.id.key)

    def _check_for_dup_router_subnets(self, context, router,
                                      new_subnets, new_device_owner):
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
                if p.get('device_owner') == DEVICE_OWNER_ROUTER_GW:
                    ext_subts = self._core_plugin.get_subnets(
                        context.elevated(),
                        filters={'network_id': [p['network_id']]})
                    for sub in ext_subts:
                        router_subnets.append(sub['id'])
                else:
                    router_subnets.append(ip['subnet_id'])

        # Ignore temporary Prefix Delegation CIDRs
        new_subnets = [s for s in new_subnets
                       if s['cidr'] != constants.PROVISIONAL_IPV6_PD_PREFIX]
        id_filter = {'id': router_subnets}
        subnets = self._core_plugin.get_subnets(context.elevated(),
                                                filters=id_filter)
        for sub in subnets:
            for s in new_subnets:
                self._raise_on_subnets_overlap(sub, s)

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
        """Check that a port is available for an attachment to a router

        :param context: The context of the request.
        :param port_id: The port to be attached.
        :param device_id: This method will check that device_id corresponds to
        the device_id of the port. It raises PortInUse exception if it
        doesn't.
        :returns: The port description returned by the core plugin.
        :raises: PortInUse if the device_id is not the same as the port's one.
        :raises: BadRequest if the port has no fixed IP.
        """
        port = self._core_plugin.get_port(context, port_id)
        if port['device_id'] != device_id:
            raise n_exc.PortInUse(net_id=port['network_id'],
                                  port_id=port['id'],
                                  device_id=port['device_id'])
        if not port['fixed_ips']:
            msg = _('Router port must have at least one fixed IP')
            raise n_exc.BadRequest(resource='router', msg=msg)

        fixed_ips = list(port['fixed_ips'])
        for fixed_ip in fixed_ips:
            subnet = self._core_plugin.get_subnet(
                context, fixed_ip['subnet_id'])
            self._validate_subnet_address_mode(subnet)

        return port

    def _validate_port_in_range_or_admin(self, context, subnets, port):
        if context.is_admin:
            return
        subnets_by_id = {}
        for s in subnets:
            addr_set = netaddr.IPSet()
            for range in s['allocation_pools']:
                addr_set.add(netaddr.IPRange(netaddr.IPAddress(range['start']),
                                             netaddr.IPAddress(range['end'])))
            subnets_by_id[s['id']] = (addr_set, s['project_id'],)
        for subnet_id, ip in [(fix_ip['subnet_id'], fix_ip['ip_address'],)
                              for fix_ip in port['fixed_ips']]:
            if (ip not in subnets_by_id[subnet_id][0] and
                    context.project_id != subnets_by_id[subnet_id][1]):
                msg = (_('Cannot add interface to router because specified '
                         'port %(port)s has an IP address out of the '
                         'allocation pool of subnet %(subnet)s, which is not '
                         'owned by the project making the request') %
                       {'port': port['id'], 'subnet': subnet_id})
                raise n_exc.BadRequest(resource='router', msg=msg)

    @db_api.CONTEXT_READER
    def _validate_router_port_info(self, context, router, port_id):
        # check again within transaction to mitigate race
        port = self._check_router_port(context, port_id, router.id)

        # Only allow one router port with IPv6 subnets per network id
        self._validate_one_router_ipv6_port_per_network(router, port)

        fixed_ips = list(port['fixed_ips'])
        subnets = []
        for fixed_ip in fixed_ips:
            subnet = self._core_plugin.get_subnet(context,
                                                  fixed_ip['subnet_id'])
            subnets.append(subnet)

        if subnets:
            self._check_for_dup_router_subnets(context, router,
                                               subnets, port['device_owner'])

        # Keep the restriction against multiple IPv4 subnets
        if len([s for s in subnets if s['ip_version'] == 4]) > 1:
            msg = _("Cannot have multiple "
                    "IPv4 subnets on router port")
            raise n_exc.BadRequest(resource='router', msg=msg)
        self._validate_port_in_range_or_admin(context, subnets, port)
        return port, subnets

    def _notify_attaching_interface(self, context, router_db, port,
                                    interface_info):
        """Notify third party code that an interface is being attached to a
        router

        :param context: The context of the request.
        :param router_db: The router db object having an interface attached.
        :param port: The port object being attached to the router.
        :param interface_info: The requested interface attachment info passed
        to add_router_interface.
        :raises: RouterInterfaceAttachmentConflict if a third party code
        prevent the port to be attach to the router.
        """
        try:
            metadata = {
                'port': port, 'interface_info': interface_info,
                'network_id': port['network_id']}
            registry.publish(resources.ROUTER_INTERFACE,
                             events.BEFORE_CREATE, self,
                             payload=events.DBEventPayload(
                                 context, states=(router_db,),
                                 metadata=metadata,
                                 resource_id=router_db.id))
        except exceptions.CallbackFailure as e:
            # raise the underlying exception
            reason = (_('cannot perform router interface attachment '
                        'due to %(reason)s') % {'reason': e})
            raise l3_exc.RouterInterfaceAttachmentConflict(reason=reason)

    def _add_interface_by_port(self, context, router, port_id, owner):
        # Update owner before actual process in order to avoid the
        # case where a port might get attached to a router without the
        # owner successfully updating due to an unavailable backend.
        self._core_plugin.update_port(
            context, port_id, {'port': {'device_id': router.id,
                                        'device_owner': owner}})

        return self._validate_router_port_info(context, router, port_id)

    def _port_has_ipv6_address(self, port):
        for fixed_ip in port['fixed_ips']:
            if netaddr.IPNetwork(fixed_ip['ip_address']).version == 6:
                return True

    def _validate_one_router_ipv6_port_per_network(self, router, port):
        if self._port_has_ipv6_address(port):
            for existing_port in (rp.port for rp in router.attached_ports):
                if (existing_port["id"] != port["id"] and
                        existing_port["network_id"] == port["network_id"] and
                        self._port_has_ipv6_address(existing_port) and
                        port["device_owner"] not in [
                            constants.DEVICE_OWNER_ROUTER_SNAT,
                            constants.DEVICE_OWNER_DVR_INTERFACE]):
                    msg = _("Router already contains IPv6 port %(p)s "
                            "belonging to network id %(nid)s. Only one IPv6 "
                            "port from the same network subnet can be "
                            "connected to a router.")
                    raise n_exc.BadRequest(resource='router', msg=msg % {
                        'p': existing_port['id'],
                        'nid': existing_port['network_id']})

    def _find_ipv6_router_port_by_network(self, context, router, net_id):
        router_dev_owner = self._get_device_owner(context, router)
        for port in router.attached_ports:
            p = port['port']
            if p['device_owner'] != router_dev_owner:
                # we don't want any special purpose internal ports
                continue
            if p['network_id'] == net_id and self._port_has_ipv6_address(p):
                return port

    def _add_interface_by_subnet(self, context, router, subnet_id, owner):
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        if not subnet['gateway_ip']:
            msg = _('Subnet for router interface must have a gateway IP')
            raise n_exc.BadRequest(resource='router', msg=msg)
        if subnet['project_id'] != context.project_id and not context.is_admin:
            # NOTE(amorin): check if network is RBAC or globaly shared
            # globaly shared --> disallow adding interface (see LP-1757482)
            # RBAC shared --> allow adding interface (see LP-1975603)
            elevated = context.elevated()

            with db_api.CONTEXT_READER.using(elevated):
                rbac_allowed_projects = network_obj.NetworkRBAC.get_projects(
                    elevated, object_id=subnet['network_id'],
                    action=rbac_db_models.ACCESS_SHARED,
                    target_project=context.project_id)

                # Fail if the current project_id is NOT in the allowed
                # projects
                if context.project_id not in rbac_allowed_projects:
                    msg = (_('Cannot add interface to router because subnet '
                             '%s is not owned by project making the request')
                           % subnet_id)
                    raise n_exc.BadRequest(resource='router', msg=msg)
        self._validate_subnet_address_mode(subnet)
        self._check_for_dup_router_subnets(context, router, [subnet],
                                           constants.DEVICE_OWNER_ROUTER_INTF)
        fixed_ip = {'ip_address': subnet['gateway_ip'],
                    'subnet_id': subnet['id']}

        if (subnet['ip_version'] == 6 and not
                ipv6_utils.is_ipv6_pd_enabled(subnet)):
            # Add new prefix to an existing ipv6 port with the same network id
            # if one exists
            port = self._find_ipv6_router_port_by_network(context, router,
                                                          subnet['network_id'])
            if port:
                fixed_ips = list(map(dict, port['port']['fixed_ips']))
                fixed_ips.append(fixed_ip)
                return (self._core_plugin.update_port(
                    context, port['port_id'],
                    {'port': {'fixed_ips': fixed_ips}}),
                        [subnet],
                        False)

        port_data = {'tenant_id': router.tenant_id,
                     'network_id': subnet['network_id'],
                     'fixed_ips': [fixed_ip],
                     'admin_state_up': True,
                     'device_id': router.id,
                     'device_owner': owner,
                     'name': ''}
        return plugin_utils.create_port(
            self._core_plugin, context, {'port': port_data}), [subnet], True

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

    @db_api.retry_if_session_inactive()
    def add_router_interface(self, context, router_id, interface_info=None):
        router = self._get_router(context, router_id)
        add_by_port, add_by_sub = self._validate_interface_info(interface_info)
        device_owner = self._get_device_owner(context, router_id)

        # This should be True unless adding an IPv6 prefix to an existing port
        new_router_intf = True
        cleanup_port = False

        if add_by_port:
            port_id = interface_info['port_id']
            port = self._check_router_port(context, port_id, '')
            revert_value = {'device_id': '',
                            'device_owner': port['device_owner']}
            with plugin_utils.update_port_on_error(
                    self._core_plugin, context, port_id, revert_value):
                port, subnets = self._add_interface_by_port(
                    context, router, port_id, device_owner)
        # add_by_subnet is not used here, because the validation logic of
        # _validate_interface_info ensures that either of add_by_* is True.
        else:
            port, subnets, new_router_intf = self._add_interface_by_subnet(
                context, router, interface_info['subnet_id'], device_owner)
            cleanup_port = new_router_intf  # only cleanup port we created
            revert_value = {'device_id': '',
                            'device_owner': port['device_owner']}

        if cleanup_port:
            mgr = plugin_utils.delete_port_on_error(
                self._core_plugin, context, port['id'])
        else:
            mgr = plugin_utils.update_port_on_error(
                self._core_plugin, context, port['id'], revert_value)

        if new_router_intf:
            with mgr:
                self._notify_attaching_interface(context, router_db=router,
                                                 port=port,
                                                 interface_info=interface_info)
                self._add_router_port(
                    context, port, router, device_owner)

        gw_ips = []
        gw_network_id = None
        if router.gw_port:
            gw_network_id = router.gw_port.network_id
            gw_ips = [x['ip_address'] for x in router.gw_port.fixed_ips]

        cidrs = [x['cidr'] for x in subnets]
        metadata = {'interface_info': interface_info,
                    'new_interface': new_router_intf,
                    'port': port,
                    'subnets': subnets,
                    'cidrs': cidrs,
                    'gateway_ips': gw_ips,
                    'network_id': gw_network_id}
        registry.publish(resources.ROUTER_INTERFACE,
                         events.AFTER_CREATE, self,
                         payload=events.DBEventPayload(
                             context, metadata=metadata,
                             states=(router,),
                             resource_id=router_id))

        return self._make_router_interface_info(
            router.id, port['tenant_id'], port['id'], port['network_id'],
            subnets[-1]['id'], [subnet['id'] for subnet in subnets])

    @db_api.retry_if_session_inactive()
    def _add_router_port(self, context, port, router, device_owner):
        l3_obj.RouterPort(
            context,
            port_id=port['id'],
            router_id=router.id,
            port_type=device_owner
        ).create()

        # NOTE(froyo): Check after create the RouterPort if we have generated
        # an overlapping. Like creation of port is an ML2 plugin command it
        # runs in an isolated transaction so we could not control there the
        # addition of ports to different subnets that collides in cidrs. So
        # make the check here an trigger the overlaping that will remove all
        # created items.
        router_ports = l3_obj.RouterPort.get_objects(
            context, router_id=router.id)

        if len(router_ports) > 1:
            subnets_id = []
            for rp in router_ports:
                router_port = port_obj.Port.get_object(context.elevated(),
                                                       id=rp.port_id)
                if router_port:
                    # NOTE(froyo): Just run the validation in case the new port
                    # added is on the same network than an existing one.
                    # Only allow one router port with IPv6 subnets per network
                    # id.
                    if router_port['network_id'] == port['network_id']:
                        self._validate_one_router_ipv6_port_per_network(
                            router, router_port)
                    subnets_id.extend(
                        [fixed_ip["subnet_id"]
                         for fixed_ip in router_port["fixed_ips"]])
                else:
                    # due to race conditions maybe the port under analysis is
                    # deleted, so instead returning a RouterInterfaceNotFound
                    # we continue the analysis avoiding that port
                    LOG.debug("Port %s could not be found, it might have been "
                              "deleted concurrently. Will not be checked for "
                              "an overlapping router interface.",
                              rp.port_id)

            if len(subnets_id) > 1:
                id_filter = {'id': subnets_id}
                subnets = self._core_plugin.get_subnets(context.elevated(),
                                                        filters=id_filter)

                # Ignore temporary Prefix Delegation CIDRs
                subnets = [
                    s
                    for s in subnets
                    if s["cidr"] != constants.PROVISIONAL_IPV6_PD_PREFIX
                ]
                for sub1, sub2 in itertools.combinations(subnets, 2):
                    self._raise_on_subnets_overlap(sub1, sub2)

        # Update owner after actual process again in order to
        # make sure the records in routerports table and ports
        # table are consistent.
        self._core_plugin.update_port(
            context, port['id'], {'port': {'device_id': router.id,
                                           'device_owner': device_owner}})

    def _check_router_interface_not_in_use(self, router_id, subnet):
        context = n_ctx.get_admin_context()
        subnet_cidr = netaddr.IPNetwork(subnet['cidr'])

        fip_objs = l3_obj.FloatingIP.get_objects(context, router_id=router_id)
        pf_plugin = directory.get_plugin(plugin_constants.PORTFORWARDING)
        subnet_port_ids = [
            port.id for port in
            port_obj.Port.get_ports_allocated_by_subnet_id(
                context, subnet_id=subnet['id'])]
        if pf_plugin:
            fip_ids = [fip_obj.id for fip_obj in fip_objs]
            pf_objs = port_forwarding.PortForwarding.get_objects(
                context, floatingip_id=fip_ids)
            for pf_obj in pf_objs:
                if (pf_obj.internal_ip_address and
                        pf_obj.internal_ip_address in subnet_cidr):
                    if pf_obj.internal_port_id in subnet_port_ids:
                        raise l3_exc.RouterInterfaceInUseByFloatingIP(
                            router_id=router_id, subnet_id=subnet['id'])

        for fip_obj in fip_objs:
            if (fip_obj.fixed_ip_address and
                    fip_obj.fixed_ip_address in subnet_cidr):
                if fip_obj.fixed_port_id in subnet_port_ids:
                    raise l3_exc.RouterInterfaceInUseByFloatingIP(
                        router_id=router_id, subnet_id=subnet['id'])

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet):
        try:
            registry.publish(
                resources.ROUTER_INTERFACE,
                events.BEFORE_DELETE, self,
                payload=events.DBEventPayload(
                    context, metadata={'subnet_id': subnet['id']},
                    resource_id=router_id))
        except exceptions.CallbackFailure as e:
            # NOTE(armax): preserve old check's behavior
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise l3_exc.RouterInUse(router_id=router_id, reason=e)

        self._check_router_interface_not_in_use(router_id, subnet)

    def _remove_interface_by_port(self, context, router_id,
                                  port_id, subnet_id, owner):
        ports = port_obj.Port.get_ports_by_router_and_port(
            context, router_id, owner, port_id)
        if len(ports) < 1:
            raise l3_exc.RouterInterfaceNotFound(
                router_id=router_id, port_id=port_id)

        port = ports[0]
        port_subnet_ids = [fixed_ip['subnet_id']
                           for fixed_ip in port['fixed_ips']]
        if subnet_id and subnet_id not in port_subnet_ids:
            raise n_exc.SubnetMismatchForPort(
                port_id=port_id, subnet_id=subnet_id)
        subnets = subnet_obj.Subnet.get_objects(context, id=port_subnet_ids)
        for subnet in subnets:
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet)
        self._core_plugin.delete_port(context, port['id'],
                                      l3_port_check=False)
        return port, subnets

    def _remove_interface_by_subnet(self, context,
                                    router_id, subnet_id, owner):
        subnet = self._core_plugin.get_subnet(context, subnet_id)
        ports = port_obj.Port.get_ports_by_router_and_network(
            context, router_id, owner, subnet['network_id'])
        if ports:
            self._confirm_router_interface_not_in_use(
                context, router_id, subnet)

        for p in ports:
            try:
                p = self._core_plugin.get_port(context, p.id)
            except n_exc.PortNotFound:
                continue
            port_subnets = [fip['subnet_id'] for fip in p['fixed_ips']]
            if subnet_id in port_subnets and len(port_subnets) > 1:
                # multiple prefix port - delete prefix from port
                fixed_ips = [dict(fip) for fip in p['fixed_ips']
                             if fip['subnet_id'] != subnet_id]
                self._core_plugin.update_port(
                    context, p['id'], {'port': {'fixed_ips': fixed_ips}})
                return (p, [subnet])
            elif subnet_id in port_subnets:
                # only one subnet on port - delete the port
                self._core_plugin.delete_port(context, p['id'],
                                              l3_port_check=False)
                return (p, [subnet])
        raise l3_exc.RouterInterfaceNotFoundForSubnet(
            router_id=router_id, subnet_id=subnet_id)

    @db_api.retry_if_session_inactive()
    def remove_router_interface(self, context, router_id, interface_info):
        remove_by_port, _ = self._validate_interface_info(interface_info,
                                                          for_removal=True)
        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')
        device_owner = self._get_device_owner(context, router_id)
        if remove_by_port:
            port, subnets = self._remove_interface_by_port(context, router_id,
                                                           port_id, subnet_id,
                                                           device_owner)
        else:
            port, subnets = self._remove_interface_by_subnet(
                context, router_id, subnet_id, device_owner)

        gw_network_id = None
        gw_ips = []
        router = self._get_router(context, router_id)
        if router.gw_port:
            gw_network_id = router.gw_port.network_id
            gw_ips = [x['ip_address'] for x in router.gw_port.fixed_ips]

        cidrs = [x['cidr'] for x in subnets]
        metadata = {'interface_info': interface_info,
                    'port': port, 'gateway_ips': gw_ips,
                    'network_id': gw_network_id, 'cidrs': cidrs}
        registry.publish(resources.ROUTER_INTERFACE,
                         events.AFTER_DELETE, self,
                         payload=events.DBEventPayload(
                             context, metadata=metadata,
                             resource_id=router_id))

        return self._make_router_interface_info(router_id, port['tenant_id'],
                                                port['id'], port['network_id'],
                                                subnets[0]['id'],
                                                [subnet['id'] for subnet in
                                                 subnets])

    def _get_floatingip(self, context, id):
        floatingip = l3_obj.FloatingIP.get_object(context, id=id)
        if not floatingip:
            raise l3_exc.FloatingIPNotFound(floatingip_id=id)
        return floatingip

    def _make_floatingip_dict(self, floatingip, fields=None,
                              process_extensions=True):
        floating_ip_address = (str(floatingip.floating_ip_address)
                               if floatingip.floating_ip_address else None)
        fixed_ip_address = (str(floatingip.fixed_ip_address)
                            if floatingip.fixed_ip_address else None)
        res = {'id': floatingip.id,
               'tenant_id': floatingip.project_id,
               'floating_ip_address': floating_ip_address,
               'floating_network_id': floatingip.floating_network_id,
               'router_id': floatingip.router_id,
               'port_id': floatingip.fixed_port_id,
               'fixed_ip_address': fixed_ip_address,
               'status': floatingip.status,
               'standard_attr_id': floatingip.db_obj.standard_attr.id,
               }
        # NOTE(mlavalle): The following assumes this mixin is used in a
        # class inheriting from CommonDbMixin, which is true for all existing
        # plugins.
        # TODO(lujinluo): Change floatingip.db_obj to floatingip once all
        # codes are migrated to use Floating IP OVO object.
        if process_extensions:
            resource_extend.apply_funcs(
                l3_apidef.FLOATINGIPS, res, floatingip.db_obj)
        return lib_db_utils.resource_fields(res, fields)

    def _get_router_for_floatingip(self, context, internal_port,
                                   internal_subnet_id,
                                   external_network_id):
        subnet = self._core_plugin.get_subnet(context, internal_subnet_id)
        return self.get_router_for_floatingip(
            context, internal_port, subnet, external_network_id)

    # NOTE(yamamoto): This method is an override point for plugins
    # inheriting this class.  Do not optimize this out.
    def get_router_for_floatingip(self, context, internal_port,
                                  internal_subnet, external_network_id):
        """Find a router to handle the floating-ip association.

        :param internal_port: The port for the fixed-ip.
        :param internal_subnet: The subnet for the fixed-ip.
        :param external_network_id: The external network for floating-ip.

        :raises: ExternalGatewayForFloatingIPNotFound if no suitable router
                 is found.
        """

        # Find routers(with router_id and interface address) that
        # connect given internal subnet and the external network.
        # Among them, if the router's interface address matches
        # with subnet's gateway-ip, return that router.
        # Otherwise return the first router.
        RouterPort = l3_models.RouterPort
        gw_port = orm.aliased(models_v2.Port, name="gw_port")
        # TODO(lujinluo): Need IPAllocation and Port object
        routerport_qry = (context.session.query(
            RouterPort.router_id, models_v2.IPAllocation.ip_address).
                          join(RouterPort.port).
                          join(models_v2.Port.fixed_ips).
                          filter(models_v2.Port.network_id ==
                                 internal_port['network_id'],
                                 RouterPort.port_type.in_(
                                     constants.ROUTER_INTERFACE_OWNERS),
                                 models_v2.IPAllocation.subnet_id ==
                                 internal_subnet['id']).
                          join(gw_port,
                               gw_port.device_id == RouterPort.router_id).
                          filter(gw_port.network_id == external_network_id,
                                 gw_port.device_owner ==
                                 DEVICE_OWNER_ROUTER_GW).
                          distinct())

        first_router_id = None
        for router_id, interface_ip in routerport_qry:
            if interface_ip == internal_subnet['gateway_ip']:
                return router_id
            if not first_router_id:
                first_router_id = router_id
        if first_router_id:
            return first_router_id

        raise l3_exc.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet['id'],
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def _port_ipv4_fixed_ips(self, port):
        return [ip for ip in port['fixed_ips']
                if netaddr.IPAddress(ip['ip_address']).version == 4]

    def _internal_fip_assoc_data(self, context, fip, tenant_id):
        """Retrieve internal port data for floating IP.

        Retrieve information concerning the internal port where
        the floating IP should be associated to.
        """
        internal_port = self._core_plugin.get_port(context, fip['port_id'])
        if internal_port['tenant_id'] != tenant_id and not context.is_admin:
            port_id = fip['port_id']
            msg = (_('Cannot process floating IP association with '
                     'Port %s, since that port is owned by a '
                     'different tenant') % port_id)
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        internal_subnet_id = None
        if not utils.is_fip_serviced(internal_port.get('device_owner')):
            msg = _('Port %(id)s is unable to be assigned a floating IP')
            raise n_exc.BadRequest(resource='floatingip', msg=msg)
        if fip.get('fixed_ip_address'):
            internal_ip_address = fip['fixed_ip_address']
            if netaddr.IPAddress(internal_ip_address).version != 4:
                msg = (_('Cannot process floating IP association with %s, '
                         'since that is not an IPv4 address') %
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

    def _get_assoc_data(self, context, fip, floatingip_obj):
        """Determine/extract data associated with the internal port.

        When a floating IP is associated with an internal port,
        we need to extract/determine some data associated with the
        internal port, including the internal_ip_address, and router_id.
        The confirmation of the internal port whether owned by the tenant who
        owns the floating IP will be confirmed by _get_router_for_floatingip.
        """
        (internal_port, internal_subnet_id,
         internal_ip_address) = self._internal_fip_assoc_data(
             context, fip, floatingip_obj.project_id)
        router_id = self._get_router_for_floatingip(
            context, internal_port,
            internal_subnet_id, floatingip_obj.floating_network_id)

        if self.is_router_distributed(context, router_id):
            if not plugin_utils.can_port_be_bound_to_virtual_bridge(
                    internal_port):
                msg = _('Port VNIC type is not valid to associate a FIP in '
                        'DVR mode')
                raise n_exc.BadRequest(resource='floatingip', msg=msg)

        return (fip['port_id'], internal_ip_address, router_id)

    def _check_and_get_fip_assoc(self, context, fip, floatingip_obj):
        port_id = internal_ip_address = router_id = None
        if fip.get('fixed_ip_address') and not fip.get('port_id'):
            msg = _("fixed_ip_address cannot be specified without a port_id")
            raise n_exc.BadRequest(resource='floatingip', msg=msg)
        if fip.get('port_id'):
            port_id, internal_ip_address, router_id = self._get_assoc_data(
                context,
                fip,
                floatingip_obj)

            if port_id == floatingip_obj.fixed_port_id:
                # Floating IP association is not changed.
                return port_id, internal_ip_address, router_id

            fip_exists = l3_obj.FloatingIP.objects_exist(
                context,
                fixed_port_id=fip['port_id'],
                floating_network_id=floatingip_obj.floating_network_id,
                fixed_ip_address=netaddr.IPAddress(internal_ip_address))
            if fip_exists:
                floating_ip_address = (str(floatingip_obj.floating_ip_address)
                                       if floatingip_obj.floating_ip_address
                                       else None)
                raise l3_exc.FloatingIPPortAlreadyAssociated(
                    port_id=fip['port_id'],
                    fip_id=floatingip_obj.id,
                    floating_ip_address=floating_ip_address,
                    fixed_ip=internal_ip_address,
                    net_id=floatingip_obj.floating_network_id)

        if fip and 'port_id' not in fip and floatingip_obj.fixed_port_id:
            # NOTE(liuyulong): without the fix of bug #1610045 here could
            # also let floating IP can be dissociated with an empty
            # updating dict.
            fip['port_id'] = floatingip_obj.fixed_port_id
            port_id, internal_ip_address, router_id = self._get_assoc_data(
                context, fip, floatingip_obj)

        # Condition for floating IP with binding port forwarding
        if not floatingip_obj.fixed_port_id and floatingip_obj.router_id:
            router_id = floatingip_obj.router_id

        # After all upper conditions, if updating API dict is submitted with
        # {'port_id': null}, then the floating IP cloud also be dissociated.
        return port_id, internal_ip_address, router_id

    def _update_fip_assoc(self, context, fip, floatingip_obj):
        previous_router_id = floatingip_obj.router_id
        port_id, internal_ip_address, router_id = (
            self._check_and_get_fip_assoc(context, fip, floatingip_obj))
        association_event = None
        if floatingip_obj.fixed_port_id != port_id:
            association_event = bool(port_id)
        floatingip_obj.fixed_ip_address = (
            netaddr.IPAddress(internal_ip_address)
            if internal_ip_address else None)
        floatingip_obj.fixed_port_id = port_id
        floatingip_obj.router_id = router_id
        floatingip_obj.last_known_router_id = previous_router_id
        if 'description' in fip:
            floatingip_obj.description = fip['description']
        return association_event

    def _is_ipv4_network(self, context, net_db):
        return any(s.ip_version == 4 for s in net_db.subnets)

    def _create_floatingip(self, context, floatingip,
                           initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
        try:
            registry.publish(resources.FLOATING_IP, events.BEFORE_CREATE,
                             self, payload=events.DBEventPayload(
                                 context, request_body=floatingip))
        except exceptions.CallbackFailure as e:
            # raise the underlying exception
            raise e.errors[0].error

        fip = floatingip['floatingip']
        fip_id = uuidutils.generate_uuid()

        f_net_id = fip['floating_network_id']
        with db_api.CONTEXT_READER.using(context):
            f_net_db = self._core_plugin._get_network(context, f_net_id)
        if not f_net_db.external:
            msg = _("Network %s is not a valid external network") % f_net_id
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        if not self._is_ipv4_network(context, f_net_db):
            msg = _("Network %s does not contain any IPv4 subnet") % f_net_id
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        # This external port is never exposed to the tenant.
        # it is used purely for internal system and admin use when
        # managing floating IPs.

        port = {'tenant_id': '',  # tenant intentionally not set
                'network_id': f_net_id,
                'admin_state_up': True,
                'device_id': 'PENDING',
                'device_owner': DEVICE_OWNER_FLOATINGIP,
                'status': constants.PORT_STATUS_NOTAPPLICABLE,
                'name': ''}

        # Both subnet_id and floating_ip_address are accepted, if
        # floating_ip_address is not in the subnet,
        # InvalidIpForSubnet exception will be raised.
        fixed_ip = {}
        if validators.is_attr_set(fip.get('subnet_id')):
            fixed_ip['subnet_id'] = fip['subnet_id']
        if validators.is_attr_set(fip.get('floating_ip_address')):
            fixed_ip['ip_address'] = fip['floating_ip_address']
        if fixed_ip:
            port['fixed_ips'] = [fixed_ip]

        # 'status' in port dict could not be updated by default, use
        # check_allow_post to stop the verification of system
        external_port = plugin_utils.create_port(
            self._core_plugin, context.elevated(),
            {'port': port}, check_allow_post=False)

        dns_data = None
        with plugin_utils.delete_port_on_error(
                self._core_plugin, context.elevated(),
                external_port['id']),\
                db_api.CONTEXT_WRITER.using(context):
            # Ensure IPv4 addresses are allocated on external port
            external_ipv4_ips = self._port_ipv4_fixed_ips(external_port)
            if not external_ipv4_ips:
                raise n_exc.ExternalIpAddressExhausted(net_id=f_net_id)

            floating_fixed_ip = external_ipv4_ips[0]
            floating_ip_address = floating_fixed_ip['ip_address']
            qos_policy_id = (fip.get(qos_const.QOS_POLICY_ID)
                             if self._is_fip_qos_supported else None)
            floatingip_obj = l3_obj.FloatingIP(
                context,
                id=fip_id,
                project_id=fip['tenant_id'],
                status=initial_status,
                floating_network_id=fip['floating_network_id'],
                floating_ip_address=floating_ip_address,
                floating_port_id=external_port['id'],
                description=fip.get('description'),
                qos_policy_id=qos_policy_id)
            # Update association with internal port
            # and define external IP address
            assoc_result = self._update_fip_assoc(context, fip, floatingip_obj)
            floatingip_obj.create()
            floatingip_dict = self._make_floatingip_dict(
                floatingip_obj, process_extensions=False)
            if self._is_dns_integration_supported:
                dns_data = self._process_dns_floatingip_create_precommit(
                    context, floatingip_dict, fip)

            registry.publish(resources.FLOATING_IP,
                             events.PRECOMMIT_CREATE,
                             self,
                             payload=events.DBEventPayload(
                                 context,
                                 resource_id=fip_id,
                                 desired_state=floatingip_obj.db_obj,
                                 states=(fip,)))

        self._core_plugin.update_port(
            context.elevated(), external_port['id'],
            {'port': {'device_id': fip_id}})
        registry.publish(
            resources.FLOATING_IP, events.AFTER_CREATE, self,
            payload=events.DBEventPayload(
                context, states=(floatingip_dict,),
                resource_id=floatingip_obj.id,
                metadata={'association_event': assoc_result}))
        if assoc_result:
            LOG.info(FIP_ASSOC_MSG,
                     {'fip_id': floatingip_obj.id,
                      'ext_ip': str(floatingip_obj.floating_ip_address),
                      'port_id': floatingip_obj.fixed_port_id,
                      'assoc': 'associated'})

        if self._is_dns_integration_supported:
            self._process_dns_floatingip_create_postcommit(context,
                                                           floatingip_dict,
                                                           dns_data)
        # TODO(lujinluo): Change floatingip_db to floatingip_obj once all
        # codes are migrated to use Floating IP OVO object.
        resource_extend.apply_funcs(l3_apidef.FLOATINGIPS, floatingip_dict,
                                    floatingip_obj.db_obj)
        return floatingip_dict

    @db_api.retry_if_session_inactive()
    def create_floatingip(self, context, floatingip,
                          initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
        return self._create_floatingip(context, floatingip, initial_status)

    def _update_floatingip(self, context, id, floatingip):
        try:
            registry.publish(resources.FLOATING_IP, events.BEFORE_UPDATE,
                             self, payload=events.DBEventPayload(
                                 context, request_body=floatingip,
                                 resource_id=id))
        except exceptions.CallbackFailure as e:
            # raise the underlying exception
            raise e.errors[0].error

        dns_data = None
        fip = floatingip['floatingip']
        with db_api.CONTEXT_WRITER.using(context):
            floatingip_obj = self._get_floatingip(context, id)
            old_floatingip = self._make_floatingip_dict(floatingip_obj)
            old_fixed_port_id = floatingip_obj.fixed_port_id
            assoc_result = self._update_fip_assoc(context, fip, floatingip_obj)
            if self._is_fip_qos_supported:
                floatingip_obj.qos_policy_id = fip.get(qos_const.QOS_POLICY_ID)

            floatingip_obj.update()
            floatingip_dict = self._make_floatingip_dict(floatingip_obj)

            if self._is_dns_integration_supported:
                dns_data = self._process_dns_floatingip_update_precommit(
                    context, floatingip_dict)
            floatingip_obj = l3_obj.FloatingIP.get_object(
                context, id=floatingip_obj.id)
            floatingip_db = floatingip_obj.db_obj

            registry.publish(resources.FLOATING_IP,
                             events.PRECOMMIT_UPDATE,
                             self,
                             payload=events.DBEventPayload(
                                 context,
                                 desired_state=floatingip_db,
                                 states=(old_floatingip, floatingip)))

        registry.publish(
            resources.FLOATING_IP, events.AFTER_UPDATE, self,
            payload=events.DBEventPayload(
                context, states=(old_floatingip, floatingip_dict),
                resource_id=floatingip_obj.id,
                metadata={'association_event': assoc_result}))
        if assoc_result is not None:
            port_id = old_fixed_port_id or floatingip_obj.fixed_port_id
            assoc = 'associated' if assoc_result else 'disassociated'
            LOG.info(FIP_ASSOC_MSG,
                     {'fip_id': floatingip_obj.id,
                      'ext_ip': str(floatingip_obj.floating_ip_address),
                      'port_id': port_id, 'assoc': assoc})

        if self._is_dns_integration_supported:
            self._process_dns_floatingip_update_postcommit(context,
                                                           floatingip_dict,
                                                           dns_data)
        # TODO(lujinluo): Change floatingip_db to floatingip_obj once all
        # codes are migrated to use Floating IP OVO object.
        resource_extend.apply_funcs(l3_apidef.FLOATINGIPS, floatingip_dict,
                                    floatingip_db)
        return old_floatingip, floatingip_dict

    def _floatingips_to_router_ids(self, floatingips):
        return list(set([floatingip['router_id']
                         for floatingip in floatingips
                         if floatingip['router_id']]))

    @db_api.retry_if_session_inactive()
    def update_floatingip(self, context, id, floatingip):
        _old_floatingip, floatingip = self._update_floatingip(
            context, id, floatingip)
        return floatingip

    def update_floatingip_status(self, context, floatingip_id, status):
        """Update operational status for floating IP in neutron DB."""
        return l3_obj.FloatingIP.update_object(
            context, {'status': status}, id=floatingip_id)

    @registry.receives(resources.PORT, [events.PRECOMMIT_DELETE])
    def _precommit_delete_port_callback(
            self, resource, event, trigger, payload):
        port = payload.latest_state
        if (port['device_owner'] ==
                constants.DEVICE_OWNER_FLOATINGIP):
            registry.publish(resources.FLOATING_IP, events.PRECOMMIT_DELETE,
                             self, payload)

    def _delete_floatingip(self, context, id):
        floatingip = self._get_floatingip(context, id)
        floatingip_dict = self._make_floatingip_dict(floatingip)
        if self._is_dns_integration_supported:
            self._process_dns_floatingip_delete(context, floatingip_dict)
        # Foreign key cascade will take care of the removal of the
        # floating IP record once the port is deleted. We can't start
        # a transaction first to remove it ourselves because the delete_port
        # method will yield in its post-commit activities.
        self._core_plugin.delete_port(context.elevated(),
                                      floatingip.floating_port_id,
                                      l3_port_check=False)
        registry.publish(
            resources.FLOATING_IP, events.AFTER_DELETE, self,
            payload=events.DBEventPayload(
                context, states=(floatingip_dict,),
                resource_id=id))
        if floatingip.fixed_port_id:
            LOG.info(FIP_ASSOC_MSG,
                     {'fip_id': floatingip.id,
                      'ext_ip': str(floatingip.floating_ip_address),
                      'port_id': floatingip.fixed_port_id,
                      'assoc': 'disassociated (deleted)'})
        return floatingip_dict

    @db_api.retry_if_session_inactive()
    def delete_floatingip(self, context, id):
        self._delete_floatingip(context, id)

    @db_api.retry_if_session_inactive()
    def get_floatingip(self, context, id, fields=None):
        floatingip = self._get_floatingip(context, id)
        return self._make_floatingip_dict(floatingip, fields)

    @db_api.retry_if_session_inactive()
    def get_floatingips(self, context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        filters = filters or {}
        for key, val in API_TO_DB_COLUMN_MAP.items():
            if key in filters:
                filters[val] = filters.pop(key)
        floatingip_objs = l3_obj.FloatingIP.get_objects(
            context, _pager=pager, validate_filters=False, **filters)
        floatingip_dicts = [
            self._make_floatingip_dict(floatingip_obj, fields)
            for floatingip_obj in floatingip_objs
        ]
        return floatingip_dicts

    @db_api.retry_if_session_inactive()
    def delete_disassociated_floatingips(self, context, network_id):
        fip_ids = l3_obj.FloatingIP.get_disassociated_ids_for_net(
            context, network_id)

        for fip_id in fip_ids:
            self.delete_floatingip(context, fip_id)

    @db_api.retry_if_session_inactive()
    def get_floatingips_count(self, context, filters=None):
        filters = filters or {}
        return l3_obj.FloatingIP.count(context, **filters)

    def prevent_internal_ip_change_for_fip(self, context, port_id,
                                           new_fixed_ips):
        fips = self._get_floatingips_by_port_id(context, port_id)
        if not fips or not fips[0].fixed_ip_address:
            return
        internal_ip = str(fips[0].fixed_ip_address)
        for fixed_ip in new_fixed_ips:
            if fixed_ip.get('ip_address') == internal_ip:
                return
        msg = (_('Cannot update the fixed_ips of the port %s, because '
                 'its original fixed_ip has been associated to a '
                 'floating ip') %
               port_id)
        raise n_exc.BadRequest(resource='port', msg=msg)

    def prevent_l3_port_deletion(self, context, port_id, port=None):
        """Checks to make sure a port is allowed to be deleted.

        Raises an exception if this is not the case.  This should be called by
        any plugin when the API requests the deletion of a port, since some
        ports for L3 are not intended to be deleted directly via a DELETE
        to /ports, but rather via other API calls that perform the proper
        deletion checks.
        """
        try:
            port = port or self._core_plugin.get_port(context, port_id)
        except n_exc.PortNotFound:
            # non-existent ports don't need to be protected from deletion
            return
        if port['device_owner'] not in self.router_device_owners:
            return
        # NOTE(kevinbenton): we also check to make sure that the
        # router still exists. It's possible for HA router interfaces
        # to remain after the router is deleted if they encounter an
        # error during deletion.
        # Elevated context in case router is owned by another tenant
        if port['device_owner'] == DEVICE_OWNER_FLOATINGIP:
            if not l3_obj.FloatingIP.objects_exist(
                    context, id=port['device_id']):
                LOG.debug("Floating IP %(f_id)s corresponding to port "
                          "%(port_id)s no longer exists, allowing deletion.",
                          {'f_id': port['device_id'], 'port_id': port['id']})
                return
        elif not l3_obj.Router.objects_exist(context.elevated(),
                                             id=port['device_id']):
            LOG.debug("Router %(router_id)s corresponding to port "
                      "%(port_id)s no longer exists, allowing deletion.",
                      {'router_id': port['device_id'],
                       'port_id': port['id']})
            return

        reason = _('has device owner %s') % port['device_owner']
        raise n_exc.ServicePortInUse(port_id=port['id'],
                                     reason=reason)

    @db_api.retry_if_session_inactive()
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        """Disassociate all floating IPs linked to specific port.

        @param port_id: ID of the port to disassociate floating IPs.
        @param do_notify: whether we should notify routers right away.
                          This parameter is ignored.
        @return: set of router-ids that require notification updates
        """
        with db_api.CONTEXT_WRITER.using(context):
            # NOTE(froyo): Context is elevated to confirm the presence of at
            # least one FIP associated to the port_id. Additional checks
            # regarding the tenant's grants will be carried out in following
            # lines.
            if not l3_obj.FloatingIP.objects_exist(
                    context.elevated(), fixed_port_id=port_id):
                return []

            floating_ip_objs = l3_obj.FloatingIP.get_objects(
                context, fixed_port_id=port_id)

            # NOTE(froyo): To ensure that a FIP assigned by an admin user
            # cannot be disassociated by a tenant user, we raise exception to
            # generate a 409 Conflict response message that prompts the tenant
            # user to contact an admin, rather than a 500 error message.
            if not context.is_admin:
                floating_ip_objs_admin = l3_obj.FloatingIP.get_objects(
                    context.elevated(), fixed_port_id=port_id)
                if floating_ip_objs_admin != floating_ip_objs:
                    raise FipAssociated(port_id=port_id)

            router_ids = {fip.router_id for fip in floating_ip_objs}
            old_fips = {fip.id: self._make_floatingip_dict(fip)
                        for fip in floating_ip_objs}
            values = {'fixed_port_id': None,
                      'fixed_ip_address': None,
                      'router_id': None}
            l3_obj.FloatingIP.update_objects(
                context, values, fixed_port_id=port_id)
            # NOTE(swroblew): to avoid querying DB for new FIPs state,
            # update state of local FIP objects for _make_floatingip_dict call
            for fip in floating_ip_objs:
                fip.fixed_port_id = None
                fip.fixed_ip_address = None
                fip.router_id = None
            new_fips = {fip.id: self._make_floatingip_dict(fip)
                        for fip in floating_ip_objs}
            for fip in floating_ip_objs:
                registry.publish(
                    resources.FLOATING_IP,
                    events.PRECOMMIT_UPDATE,
                    self,
                    payload=events.DBEventPayload(
                        context,
                        desired_state=fip,
                        metadata={'router_ids': router_ids},
                        states=(old_fips[fip.id],
                                {l3_apidef.FLOATINGIP: values})))

        for fip_id, fip in new_fips.items():
            # Process DNS record removal after committing the transaction
            if self._is_dns_integration_supported:
                self._process_dns_floatingip_delete(context, fip)
            registry.publish(
                resources.FLOATING_IP, events.AFTER_UPDATE, self,
                payload=events.DBEventPayload(
                    context, states=(old_fips[fip_id], fip),
                    resource_id=fip_id,
                    metadata={'association_event': False}))
        for fip in old_fips.values():
            LOG.info(FIP_ASSOC_MSG,
                     {'fip_id': fip['id'],
                      'ext_ip': str(fip['floating_ip_address']),
                      'port_id': fip['port_id'],
                      'assoc': 'disassociated'})
        return router_ids

    def _get_floatingips_by_port_id(self, context, port_id):
        """Helper function to retrieve the fips associated with a port_id."""
        if l3_obj.FloatingIP.objects_exist(context, fixed_port_id=port_id):
            return l3_obj.FloatingIP.get_objects(
                context, fixed_port_id=port_id)
        else:
            return []

    def _build_routers_list(self, context, routers, gw_ports):
        """Subclasses can override this to add extra gateway info"""
        return routers

    def _make_router_dict_with_gw_port(self, router, fields):
        result = self._make_router_dict(router, fields)
        if router.get('gw_port'):
            result['gw_port'] = self._core_plugin._make_port_dict(
                router['gw_port'])
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
        router_dicts = model_query.get_collection(
            context, l3_models.Router, self._make_router_dict_with_gw_port,
            filters=filters)
        if not router_dicts:
            return []
        gw_ports = dict((r['gw_port']['id'], r['gw_port'])
                        for r in router_dicts
                        if r.get('gw_port'))
        return self._build_routers_list(context, router_dicts, gw_ports)

    def _make_floatingip_dict_with_scope(self, floatingip_obj, scope_id):
        d = self._make_floatingip_dict(floatingip_obj)
        d['fixed_ip_address_scope'] = scope_id
        return d

    def _get_sync_floating_ips(self, context, router_ids, host=None):
        """Query floating_ips that relate to list of router_ids with scope.

        This is different than the regular get_floatingips in that it finds the
        address scope of the fixed IP.  The router needs to know this to
        distinguish it from other scopes.

        There are a few redirections to go through to discover the address
        scope from the floating ip.
        """
        if not router_ids:
            return []

        return [
            self._make_floatingip_dict_with_scope(*scoped_fip)
            for scoped_fip in l3_obj.FloatingIP.get_scoped_floating_ips(
                context, router_ids, host)
        ]

    def _get_sync_interfaces(self, context, router_ids, device_owners=None):
        """Query router interfaces that relate to list of router_ids."""
        device_owners = device_owners or [DEVICE_OWNER_ROUTER_INTF,
                                          DEVICE_OWNER_HA_REPLICATED_INT]
        if not router_ids:
            return []
        # TODO(lujinluo): Need Port as synthetic field
        objs = l3_obj.RouterPort.get_objects(
            context, router_id=router_ids, port_type=list(device_owners))

        interfaces = [self._core_plugin._make_port_dict(rp.db_obj.port)
                      for rp in objs]
        return interfaces

    @staticmethod
    def _each_port_having_fixed_ips(ports):
        for port in ports or []:
            fixed_ips = port.get('fixed_ips', [])
            if not fixed_ips:
                # Skip ports without IPs, which can occur if a subnet
                # attached to a router is deleted
                LOG.info("Skipping port %s as no IP is configure on "
                         "it",
                         port['id'])
                continue
            yield port

    @db_api.CONTEXT_READER
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
                  'network_id', 'ipv6_ra_mode', 'subnetpool_id', 'segment_id']

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
        filters = {'id': network_ids}
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
        seg_plugin_loaded = segment_ext.SegmentPluginBase.is_loaded()
        network_ids = [p['network_id']
                       for p in self._each_port_having_fixed_ips(ports)]

        mtus_by_network = self._get_mtus_by_network_list(context, network_ids)
        subnets_by_network = self._get_subnets_by_network_list(
            context, network_ids)

        for port in self._each_port_having_fixed_ips(ports):
            is_gw = port['device_owner'] == constants.DEVICE_OWNER_ROUTER_GW
            port['subnets'] = []
            port['extra_subnets'] = []
            port['address_scopes'] = {constants.IP_VERSION_4: None,
                                      constants.IP_VERSION_6: None}

            gw_port_segment = None
            if is_gw and seg_plugin_loaded:
                for subnet in subnets_by_network[port['network_id']]:
                    if subnet['id'] == port['fixed_ips'][0]['subnet_id']:
                        gw_port_segment = subnet['segment_id']
                        break

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
                    # NOTE(ralonsoh): if this is the gateway port and is
                    # connected to a router provider network, it will have L2
                    # connectivity only to the subnets in the same segment.
                    # The router will add only the onlink routes to those
                    # subnet CIDRs.
                    if is_gw and seg_plugin_loaded:
                        if subnet['segment_id'] == gw_port_segment:
                            port['extra_subnets'].append(subnet_info)
                    else:
                        port['extra_subnets'].append(subnet_info)

            port['address_scopes'].update(scopes)
            port['mtu'] = mtus_by_network.get(port['network_id'], 0)

    def _process_floating_ips(self, context, routers_dict, floating_ips):
        for floating_ip in floating_ips:
            router = routers_dict.get(floating_ip['router_id'])
            if router:
                router_floatingips = router.get(constants.FLOATINGIP_KEY,
                                                [])
                router_floatingips.append(floating_ip)
                router[constants.FLOATINGIP_KEY] = router_floatingips

    def _process_interfaces(self, routers_dict, interfaces):
        for interface in interfaces:
            router = routers_dict.get(interface['device_id'])
            if router:
                router_interfaces = router.get(constants.INTERFACE_KEY, [])
                router_interfaces.append(interface)
                router[constants.INTERFACE_KEY] = router_interfaces

    def _get_router_info_list(self, context, router_ids=None, active=None,
                              device_owners=None, fip_host_filter=None):
        """Query routers and their related floating_ips, interfaces."""
        with db_api.CONTEXT_WRITER.using(context):
            routers = self._get_sync_routers(context,
                                             router_ids=router_ids,
                                             active=active)
            router_ids = [router['id'] for router in routers]
            interfaces = self._get_sync_interfaces(
                context, router_ids, device_owners)
            floating_ips = self._get_sync_floating_ips(
                context, router_ids, host=fip_host_filter)
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

    def is_router_distributed(self, context, router_id):
        """Returns if a router is distributed or not

        If DVR extension is not enabled, no router will be distributed. This
        function is overridden in L3_NAT_with_dvr_db_mixin in case the DVR
        extension is loaded.
        """
        return False


@registry.has_registry_receivers
class L3RpcNotifierMixin(object):
    """Mixin class to add rpc notifier attribute to db_base_plugin_v2."""

    @staticmethod
    @registry.receives(resources.PORT, [events.AFTER_DELETE])
    def _notify_routers_callback(resource, event, trigger, payload):
        context = payload.context
        router_ids = payload.metadata['router_ids']
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if l3plugin:
            l3plugin.notify_routers_updated(context, router_ids)
        else:
            LOG.debug('%s not configured', plugin_constants.L3)

    @staticmethod
    @registry.receives(resources.SUBNET, [events.AFTER_UPDATE])
    def _notify_subnet_gateway_ip_update(resource, event, trigger, payload):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if not l3plugin:
            return
        context = payload.context
        orig = payload.states[0]
        updated = payload.latest_state
        if orig['gateway_ip'] == updated['gateway_ip']:
            return
        network_id = updated['network_id']
        subnet_id = updated['id']
        with db_api.CONTEXT_READER.using(context):
            query = context.session.query(models_v2.Port.device_id).filter_by(
                network_id=network_id,
                device_owner=DEVICE_OWNER_ROUTER_GW)
            query = query.join(models_v2.Port.fixed_ips).filter(
                models_v2.IPAllocation.subnet_id == subnet_id)
            router_ids = set(port.device_id for port in query)
        for router_id in router_ids:
            l3plugin.notify_router_updated(context, router_id)

    @staticmethod
    @registry.receives(resources.PORT, [events.AFTER_UPDATE])
    def _notify_gateway_port_ip_changed(resource, event, trigger,
                                        payload):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if not l3plugin:
            return
        context = payload.context
        new_port = payload.latest_state
        original_port = payload.states[0]

        if original_port['device_owner'] != constants.DEVICE_OWNER_ROUTER_GW:
            return

        if utils.port_ip_changed(new_port, original_port):
            l3plugin.notify_router_updated(context,
                                           new_port['device_id'])

    @staticmethod
    @registry.receives(resources.SUBNETPOOL_ADDRESS_SCOPE,
                       [events.AFTER_UPDATE])
    def _notify_subnetpool_address_scope_update(resource, event,
                                                trigger, payload=None):
        context = payload.context
        subnetpool_id = payload.resource_id

        router_ids = l3_obj.RouterPort.get_router_ids_by_subnetpool(
            context, subnetpool_id)

        l3plugin = directory.get_plugin(plugin_constants.L3)
        if l3plugin:
            l3plugin.notify_routers_updated(context, router_ids)
        else:
            LOG.debug('%s not configured', plugin_constants.L3)

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

    def add_router_interface(self, context, router_id, interface_info=None):
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
                          initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
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
            context, port_id, do_notify)
        if do_notify:
            self.notify_routers_updated(context, router_ids)
            # since caller assumes that we handled notifications on its
            # behalf, return nothing
            return

        return router_ids

    def notify_routers_updated(self, context, router_ids):
        super(L3_NAT_db_mixin, self).notify_routers_updated(
            context, list(router_ids), 'disassociate_floatingips', {})

    def _migrate_router_ports(self, context, router_db, old_owner, new_owner):
        """Update the model to support the dvr case of a router."""
        for rp in router_db.attached_ports:
            if rp.port_type == old_owner:
                rp.port_type = new_owner
                rp.port.device_owner = new_owner
