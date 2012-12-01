# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
# @author: Dan Wendlandt, Nicira, Inc
#

import netaddr
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr
import webob.exc as w_exc

from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum.db import db_base_plugin_v2
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import l3
from quantum.openstack.common import cfg
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils
from quantum import policy


LOG = logging.getLogger(__name__)

l3_opts = [
    cfg.StrOpt('metadata_ip_address', default='127.0.0.1'),
    cfg.IntOpt('metadata_port', default=8775)
]

# Register the configuration options
cfg.CONF.register_opts(l3_opts)

DEVICE_OWNER_ROUTER_INTF = "network:router_interface"
DEVICE_OWNER_ROUTER_GW = "network:router_gateway"
DEVICE_OWNER_FLOATINGIP = "network:floatingip"


class Router(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 quantum router."""
    name = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    gw_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    gw_port = orm.relationship(models_v2.Port)


class ExternalNetwork(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)


class FloatingIP(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a floating IP, which may or many not be
       allocated to a tenant, and may or may not be associated with
       an internal port/ip address/router.
    """
    floating_ip_address = sa.Column(sa.String(64), nullable=False)
    floating_network_id = sa.Column(sa.String(36), nullable=False)
    floating_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'),
                                 nullable=False)
    fixed_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    fixed_ip_address = sa.Column(sa.String(64))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'))


class L3_NAT_db_mixin(l3.RouterPluginBase):
    """Mixin class to add L3/NAT router methods to db_plugin_base_v2"""

    def _network_model_hook(self, context, original_model, query):
        query = query.outerjoin(ExternalNetwork,
                                (original_model.id ==
                                 ExternalNetwork.network_id))
        return query

    def _network_filter_hook(self, context, original_model, conditions):
        if conditions is not None and not hasattr(conditions, '__iter__'):
            conditions = (conditions, )
        # Apply the external network filter only in non-admin context
        if not context.is_admin and hasattr(original_model, 'tenant_id'):
            conditions = expr.or_(ExternalNetwork.network_id != expr.null(),
                                  *conditions)
        return conditions

    # TODO(salvatore-orlando): Perform this operation without explicitly
    # referring to db_base_plugin_v2, as plugins that do not extend from it
    # might exist in the future
    db_base_plugin_v2.QuantumDbPluginV2.register_model_query_hook(
        models_v2.Network,
        "external_net",
        _network_model_hook,
        _network_filter_hook)

    def _get_router(self, context, id):
        try:
            router = self._get_by_id(context, Router, id)
        except exc.NoResultFound:
            raise l3.RouterNotFound(router_id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple routers match for %s' % id)
            raise l3.RouterNotFound(router_id=id)
        return router

    def _make_router_dict(self, router, fields=None):
        res = {'id': router['id'],
               'name': router['name'],
               'tenant_id': router['tenant_id'],
               'admin_state_up': router['admin_state_up'],
               'status': router['status'],
               'external_gateway_info': None}
        if router['gw_port_id']:
            nw_id = router.gw_port['network_id']
            res['external_gateway_info'] = {'network_id': nw_id}
        return self._fields(res, fields)

    def create_router(self, context, router):
        r = router['router']
        has_gw_info = False
        if 'external_gateway_info' in r:
            has_gw_info = True
            gw_info = r['external_gateway_info']
            del r['external_gateway_info']
        tenant_id = self._get_tenant_id_for_create(context, r)
        with context.session.begin(subtransactions=True):
            # pre-generate id so it will be available when
            # configuring external gw port
            router_db = Router(id=uuidutils.generate_uuid(),
                               tenant_id=tenant_id,
                               name=r['name'],
                               admin_state_up=r['admin_state_up'],
                               status="ACTIVE")
            context.session.add(router_db)
            if has_gw_info:
                self._update_router_gw_info(context, router_db['id'], gw_info)
        return self._make_router_dict(router_db)

    def update_router(self, context, id, router):
        r = router['router']
        has_gw_info = False
        if 'external_gateway_info' in r:
            has_gw_info = True
            gw_info = r['external_gateway_info']
            del r['external_gateway_info']
        with context.session.begin(subtransactions=True):
            if has_gw_info:
                self._update_router_gw_info(context, id, gw_info)
            router_db = self._get_router(context, id)
            # Ensure we actually have something to update
            if r.keys():
                router_db.update(r)
        return self._make_router_dict(router_db)

    def _update_router_gw_info(self, context, router_id, info):
        # TODO(salvatore-orlando): guarantee atomic behavior also across
        # operations that span beyond the model classes handled by this
        # class (e.g.: delete_port)
        router = self._get_router(context, router_id)
        gw_port = router.gw_port

        network_id = info.get('network_id', None) if info else None
        if network_id:
            self._get_network(context, network_id)
            if not self._network_is_external(context, network_id):
                msg = "Network %s is not a valid external network" % network_id
                raise q_exc.BadRequest(resource='router', msg=msg)

        # figure out if we need to delete existing port
        if gw_port and gw_port['network_id'] != network_id:
            fip_count = self.get_floatingips_count(context.elevated(),
                                                   {'router_id': [router_id]})
            if fip_count:
                raise l3.RouterExternalGatewayInUseByFloatingIp(
                    router_id=router_id, net_id=gw_port['network_id'])
            with context.session.begin(subtransactions=True):
                router.gw_port = None
                context.session.add(router)
            self.delete_port(context.elevated(), gw_port['id'],
                             l3_port_check=False)

        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            subnets = self._get_subnets_by_network(context,
                                                   network_id)
            for subnet in subnets:
                self._check_for_dup_router_subnet(context, router_id,
                                                  network_id, subnet['id'])

            # Port has no 'tenant-id', as it is hidden from user
            gw_port = self.create_port(context.elevated(), {
                'port':
                {'tenant_id': '',  # intentionally not set
                 'network_id': network_id,
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                 'device_id': router_id,
                 'device_owner': DEVICE_OWNER_ROUTER_GW,
                 'admin_state_up': True,
                 'name': ''}})

            if not len(gw_port['fixed_ips']):
                self.delete_port(context.elevated(), gw_port['id'],
                                 l3_port_check=False)
                msg = ('No IPs available for external network %s' %
                       network_id)
                raise q_exc.BadRequest(resource='router', msg=msg)

            with context.session.begin(subtransactions=True):
                router.gw_port = self._get_port(context.elevated(),
                                                gw_port['id'])
                context.session.add(router)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)

            # Ensure that the router is not used
            fips = self.get_floatingips_count(context.elevated(),
                                              filters={'router_id': [id]})
            if fips:
                raise l3.RouterInUse(router_id=id)

            device_filter = {'device_id': [id],
                             'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=id)

            # delete any gw port
            device_filter = {'device_id': [id],
                             'device_owner': [DEVICE_OWNER_ROUTER_GW]}
            ports = self.get_ports(context.elevated(), filters=device_filter)
            if ports:
                self._delete_port(context.elevated(), ports[0]['id'])

            context.session.delete(router)

    def get_router(self, context, id, fields=None):
        router = self._get_router(context, id)
        return self._make_router_dict(router, fields)

    def get_routers(self, context, filters=None, fields=None):
        return self._get_collection(context, Router,
                                    self._make_router_dict,
                                    filters=filters, fields=fields)

    def get_routers_count(self, context, filters=None):
        return self._get_collection_count(context, Router,
                                          filters=filters)

    def _check_for_dup_router_subnet(self, context, router_id,
                                     network_id, subnet_id):
        try:
            rport_qry = context.session.query(models_v2.Port)
            rports = rport_qry.filter_by(
                device_id=router_id).all()
            # its possible these ports on on the same network, but
            # different subnet
            new_cidr = self._get_subnet(context, subnet_id)['cidr']
            new_ipnet = netaddr.IPNetwork(new_cidr)
            for p in rports:
                for ip in p['fixed_ips']:
                    if ip['subnet_id'] == subnet_id:
                        msg = ("Router already has a port on subnet %s"
                               % subnet_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)
                    cidr = self._get_subnet(context.elevated(),
                                            ip['subnet_id'])['cidr']
                    ipnet = netaddr.IPNetwork(cidr)
                    match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                    match2 = netaddr.all_matching_cidrs(ipnet, [new_cidr])
                    if match1 or match2:
                        msg = (("Cidr %s of subnet %s is overlapped "
                                + "with cidr %s of subnet %s")
                               % (new_cidr, subnet_id, cidr, ip['subnet_id']))
                        raise q_exc.BadRequest(resource='router', msg=msg)
        except exc.NoResultFound:
            pass

    def add_router_interface(self, context, router_id, interface_info):
        # make sure router exists
        router = self._get_router(context, router_id)
        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)

        try:
            policy.enforce(context,
                           "extension:router:add_router_interface",
                           self._make_router_dict(router))
        except q_exc.PolicyNotAuthorized:
            raise l3.RouterNotFound(router_id=router_id)

        if 'port_id' in interface_info:
            if 'subnet_id' in interface_info:
                msg = "cannot specify both subnet-id and port-id"
                raise q_exc.BadRequest(resource='router', msg=msg)

            port = self._get_port(context, interface_info['port_id'])
            if port['device_id']:
                raise q_exc.PortInUse(net_id=port['network_id'],
                                      port_id=port['id'],
                                      device_id=port['device_id'])
            fixed_ips = [ip for ip in port['fixed_ips']]
            if len(fixed_ips) != 1:
                msg = 'Router port must have exactly one fixed IP'
                raise q_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router_id,
                                              port['network_id'],
                                              fixed_ips[0]['subnet_id'])
            with context.session.begin(subtransactions=True):
                port.update({'device_id': router_id,
                             'device_owner': DEVICE_OWNER_ROUTER_INTF})
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            subnet = self._get_subnet(context, subnet_id)
            # Ensure the subnet has a gateway
            if not subnet['gateway_ip']:
                msg = 'Subnet for router interface must have a gateway IP'
                raise q_exc.BadRequest(resource='router', msg=msg)
            self._check_for_dup_router_subnet(context, router_id,
                                              subnet['network_id'], subnet_id)
            fixed_ip = {'ip_address': subnet['gateway_ip'],
                        'subnet_id': subnet['id']}
            port = self.create_port(context, {
                'port':
                {'tenant_id': subnet['tenant_id'],
                 'network_id': subnet['network_id'],
                 'fixed_ips': [fixed_ip],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'admin_state_up': True,
                 'device_id': router_id,
                 'device_owner': DEVICE_OWNER_ROUTER_INTF,
                 'name': ''}})
        return {'port_id': port['id'],
                'subnet_id': port['fixed_ips'][0]['subnet_id']}

    def _confirm_router_interface_not_in_use(self, context, router_id,
                                             subnet_id):
        subnet_db = self._get_subnet(context, subnet_id)
        subnet_cidr = netaddr.IPNetwork(subnet_db['cidr'])
        fip_qry = context.session.query(FloatingIP)
        for fip_db in fip_qry.filter_by(router_id=router_id):
            if netaddr.IPAddress(fip_db['fixed_ip_address']) in subnet_cidr:
                raise l3.RouterInterfaceInUseByFloatingIP(
                    router_id=router_id, subnet_id=subnet_id)

    def remove_router_interface(self, context, router_id, interface_info):
        # make sure router exists
        router = self._get_router(context, router_id)
        try:
            policy.enforce(context,
                           "extension:router:remove_router_interface",
                           self._make_router_dict(router))
        except q_exc.PolicyNotAuthorized:
            raise l3.RouterNotFound(router_id=router_id)

        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port_id = interface_info['port_id']
            port_db = self._get_port(context, port_id)
            if not (port_db['device_owner'] == DEVICE_OWNER_ROUTER_INTF and
                    port_db['device_id'] == router_id):
                raise w_exc.HTTPNotFound("Router %(router_id)s does not have "
                                         " an interface with id %(port_id)s"
                                         % locals())
            if 'subnet_id' in interface_info:
                port_subnet_id = port_db['fixed_ips'][0]['subnet_id']
                if port_subnet_id != interface_info['subnet_id']:
                    raise w_exc.HTTPConflict("subnet_id %s on port does not "
                                             "match requested one (%s)"
                                             % (port_subnet_id,
                                                interface_info['subnet_id']))
            if port_db['device_id'] != router_id:
                raise w_exc.HTTPConflict("port_id %s not used by router" %
                                         port_db['id'])
            self._confirm_router_interface_not_in_use(
                context, router_id,
                port_db['fixed_ips'][0]['subnet_id'])
            self.delete_port(context, port_db['id'], l3_port_check=False)
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
            self._confirm_router_interface_not_in_use(context, router_id,
                                                      subnet_id)

            subnet = self._get_subnet(context, subnet_id)
            found = False

            try:
                rport_qry = context.session.query(models_v2.Port)
                ports = rport_qry.filter_by(
                    device_id=router_id,
                    device_owner=DEVICE_OWNER_ROUTER_INTF,
                    network_id=subnet['network_id']).all()

                for p in ports:
                    if p['fixed_ips'][0]['subnet_id'] == subnet_id:
                        self.delete_port(context, p['id'], l3_port_check=False)
                        found = True
                        break
            except exc.NoResultFound:
                pass

            if not found:
                raise w_exc.HTTPNotFound("Router %(router_id)s has no "
                                         "interface on subnet %(subnet_id)s"
                                         % locals())

    def _get_floatingip(self, context, id):
        try:
            floatingip = self._get_by_id(context, FloatingIP, id)
        except exc.NoResultFound:
            raise l3.FloatingIPNotFound(floatingip_id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple floating ips match for %s' % id)
            raise l3.FloatingIPNotFound(floatingip_id=id)
        return floatingip

    def _make_floatingip_dict(self, floatingip, fields=None):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address']}
        return self._fields(res, fields)

    def _get_router_for_floatingip(self, context, internal_port,
                                   internal_subnet_id,
                                   external_network_id):
        subnet_db = self._get_subnet(context, internal_subnet_id)
        if not subnet_db['gateway_ip']:
            msg = ('Cannot add floating IP to port on subnet %s '
                   'which has no gateway_ip' % internal_subnet_id)
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        # find router interface ports on this network
        router_intf_qry = context.session.query(models_v2.Port)
        router_intf_ports = router_intf_qry.filter_by(
            network_id=internal_port['network_id'],
            device_owner=DEVICE_OWNER_ROUTER_INTF)

        for intf_p in router_intf_ports:
            if intf_p['fixed_ips'][0]['subnet_id'] == internal_subnet_id:
                router_id = intf_p['device_id']
                router_gw_qry = context.session.query(models_v2.Port)
                has_gw_port = router_gw_qry.filter_by(
                    network_id=external_network_id,
                    device_id=router_id,
                    device_owner=DEVICE_OWNER_ROUTER_GW).count()
                if has_gw_port:
                    return router_id

        raise l3.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet_id,
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def get_assoc_data(self, context, fip, floating_network_id):
        """When a floating IP is associated with an internal port,
        we need to extract/determine some data associated with the
        internal port, including the internal_ip_address, and router_id.
        We also need to confirm that this internal port is owned by the
        tenant who owns the floating IP.
        """
        internal_port = self._get_port(context, fip['port_id'])
        if not internal_port['tenant_id'] == fip['tenant_id']:
            port_id = fip['port_id']
            if 'id' in fip:
                floatingip_id = fip['id']
                msg = _('Port %(port_id)s is associated with a different '
                        'tenant than Floating IP %(floatingip_id)s and '
                        'therefore cannot be bound.')
            else:
                msg = _('Cannnot create floating IP and bind it to '
                        'Port %(port_id)s, since that port is owned by a '
                        'different tenant.')
            raise q_exc.BadRequest(resource='floatingip', msg=msg % locals())

        internal_subnet_id = None
        if 'fixed_ip_address' in fip and fip['fixed_ip_address']:
            internal_ip_address = fip['fixed_ip_address']
            for ip in internal_port['fixed_ips']:
                if ip['ip_address'] == internal_ip_address:
                    internal_subnet_id = ip['subnet_id']
            if not internal_subnet_id:
                msg = ('Port %s does not have fixed ip %s' %
                       (internal_port['id'], internal_ip_address))
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
        else:
            ips = [ip['ip_address'] for ip in internal_port['fixed_ips']]
            if len(ips) == 0:
                msg = ('Cannot add floating IP to port %s that has'
                       'no fixed IP addresses' % internal_port['id'])
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
            if len(ips) > 1:
                msg = ('Port %s has multiple fixed IPs.  Must provide'
                       ' a specific IP when assigning a floating IP' %
                       internal_port['id'])
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
            internal_ip_address = internal_port['fixed_ips'][0]['ip_address']
            internal_subnet_id = internal_port['fixed_ips'][0]['subnet_id']

        router_id = self._get_router_for_floatingip(context,
                                                    internal_port,
                                                    internal_subnet_id,
                                                    floating_network_id)
        # confirm that this router has a floating
        # ip enabled gateway with support for this floating IP network
        try:
            port_qry = context.elevated().session.query(models_v2.Port)
            ports = port_qry.filter_by(
                network_id=floating_network_id,
                device_id=router_id,
                device_owner=DEVICE_OWNER_ROUTER_GW).one()
        except exc.NoResultFound:
            raise l3.ExternalGatewayForFloatingIPNotFound(
                subnet_id=internal_subnet_id,
                port_id=internal_port['id'])

        return (fip['port_id'], internal_ip_address, router_id)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        port_id = internal_ip_address = router_id = None
        if (('fixed_ip_address' in fip and fip['fixed_ip_address']) and
            not ('port_id' in fip and fip['port_id'])):
            msg = "fixed_ip_address cannot be specified without a port_id"
            raise q_exc.BadRequest(resource='floatingip', msg=msg)
        if 'port_id' in fip and fip['port_id']:
            port_id, internal_ip_address, router_id = self.get_assoc_data(
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
        floatingip_db.update({'fixed_ip_address': internal_ip_address,
                              'fixed_port_id': port_id,
                              'router_id': router_id})

    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        tenant_id = self._get_tenant_id_for_create(context, fip)
        fip_id = uuidutils.generate_uuid()

        f_net_id = fip['floating_network_id']
        if not self._network_is_external(context, f_net_id):
            msg = "Network %s is not a valid external network" % f_net_id
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        try:
            with context.session.begin(subtransactions=True):
                # This external port is never exposed to the tenant.
                # it is used purely for internal system and admin use when
                # managing floating IPs.
                external_port = self.create_port(context.elevated(), {
                    'port':
                    {'tenant_id': '',  # tenant intentionally not set
                     'network_id': f_net_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                     'admin_state_up': True,
                     'device_id': fip_id,
                     'device_owner': DEVICE_OWNER_FLOATINGIP,
                     'name': ''}})
                # Ensure IP addresses are allocated on external port
                if not external_port['fixed_ips']:
                    msg = "Unable to find any IP address on external network"
                    raise q_exc.BadRequest(resource='floatingip', msg=msg)

                floating_fixed_ip = external_port['fixed_ips'][0]
                floating_ip_address = floating_fixed_ip['ip_address']
                floatingip_db = FloatingIP(
                    id=fip_id,
                    tenant_id=tenant_id,
                    floating_network_id=fip['floating_network_id'],
                    floating_ip_address=floating_ip_address,
                    floating_port_id=external_port['id'])
                fip['tenant_id'] = tenant_id
                # Update association with internal port
                # and define external IP address
                self._update_fip_assoc(context, fip,
                                       floatingip_db, external_port)
                context.session.add(floatingip_db)
        # TODO(salvatore-orlando): Avoid broad catch
        # Maybe by introducing base class for L3 exceptions
        except q_exc.BadRequest:
            LOG.exception(_("Unable to create Floating ip due to a "
                          "malformed request"))
            raise
        except Exception:
            LOG.exception(_("Floating IP association failed"))
            raise

        return self._make_floatingip_dict(floatingip_db)

    def update_floatingip(self, context, id, floatingip):
        fip = floatingip['floatingip']
        with context.session.begin(subtransactions=True):
            floatingip_db = self._get_floatingip(context, id)
            fip['tenant_id'] = floatingip_db['tenant_id']
            fip['id'] = id
            fip_port_id = floatingip_db['floating_port_id']
            self._update_fip_assoc(context, fip, floatingip_db,
                                   self.get_port(context.elevated(),
                                                 fip_port_id))
        return self._make_floatingip_dict(floatingip_db)

    def delete_floatingip(self, context, id):
        floatingip = self._get_floatingip(context, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(floatingip)
            self.delete_port(context.elevated(),
                             floatingip['floating_port_id'],
                             l3_port_check=False)

    def get_floatingip(self, context, id, fields=None):
        floatingip = self._get_floatingip(context, id)
        return self._make_floatingip_dict(floatingip, fields)

    def get_floatingips(self, context, filters=None, fields=None):
        return self._get_collection(context, FloatingIP,
                                    self._make_floatingip_dict,
                                    filters=filters, fields=fields)

    def get_floatingips_count(self, context, filters=None):
        return self._get_collection_count(context, FloatingIP,
                                          filters=filters)

    def prevent_l3_port_deletion(self, context, port_id):
        """ Checks to make sure a port is allowed to be deleted, raising
        an exception if this is not the case.  This should be called by
        any plugin when the API requests the deletion of a port, since
        some ports for L3 are not intended to be deleted directly via a
        DELETE to /ports, but rather via other API calls that perform the
        proper deletion checks.
        """
        port_db = self._get_port(context, port_id)
        if port_db['device_owner'] in [DEVICE_OWNER_ROUTER_INTF,
                                       DEVICE_OWNER_ROUTER_GW,
                                       DEVICE_OWNER_FLOATINGIP]:
            raise l3.L3PortInUse(port_id=port_id,
                                 device_owner=port_db['device_owner'])

    def disassociate_floatingips(self, context, port_id):
        with context.session.begin(subtransactions=True):
            try:
                fip_qry = context.session.query(FloatingIP)
                floating_ip = fip_qry.filter_by(fixed_port_id=port_id).one()
                floating_ip.update({'fixed_port_id': None,
                                    'fixed_ip_address': None,
                                    'router_id': None})
            except exc.NoResultFound:
                return
            except exc.MultipleResultsFound:
                # should never happen
                raise Exception('Multiple floating IPs found for port %s'
                                % port_id)

    def _check_l3_view_auth(self, context, network):
        return policy.check(context,
                            "extension:router:view",
                            network)

    def _enforce_l3_set_auth(self, context, network):
        return policy.enforce(context,
                              "extension:router:set",
                              network)

    def _network_is_external(self, context, net_id):
        try:
            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def _extend_network_dict_l3(self, context, network):
        if self._check_l3_view_auth(context, network):
            network[l3.EXTERNAL] = self._network_is_external(
                context, network['id'])

    def _process_l3_create(self, context, net_data, net_id):
        external = net_data.get(l3.EXTERNAL)
        external_set = attributes.is_attr_set(external)

        if not external_set:
            return

        self._enforce_l3_set_auth(context, net_data)

        if external:
            # expects to be called within a plugin's session
            context.session.add(ExternalNetwork(network_id=net_id))

    def _process_l3_update(self, context, net_data, net_id):

        new_value = net_data.get(l3.EXTERNAL)
        if not attributes.is_attr_set(new_value):
            return

        self._enforce_l3_set_auth(context, net_data)
        existing_value = self._network_is_external(context, net_id)

        if existing_value == new_value:
            return

        if new_value:
            context.session.add(ExternalNetwork(network_id=net_id))
        else:
            # must make sure we do not have any external gateway ports
            # (and thus, possible floating IPs) on this network before
            # allow it to be update to external=False
            port = context.session.query(models_v2.Port).filter_by(
                device_owner=DEVICE_OWNER_ROUTER_GW,
                network_id=net_id).first()
            if port:
                raise l3.ExternalNetworkInUse(net_id=net_id)

            context.session.query(ExternalNetwork).filter_by(
                network_id=net_id).delete()

    def _filter_nets_l3(self, context, nets, filters):
        vals = filters and filters.get('router:external', [])
        if not vals:
            return nets

        ext_nets = set([en['network_id'] for en in
                        context.session.query(ExternalNetwork).all()])
        if vals[0]:
            return [n for n in nets if n['id'] in ext_nets]
        else:
            return [n for n in nets if n['id'] not in ext_nets]
