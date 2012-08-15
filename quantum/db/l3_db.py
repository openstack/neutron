"""
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
"""

import logging

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
import webob.exc as w_exc

from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum.common import utils
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import l3
from quantum.openstack.common import cfg


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
    gw_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id',
                                                        ondelete="CASCADE"))
    gw_port = orm.relationship(models_v2.Port)


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

    def _get_router(self, context, id, verbose=None):
        try:
            router = self._get_by_id(context, Router, id, verbose=verbose)
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
            router_db = Router(id=utils.str_uuid(),
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
            #FIXME(danwent): confirm net-id is valid external network
            self._get_network(context, network_id)

        # figure out if we need to delete existing port
        if gw_port and gw_port['network_id'] != network_id:
            with context.session.begin(subtransactions=True):
                router.update({'gw_port_id': None})
                context.session.add(router)
            self.delete_port(context, gw_port['id'])

        if network_id is not None and (gw_port is None or
                                       gw_port['network_id'] != network_id):
            # Port has no 'tenant-id', as it is hidden from user
            gw_port = self.create_port(context, {
                'port':
                {'network_id': network_id,
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
                 'device_id': router_id,
                 'device_owner': DEVICE_OWNER_ROUTER_GW,
                 'admin_state_up': True,
                 'name': ''}})

            if not len(gw_port['fixed_ips']):
                self.delete_port(context, gw_port['id'])
                msg = ('No IPs available for external network %s' %
                       network_id)
                raise q_exc.BadRequest(resource='router', msg=msg)

            with context.session.begin(subtransactions=True):
                router.update({'gw_port_id': gw_port['id']})
                context.session.add(router)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            router = self._get_router(context, id)

            device_filter = {'device_id': [id],
                             'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
            ports = self.get_ports(context, filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=id)
            # NOTE(salvatore-orlando): gw port will be automatically deleted
            # thanks to cascading on the ORM relationship
            context.session.delete(router)

    def get_router(self, context, id, fields=None, verbose=None):
        router = self._get_router(context, id, verbose=verbose)
        return self._make_router_dict(router, fields)

    def get_routers(self, context, filters=None, fields=None, verbose=None):
        return self._get_collection(context, Router,
                                    self._make_router_dict,
                                    filters=filters, fields=fields,
                                    verbose=verbose)

    def _check_for_dup_router_subnet(self, context, router_id,
                                     network_id, subnet_id):
        try:
            rport_qry = context.session.query(models_v2.Port)
            rports = rport_qry.filter_by(
                device_id=router_id,
                device_owner=DEVICE_OWNER_ROUTER_INTF,
                network_id=network_id).all()
            # its possible these ports on on the same network, but
            # different subnet
            for p in rports:
                for ip in p['fixed_ips']:
                    if ip['subnet_id'] == subnet_id:
                        msg = ("Router already has a port on subnet %s"
                               % subnet_id)
                        raise q_exc.BadRequest(resource='router', msg=msg)

        except exc.NoResultFound:
            pass

    def add_router_interface(self, context, router_id, interface_info):
        # make sure router exists - will raise if not
        self._get_router(context, router_id)
        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)

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
                {'network_id': subnet['network_id'],
                 'fixed_ips': [fixed_ip],
                 'mac_address': attributes.ATTR_NOT_SPECIFIED,
                 'admin_state_up': True,
                 'device_id': router_id,
                 'device_owner': DEVICE_OWNER_ROUTER_INTF,
                 'name': ''}})
        return {'port_id': port['id'],
                'subnet_id': port['fixed_ips'][0]['subnet_id']}

    def remove_router_interface(self, context, router_id, interface_info):
        # make sure router exists
        router = self._get_router(context, router_id)

        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise q_exc.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port_db = self._get_port(context, interface_info['port_id'])
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
            self.delete_port(context, port_db['id'])
        elif 'subnet_id' in interface_info:
            subnet_id = interface_info['subnet_id']
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
                        self.delete_port(context, p['id'])
                        found = True
                        break
            except exc.NoResultFound:
                pass

            if not found:
                raise w_exc.HTTPNotFound("Router %(router_id)s has no "
                                         "interface on subnet %(subnet_id)s"
                                         % locals())

    def _get_floatingip(self, context, id, verbose=None):
        try:
            floatingip = self._get_by_id(context, FloatingIP, id,
                                         verbose=verbose)
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

    def _get_router_for_internal_subnet(self, context, internal_port,
                                        internal_subnet_id):
        subnet_db = self._get_subnet(context, internal_subnet_id)
        if not subnet_db['gateway_ip']:
            msg = ('Cannot add floating IP to port on subnet %s '
                   'which has no gateway_ip' % internal_subnet_id)
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        #FIXME(danwent): can do join, but cannot use standard F-K syntax?
        # just do it inefficiently for now
        port_qry = context.session.query(models_v2.Port)
        ports = port_qry.filter_by(network_id=internal_port['network_id'])
        for p in ports:
            ips = [ip['ip_address'] for ip in p['fixed_ips']]
            if len(ips) != 1:
                continue
            fixed = p['fixed_ips'][0]
            if (fixed['ip_address'] == subnet_db['gateway_ip'] and
                    fixed['subnet_id'] == internal_subnet_id):
                router_qry = context.session.query(Router)
                try:
                    router = router_qry.filter_by(id=p['device_id']).one()
                    #TODO(danwent): confirm that this router has a floating
                    # ip enabled gateway with support for this floating IP
                    # network
                    return router['id']
                except exc.NoResultFound:
                    pass

        raise l3.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet_id,
            port_id=internal_port['id'])

    def get_assoc_data(self, context, fip):
        """When a floating IP is associated with an internal port,
        we need to extract/determine some data associated with the
        internal port, including the internal_ip_address, and router_id.
        We also need to confirm that this internal port is owned by the
        tenant who owns the floating IP.
        """
        internal_port = self._get_port(context, fip['port_id'])
        if not internal_port['tenant_id'] == fip['tenant_id']:
            msg = ('Port %s is associated with a different tenant'
                   'and therefore cannot be found to floating IP %s'
                   % (fip['port_id'], fip['id']))
            raise q_exc.BadRequest(resource='floating', msg=msg)

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

        router_id = self._get_router_for_internal_subnet(context,
                                                         internal_port,
                                                         internal_subnet_id)
        return (fip['port_id'], internal_ip_address, router_id)

    def _update_fip_assoc(self, context, fip, floatingip_db, external_port):
        port_id = internal_ip_address = router_id = None
        if 'port_id' in fip and fip['port_id']:
            port_qry = context.session.query(FloatingIP)
            try:
                port_qry.filter_by(fixed_port_id=fip['port_id']).one()
                raise l3.FloatingIPPortAlreadyAssociated(
                    port_id=fip['port_id'])
            except exc.NoResultFound:
                pass
            port_id, internal_ip_address, router_id = self.get_assoc_data(
                context,
                fip)
            # Assign external address for floating IP
            # fetch external gateway port
            ports = self.get_ports(context, filters={'device_id': [router_id]})
            if not ports:
                msg = ("The router %s needed for association a floating ip "
                       "to port %s does not have an external gateway"
                       % (router_id, port_id))
                raise q_exc.BadRequest(resource='floatingip', msg=msg)
            # retrieve external subnet identifier
            # NOTE: by design we cannot have more than 1 IP on ext gw port
            ext_subnet_id = ports[0]['fixed_ips'][0]['subnet_id']
            # ensure floating ip address is taken from this subnet
            for fixed_ip in external_port['fixed_ips']:
                if fixed_ip['subnet_id'] == ext_subnet_id:
                    floatingip_db.update(
                        {'floating_ip_address': fixed_ip['ip_address'],
                         'floating_port_id': external_port['id']})
        else:
            # fallback choice (first IP address on external port)
            floatingip_db.update(
                {'floating_ip_address':
                    external_port['fixed_ips'][0]['ip_address'],
                 'floating_port_id':
                    external_port['id']})

        floatingip_db.update({'fixed_ip_address': internal_ip_address,
                              'fixed_port_id': port_id,
                              'router_id': router_id})

    def create_floatingip(self, context, floatingip):
        fip = floatingip['floatingip']
        tenant_id = self._get_tenant_id_for_create(context, fip)
        fip_id = utils.str_uuid()

        #TODO(danwent): validate that network_id is valid floatingip-network

        # This external port is never exposed to the tenant.
        # it is used purely for internal system and admin use when
        # managing floating IPs.
        external_port = self.create_port(context, {
            'port':
            {'network_id': fip['floating_network_id'],
             'mac_address': attributes.ATTR_NOT_SPECIFIED,
             'fixed_ips': attributes.ATTR_NOT_SPECIFIED,
             'admin_state_up': True,
             'device_id': fip_id,
             'device_owner': DEVICE_OWNER_FLOATINGIP,
             'name': ''}})
        # Ensure IP addresses are allocated on external port
        if not external_port['fixed_ips']:
            msg = "Unable to find any IP address on external network"
            # remove the external port
            self.delete_port(context, external_port['id'])
            raise q_exc.BadRequest(resource='floatingip', msg=msg)

        try:
            with context.session.begin(subtransactions=True):
                floatingip_db = FloatingIP(
                    id=fip_id,
                    tenant_id=tenant_id,
                    floating_network_id=fip['floating_network_id'])
                fip['tenant_id'] = tenant_id
                # Update association with internal port
                # and define external IP address
                self._update_fip_assoc(context, fip,
                                       floatingip_db, external_port)
                context.session.add(floatingip_db)
        # TODO(salvatore-orlando): Avoid broad catch
        # Maybe by introducing base class for L3 exceptions
        except Exception:
            LOG.exception("Floating IP association failed")
            # Remove the port created for internal purposes
            self.delete_port(context, external_port['id'])
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
                                   self.get_port(context, fip_port_id))
        return self._make_floatingip_dict(floatingip_db)

    def delete_floatingip(self, context, id):
        floatingip = self._get_floatingip(context, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(floatingip)
        self.delete_port(context, floatingip['floating_port_id'])

    def get_floatingip(self, context, id, fields=None, verbose=None):
        floatingip = self._get_floatingip(context, id, verbose=verbose)
        return self._make_floatingip_dict(floatingip, fields)

    def get_floatingips(self, context, filters=None, fields=None,
                        verbose=None):
        return self._get_collection(context, FloatingIP,
                                    self._make_floatingip_dict,
                                    filters=filters, fields=fields,
                                    verbose=verbose)

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
