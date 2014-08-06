#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

import netaddr
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.common import constants as n_constants
from neutron.db import common_db_mixin as base_db
from neutron.db import l3_agentschedulers_db as l3_agent_db
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db.vpn import vpn_validator
from neutron.extensions import vpnaas
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.plugins.common import utils

LOG = logging.getLogger(__name__)


class IPsecPeerCidr(model_base.BASEV2):
    """Internal representation of a IPsec Peer Cidrs."""

    cidr = sa.Column(sa.String(32), nullable=False, primary_key=True)
    ipsec_site_connection_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ipsec_site_connections.id',
                      ondelete="CASCADE"),
        primary_key=True)


class IPsecPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 IPsecPolicy Object."""
    __tablename__ = 'ipsecpolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    transform_protocol = sa.Column(sa.Enum("esp", "ah", "ah-esp",
                                           name="ipsec_transform_protocols"),
                                   nullable=False)
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    encapsulation_mode = sa.Column(sa.Enum("tunnel", "transport",
                                           name="ipsec_encapsulations"),
                                   nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


class IKEPolicy(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 IKEPolicy Object."""
    __tablename__ = 'ikepolicies'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    auth_algorithm = sa.Column(sa.Enum("sha1",
                                       name="vpn_auth_algorithms"),
                               nullable=False)
    encryption_algorithm = sa.Column(sa.Enum("3des", "aes-128",
                                             "aes-256", "aes-192",
                                             name="vpn_encrypt_algorithms"),
                                     nullable=False)
    phase1_negotiation_mode = sa.Column(sa.Enum("main",
                                                name="ike_phase1_mode"),
                                        nullable=False)
    lifetime_units = sa.Column(sa.Enum("seconds", "kilobytes",
                                       name="vpn_lifetime_units"),
                               nullable=False)
    lifetime_value = sa.Column(sa.Integer, nullable=False)
    ike_version = sa.Column(sa.Enum("v1", "v2", name="ike_versions"),
                            nullable=False)
    pfs = sa.Column(sa.Enum("group2", "group5", "group14",
                            name="vpn_pfs"), nullable=False)


class IPsecSiteConnection(model_base.BASEV2,
                          models_v2.HasId, models_v2.HasTenant):
    """Represents a IPsecSiteConnection Object."""
    __tablename__ = 'ipsec_site_connections'
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    peer_address = sa.Column(sa.String(255), nullable=False)
    peer_id = sa.Column(sa.String(255), nullable=False)
    route_mode = sa.Column(sa.String(8), nullable=False)
    mtu = sa.Column(sa.Integer, nullable=False)
    initiator = sa.Column(sa.Enum("bi-directional", "response-only",
                                  name="vpn_initiators"), nullable=False)
    auth_mode = sa.Column(sa.String(16), nullable=False)
    psk = sa.Column(sa.String(255), nullable=False)
    dpd_action = sa.Column(sa.Enum("hold", "clear",
                                   "restart", "disabled",
                                   "restart-by-peer", name="vpn_dpd_actions"),
                           nullable=False)
    dpd_interval = sa.Column(sa.Integer, nullable=False)
    dpd_timeout = sa.Column(sa.Integer, nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    vpnservice_id = sa.Column(sa.String(36),
                              sa.ForeignKey('vpnservices.id'),
                              nullable=False)
    ipsecpolicy_id = sa.Column(sa.String(36),
                               sa.ForeignKey('ipsecpolicies.id'),
                               nullable=False)
    ikepolicy_id = sa.Column(sa.String(36),
                             sa.ForeignKey('ikepolicies.id'),
                             nullable=False)
    ipsecpolicy = orm.relationship(
        IPsecPolicy, backref='ipsec_site_connection')
    ikepolicy = orm.relationship(IKEPolicy, backref='ipsec_site_connection')
    peer_cidrs = orm.relationship(IPsecPeerCidr,
                                  backref='ipsec_site_connection',
                                  lazy='joined',
                                  cascade='all, delete, delete-orphan')


class VPNService(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 VPNService Object."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    subnet_id = sa.Column(sa.String(36), sa.ForeignKey('subnets.id'),
                          nullable=False)
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id'),
                          nullable=False)
    subnet = orm.relationship(models_v2.Subnet)
    router = orm.relationship(l3_db.Router)
    ipsec_site_connections = orm.relationship(
        IPsecSiteConnection,
        backref='vpnservice',
        cascade="all, delete-orphan")


class VPNPluginDb(vpnaas.VPNPluginBase, base_db.CommonDbMixin):
    """VPN plugin database class using SQLAlchemy models."""

    def _get_validator(self):
        """Obtain validator to use for attribute validation.

        Subclasses may override this with a different valdiator, as needed.
        Note: some UTs will directly create a VPNPluginDb object and then
        call its methods, instead of creating a VPNDriverPlugin, which
        will have a service driver associated that will provide a
        validator object. As a result, we use the reference validator here.
        """
        return vpn_validator.VpnReferenceValidator()

    def update_status(self, context, model, v_id, status):
        with context.session.begin(subtransactions=True):
            v_db = self._get_resource(context, model, v_id)
            v_db.update({'status': status})

    def _get_resource(self, context, model, v_id):
        try:
            r = self._get_by_id(context, model, v_id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, IPsecSiteConnection):
                    raise vpnaas.IPsecSiteConnectionNotFound(
                        ipsec_site_conn_id=v_id
                    )
                elif issubclass(model, IKEPolicy):
                    raise vpnaas.IKEPolicyNotFound(ikepolicy_id=v_id)
                elif issubclass(model, IPsecPolicy):
                    raise vpnaas.IPsecPolicyNotFound(ipsecpolicy_id=v_id)
                elif issubclass(model, VPNService):
                    raise vpnaas.VPNServiceNotFound(vpnservice_id=v_id)
                ctx.reraise = True
        return r

    def assert_update_allowed(self, obj):
        status = getattr(obj, 'status', None)
        _id = getattr(obj, 'id', None)
        if utils.in_pending_status(status):
            raise vpnaas.VPNStateInvalidToUpdate(id=_id, state=status)

    def _make_ipsec_site_connection_dict(self, ipsec_site_conn, fields=None):

        res = {'id': ipsec_site_conn['id'],
               'tenant_id': ipsec_site_conn['tenant_id'],
               'name': ipsec_site_conn['name'],
               'description': ipsec_site_conn['description'],
               'peer_address': ipsec_site_conn['peer_address'],
               'peer_id': ipsec_site_conn['peer_id'],
               'route_mode': ipsec_site_conn['route_mode'],
               'mtu': ipsec_site_conn['mtu'],
               'auth_mode': ipsec_site_conn['auth_mode'],
               'psk': ipsec_site_conn['psk'],
               'initiator': ipsec_site_conn['initiator'],
               'dpd': {
                   'action': ipsec_site_conn['dpd_action'],
                   'interval': ipsec_site_conn['dpd_interval'],
                   'timeout': ipsec_site_conn['dpd_timeout']
               },
               'admin_state_up': ipsec_site_conn['admin_state_up'],
               'status': ipsec_site_conn['status'],
               'vpnservice_id': ipsec_site_conn['vpnservice_id'],
               'ikepolicy_id': ipsec_site_conn['ikepolicy_id'],
               'ipsecpolicy_id': ipsec_site_conn['ipsecpolicy_id'],
               'peer_cidrs': [pcidr['cidr']
                              for pcidr in ipsec_site_conn['peer_cidrs']]
               }

        return self._fields(res, fields)

    def _get_subnet_ip_version(self, context, vpnservice_id):
        vpn_service_db = self._get_vpnservice(context, vpnservice_id)
        subnet = vpn_service_db.subnet['cidr']
        ip_version = netaddr.IPNetwork(subnet).version
        return ip_version

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        validator = self._get_validator()
        validator.assign_sensible_ipsec_sitecon_defaults(ipsec_sitecon)
        tenant_id = self._get_tenant_id_for_create(context, ipsec_sitecon)
        with context.session.begin(subtransactions=True):
            #Check permissions
            self._get_resource(context,
                               VPNService,
                               ipsec_sitecon['vpnservice_id'])
            self._get_resource(context,
                               IKEPolicy,
                               ipsec_sitecon['ikepolicy_id'])
            self._get_resource(context,
                               IPsecPolicy,
                               ipsec_sitecon['ipsecpolicy_id'])
            vpnservice_id = ipsec_sitecon['vpnservice_id']
            ip_version = self._get_subnet_ip_version(context, vpnservice_id)
            validator.validate_ipsec_site_connection(context,
                                                     ipsec_sitecon,
                                                     ip_version)
            ipsec_site_conn_db = IPsecSiteConnection(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ipsec_sitecon['name'],
                description=ipsec_sitecon['description'],
                peer_address=ipsec_sitecon['peer_address'],
                peer_id=ipsec_sitecon['peer_id'],
                route_mode='static',
                mtu=ipsec_sitecon['mtu'],
                auth_mode='psk',
                psk=ipsec_sitecon['psk'],
                initiator=ipsec_sitecon['initiator'],
                dpd_action=ipsec_sitecon['dpd_action'],
                dpd_interval=ipsec_sitecon['dpd_interval'],
                dpd_timeout=ipsec_sitecon['dpd_timeout'],
                admin_state_up=ipsec_sitecon['admin_state_up'],
                status=constants.PENDING_CREATE,
                vpnservice_id=vpnservice_id,
                ikepolicy_id=ipsec_sitecon['ikepolicy_id'],
                ipsecpolicy_id=ipsec_sitecon['ipsecpolicy_id']
            )
            context.session.add(ipsec_site_conn_db)
            for cidr in ipsec_sitecon['peer_cidrs']:
                peer_cidr_db = IPsecPeerCidr(
                    cidr=cidr,
                    ipsec_site_connection_id=ipsec_site_conn_db['id']
                )
                context.session.add(peer_cidr_db)
        return self._make_ipsec_site_connection_dict(ipsec_site_conn_db)

    def update_ipsec_site_connection(
            self, context,
            ipsec_site_conn_id, ipsec_site_connection):
        ipsec_sitecon = ipsec_site_connection['ipsec_site_connection']
        changed_peer_cidrs = False
        validator = self._get_validator()
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context,
                IPsecSiteConnection,
                ipsec_site_conn_id)
            vpnservice_id = ipsec_site_conn_db['vpnservice_id']
            ip_version = self._get_subnet_ip_version(context, vpnservice_id)
            validator.assign_sensible_ipsec_sitecon_defaults(
                ipsec_sitecon, ipsec_site_conn_db)
            validator.validate_ipsec_site_connection(
                context,
                ipsec_sitecon,
                ip_version)
            self.assert_update_allowed(ipsec_site_conn_db)

            if "peer_cidrs" in ipsec_sitecon:
                changed_peer_cidrs = True
                old_peer_cidr_list = ipsec_site_conn_db['peer_cidrs']
                old_peer_cidr_dict = dict(
                    (peer_cidr['cidr'], peer_cidr)
                    for peer_cidr in old_peer_cidr_list)
                new_peer_cidr_set = set(ipsec_sitecon["peer_cidrs"])
                old_peer_cidr_set = set(old_peer_cidr_dict)

                new_peer_cidrs = list(new_peer_cidr_set)
                for peer_cidr in old_peer_cidr_set - new_peer_cidr_set:
                    context.session.delete(old_peer_cidr_dict[peer_cidr])
                for peer_cidr in new_peer_cidr_set - old_peer_cidr_set:
                    pcidr = IPsecPeerCidr(
                        cidr=peer_cidr,
                        ipsec_site_connection_id=ipsec_site_conn_id)
                    context.session.add(pcidr)
                del ipsec_sitecon["peer_cidrs"]
            if ipsec_sitecon:
                ipsec_site_conn_db.update(ipsec_sitecon)
        result = self._make_ipsec_site_connection_dict(ipsec_site_conn_db)
        if changed_peer_cidrs:
            result['peer_cidrs'] = new_peer_cidrs
        return result

    def delete_ipsec_site_connection(self, context, ipsec_site_conn_id):
        with context.session.begin(subtransactions=True):
            ipsec_site_conn_db = self._get_resource(
                context, IPsecSiteConnection, ipsec_site_conn_id
            )
            context.session.delete(ipsec_site_conn_db)

    def _get_ipsec_site_connection(
            self, context, ipsec_site_conn_id):
        return self._get_resource(
            context, IPsecSiteConnection, ipsec_site_conn_id)

    def get_ipsec_site_connection(self, context,
                                  ipsec_site_conn_id, fields=None):
        ipsec_site_conn_db = self._get_ipsec_site_connection(
            context, ipsec_site_conn_id)
        return self._make_ipsec_site_connection_dict(
            ipsec_site_conn_db, fields)

    def get_ipsec_site_connections(self, context, filters=None, fields=None):
        return self._get_collection(context, IPsecSiteConnection,
                                    self._make_ipsec_site_connection_dict,
                                    filters=filters, fields=fields)

    def update_ipsec_site_conn_status(self, context, conn_id, new_status):
        with context.session.begin():
            self._update_connection_status(context, conn_id, new_status, True)

    def _update_connection_status(self, context, conn_id, new_status,
                                  updated_pending):
        """Update the connection status, if changed.

        If the connection is not in a pending state, unconditionally update
        the status. Likewise, if in a pending state, and have an indication
        that the status has changed, then update the database.
        """
        try:
            conn_db = self._get_ipsec_site_connection(context, conn_id)
        except vpnaas.IPsecSiteConnectionNotFound:
            return
        if not utils.in_pending_status(conn_db.status) or updated_pending:
            conn_db.status = new_status

    def _make_ikepolicy_dict(self, ikepolicy, fields=None):
        res = {'id': ikepolicy['id'],
               'tenant_id': ikepolicy['tenant_id'],
               'name': ikepolicy['name'],
               'description': ikepolicy['description'],
               'auth_algorithm': ikepolicy['auth_algorithm'],
               'encryption_algorithm': ikepolicy['encryption_algorithm'],
               'phase1_negotiation_mode': ikepolicy['phase1_negotiation_mode'],
               'lifetime': {
                   'units': ikepolicy['lifetime_units'],
                   'value': ikepolicy['lifetime_value'],
               },
               'ike_version': ikepolicy['ike_version'],
               'pfs': ikepolicy['pfs']
               }

        return self._fields(res, fields)

    def create_ikepolicy(self, context, ikepolicy):
        ike = ikepolicy['ikepolicy']
        tenant_id = self._get_tenant_id_for_create(context, ike)
        lifetime_info = ike.get('lifetime', [])
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with context.session.begin(subtransactions=True):
            ike_db = IKEPolicy(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=ike['name'],
                description=ike['description'],
                auth_algorithm=ike['auth_algorithm'],
                encryption_algorithm=ike['encryption_algorithm'],
                phase1_negotiation_mode=ike['phase1_negotiation_mode'],
                lifetime_units=lifetime_units,
                lifetime_value=lifetime_value,
                ike_version=ike['ike_version'],
                pfs=ike['pfs']
            )

            context.session.add(ike_db)
        return self._make_ikepolicy_dict(ike_db)

    def update_ikepolicy(self, context, ikepolicy_id, ikepolicy):
        ike = ikepolicy['ikepolicy']
        with context.session.begin(subtransactions=True):
            ikepolicy = context.session.query(IPsecSiteConnection).filter_by(
                ikepolicy_id=ikepolicy_id).first()
            if ikepolicy:
                raise vpnaas.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(context, IKEPolicy, ikepolicy_id)
            if ike:
                lifetime_info = ike.get('lifetime')
                if lifetime_info:
                    if lifetime_info.get('units'):
                        ike['lifetime_units'] = lifetime_info['units']
                    if lifetime_info.get('value'):
                        ike['lifetime_value'] = lifetime_info['value']
                ike_db.update(ike)
        return self._make_ikepolicy_dict(ike_db)

    def delete_ikepolicy(self, context, ikepolicy_id):
        with context.session.begin(subtransactions=True):
            ikepolicy = context.session.query(IPsecSiteConnection).filter_by(
                ikepolicy_id=ikepolicy_id).first()
            if ikepolicy:
                raise vpnaas.IKEPolicyInUse(ikepolicy_id=ikepolicy_id)
            ike_db = self._get_resource(context, IKEPolicy, ikepolicy_id)
            context.session.delete(ike_db)

    def get_ikepolicy(self, context, ikepolicy_id, fields=None):
        ike_db = self._get_resource(context, IKEPolicy, ikepolicy_id)
        return self._make_ikepolicy_dict(ike_db, fields)

    def get_ikepolicies(self, context, filters=None, fields=None):
        return self._get_collection(context, IKEPolicy,
                                    self._make_ikepolicy_dict,
                                    filters=filters, fields=fields)

    def _make_ipsecpolicy_dict(self, ipsecpolicy, fields=None):

        res = {'id': ipsecpolicy['id'],
               'tenant_id': ipsecpolicy['tenant_id'],
               'name': ipsecpolicy['name'],
               'description': ipsecpolicy['description'],
               'transform_protocol': ipsecpolicy['transform_protocol'],
               'auth_algorithm': ipsecpolicy['auth_algorithm'],
               'encryption_algorithm': ipsecpolicy['encryption_algorithm'],
               'encapsulation_mode': ipsecpolicy['encapsulation_mode'],
               'lifetime': {
                   'units': ipsecpolicy['lifetime_units'],
                   'value': ipsecpolicy['lifetime_value'],
               },
               'pfs': ipsecpolicy['pfs']
               }

        return self._fields(res, fields)

    def create_ipsecpolicy(self, context, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        tenant_id = self._get_tenant_id_for_create(context, ipsecp)
        lifetime_info = ipsecp['lifetime']
        lifetime_units = lifetime_info.get('units', 'seconds')
        lifetime_value = lifetime_info.get('value', 3600)

        with context.session.begin(subtransactions=True):
            ipsecp_db = IPsecPolicy(id=uuidutils.generate_uuid(),
                                    tenant_id=tenant_id,
                                    name=ipsecp['name'],
                                    description=ipsecp['description'],
                                    transform_protocol=ipsecp['transform_'
                                                              'protocol'],
                                    auth_algorithm=ipsecp['auth_algorithm'],
                                    encryption_algorithm=ipsecp['encryption_'
                                                                'algorithm'],
                                    encapsulation_mode=ipsecp['encapsulation_'
                                                              'mode'],
                                    lifetime_units=lifetime_units,
                                    lifetime_value=lifetime_value,
                                    pfs=ipsecp['pfs'])
            context.session.add(ipsecp_db)
        return self._make_ipsecpolicy_dict(ipsecp_db)

    def update_ipsecpolicy(self, context, ipsecpolicy_id, ipsecpolicy):
        ipsecp = ipsecpolicy['ipsecpolicy']
        with context.session.begin(subtransactions=True):
            ipsecpolicy = context.session.query(IPsecSiteConnection).filter_by(
                ipsecpolicy_id=ipsecpolicy_id).first()
            if ipsecpolicy:
                raise vpnaas.IPsecPolicyInUse(ipsecpolicy_id=ipsecpolicy_id)
            ipsecp_db = self._get_resource(context,
                                           IPsecPolicy,
                                           ipsecpolicy_id)
            if ipsecp:
                lifetime_info = ipsecp.get('lifetime')
                if lifetime_info:
                    if lifetime_info.get('units'):
                        ipsecp['lifetime_units'] = lifetime_info['units']
                    if lifetime_info.get('value'):
                        ipsecp['lifetime_value'] = lifetime_info['value']
                ipsecp_db.update(ipsecp)
        return self._make_ipsecpolicy_dict(ipsecp_db)

    def delete_ipsecpolicy(self, context, ipsecpolicy_id):
        with context.session.begin(subtransactions=True):
            ipsecpolicy = context.session.query(IPsecSiteConnection).filter_by(
                ipsecpolicy_id=ipsecpolicy_id).first()
            if ipsecpolicy:
                raise vpnaas.IPsecPolicyInUse(ipsecpolicy_id=ipsecpolicy_id)
            ipsec_db = self._get_resource(context, IPsecPolicy, ipsecpolicy_id)
            context.session.delete(ipsec_db)

    def get_ipsecpolicy(self, context, ipsecpolicy_id, fields=None):
        ipsec_db = self._get_resource(context, IPsecPolicy, ipsecpolicy_id)
        return self._make_ipsecpolicy_dict(ipsec_db, fields)

    def get_ipsecpolicies(self, context, filters=None, fields=None):
        return self._get_collection(context, IPsecPolicy,
                                    self._make_ipsecpolicy_dict,
                                    filters=filters, fields=fields)

    def _make_vpnservice_dict(self, vpnservice, fields=None):
        res = {'id': vpnservice['id'],
               'name': vpnservice['name'],
               'description': vpnservice['description'],
               'tenant_id': vpnservice['tenant_id'],
               'subnet_id': vpnservice['subnet_id'],
               'router_id': vpnservice['router_id'],
               'admin_state_up': vpnservice['admin_state_up'],
               'status': vpnservice['status']}
        return self._fields(res, fields)

    def create_vpnservice(self, context, vpnservice):
        vpns = vpnservice['vpnservice']
        tenant_id = self._get_tenant_id_for_create(context, vpns)
        validator = self._get_validator()
        with context.session.begin(subtransactions=True):
            validator.validate_vpnservice(context, vpns)
            vpnservice_db = VPNService(id=uuidutils.generate_uuid(),
                                       tenant_id=tenant_id,
                                       name=vpns['name'],
                                       description=vpns['description'],
                                       subnet_id=vpns['subnet_id'],
                                       router_id=vpns['router_id'],
                                       admin_state_up=vpns['admin_state_up'],
                                       status=constants.PENDING_CREATE)
            context.session.add(vpnservice_db)
        return self._make_vpnservice_dict(vpnservice_db)

    def update_vpnservice(self, context, vpnservice_id, vpnservice):
        vpns = vpnservice['vpnservice']
        with context.session.begin(subtransactions=True):
            vpns_db = self._get_resource(context, VPNService, vpnservice_id)
            self.assert_update_allowed(vpns_db)
            if vpns:
                vpns_db.update(vpns)
        return self._make_vpnservice_dict(vpns_db)

    def delete_vpnservice(self, context, vpnservice_id):
        with context.session.begin(subtransactions=True):
            if context.session.query(IPsecSiteConnection).filter_by(
                vpnservice_id=vpnservice_id
            ).first():
                raise vpnaas.VPNServiceInUse(vpnservice_id=vpnservice_id)
            vpns_db = self._get_resource(context, VPNService, vpnservice_id)
            context.session.delete(vpns_db)

    def _get_vpnservice(self, context, vpnservice_id):
        return self._get_resource(context, VPNService, vpnservice_id)

    def get_vpnservice(self, context, vpnservice_id, fields=None):
        vpns_db = self._get_resource(context, VPNService, vpnservice_id)
        return self._make_vpnservice_dict(vpns_db, fields)

    def get_vpnservices(self, context, filters=None, fields=None):
        return self._get_collection(context, VPNService,
                                    self._make_vpnservice_dict,
                                    filters=filters, fields=fields)

    def check_router_in_use(self, context, router_id):
        vpnservices = self.get_vpnservices(
            context, filters={'router_id': [router_id]})
        if vpnservices:
            raise vpnaas.RouterInUseByVPNService(
                router_id=router_id,
                vpnservice_id=vpnservices[0]['id'])


class VPNPluginRpcDbMixin():
    def _get_agent_hosting_vpn_services(self, context, host):

        plugin = manager.NeutronManager.get_plugin()
        agent = plugin._get_agent_by_type_and_host(
            context, n_constants.AGENT_TYPE_L3, host)
        if not agent.admin_state_up:
            return []
        query = context.session.query(VPNService)
        query = query.join(IPsecSiteConnection)
        query = query.join(IKEPolicy)
        query = query.join(IPsecPolicy)
        query = query.join(IPsecPeerCidr)
        query = query.join(l3_agent_db.RouterL3AgentBinding,
                           l3_agent_db.RouterL3AgentBinding.router_id ==
                           VPNService.router_id)
        query = query.filter(
            l3_agent_db.RouterL3AgentBinding.l3_agent_id == agent.id)
        return query

    def update_status_by_agent(self, context, service_status_info_list):
        """Updating vpnservice and vpnconnection status.

        :param context: context variable
        :param service_status_info_list: list of status
        The structure is
        [{id: vpnservice_id,
          status: ACTIVE|DOWN|ERROR,
          updated_pending_status: True|False
          ipsec_site_connections: {
              ipsec_site_connection_id: {
                  status: ACTIVE|DOWN|ERROR,
                  updated_pending_status: True|False
              }
          }]
        The agent will set updated_pending_status as True,
        when agent update any pending status.
        """
        with context.session.begin(subtransactions=True):
            for vpnservice in service_status_info_list:
                try:
                    vpnservice_db = self._get_vpnservice(
                        context, vpnservice['id'])
                except vpnaas.VPNServiceNotFound:
                    LOG.warn(_('vpnservice %s in db is already deleted'),
                             vpnservice['id'])
                    continue

                if (not utils.in_pending_status(vpnservice_db.status)
                    or vpnservice['updated_pending_status']):
                    vpnservice_db.status = vpnservice['status']
                for conn_id, conn in vpnservice[
                    'ipsec_site_connections'].items():
                    self._update_connection_status(
                        context, conn_id, conn['status'],
                        conn['updated_pending_status'])
