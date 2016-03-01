# Copyright 2016 Hewlett Packard Enterprise Development Company LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import itertools

from oslo_db import exception as oslo_db_exc
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import and_
from sqlalchemy import orm
from sqlalchemy.orm import aliased
from sqlalchemy.orm import exc as sa_exc

from neutron_lib import constants as lib_consts

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.db import address_scope_db
from neutron.db import common_db_mixin as common_db
from neutron.db import l3_attrs_db
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import bgp as bgp_ext
from neutron.plugins.ml2 import models as ml2_models


LOG = logging.getLogger(__name__)
DEVICE_OWNER_ROUTER_GW = lib_consts.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_ROUTER_INTF = lib_consts.DEVICE_OWNER_ROUTER_INTF


class BgpSpeakerPeerBinding(model_base.BASEV2):

    """Represents a mapping between BGP speaker and BGP peer"""

    __tablename__ = 'bgp_speaker_peer_bindings'

    bgp_speaker_id = sa.Column(sa.String(length=36),
                               sa.ForeignKey('bgp_speakers.id',
                                             ondelete='CASCADE'),
                               nullable=False,
                               primary_key=True)
    bgp_peer_id = sa.Column(sa.String(length=36),
                            sa.ForeignKey('bgp_peers.id',
                                          ondelete='CASCADE'),
                            nullable=False,
                            primary_key=True)


class BgpSpeakerNetworkBinding(model_base.BASEV2):

    """Represents a mapping between a network and BGP speaker"""

    __tablename__ = 'bgp_speaker_network_bindings'

    bgp_speaker_id = sa.Column(sa.String(length=36),
                               sa.ForeignKey('bgp_speakers.id',
                                             ondelete='CASCADE'),
                               nullable=False,
                               primary_key=True)
    network_id = sa.Column(sa.String(length=36),
                           sa.ForeignKey('networks.id',
                                         ondelete='CASCADE'),
                           nullable=False,
                           primary_key=True)
    ip_version = sa.Column(sa.Integer, nullable=False, autoincrement=False,
                           primary_key=True)


class BgpSpeaker(model_base.BASEV2,
                 model_base.HasId,
                 model_base.HasTenant):

    """Represents a BGP speaker"""

    __tablename__ = 'bgp_speakers'

    name = sa.Column(sa.String(attr.NAME_MAX_LEN), nullable=False)
    local_as = sa.Column(sa.Integer, nullable=False, autoincrement=False)
    advertise_floating_ip_host_routes = sa.Column(sa.Boolean, nullable=False)
    advertise_tenant_networks = sa.Column(sa.Boolean, nullable=False)
    peers = orm.relationship(BgpSpeakerPeerBinding,
                             backref='bgp_speaker_peer_bindings',
                             cascade='all, delete, delete-orphan',
                             lazy='joined')
    networks = orm.relationship(BgpSpeakerNetworkBinding,
                                backref='bgp_speaker_network_bindings',
                                cascade='all, delete, delete-orphan',
                                lazy='joined')
    ip_version = sa.Column(sa.Integer, nullable=False, autoincrement=False)


class BgpPeer(model_base.BASEV2,
              model_base.HasId,
              model_base.HasTenant):

    """Represents a BGP routing peer."""

    __tablename__ = 'bgp_peers'

    name = sa.Column(sa.String(attr.NAME_MAX_LEN), nullable=False)
    peer_ip = sa.Column(sa.String(64),
                        nullable=False)
    remote_as = sa.Column(sa.Integer, nullable=False, autoincrement=False)
    auth_type = sa.Column(sa.String(16), nullable=False)
    password = sa.Column(sa.String(255), nullable=True)


class BgpDbMixin(common_db.CommonDbMixin):

    def create_bgp_speaker(self, context, bgp_speaker):
        uuid = uuidutils.generate_uuid()
        self._save_bgp_speaker(context, bgp_speaker, uuid)
        return self.get_bgp_speaker(context, uuid)

    def get_bgp_speakers(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        with context.session.begin(subtransactions=True):
            return self._get_collection(context, BgpSpeaker,
                                        self._make_bgp_speaker_dict,
                                        filters=filters, fields=fields,
                                        sorts=sorts, limit=limit,
                                        page_reverse=page_reverse)

    def get_bgp_speaker(self, context, bgp_speaker_id, fields=None):
        with context.session.begin(subtransactions=True):
            bgp_speaker = self._get_bgp_speaker(context, bgp_speaker_id)
            return self._make_bgp_speaker_dict(bgp_speaker, fields)

    def get_bgp_speaker_with_advertised_routes(self, context,
                                               bgp_speaker_id):
        bgp_speaker_attrs = ['id', 'local_as', 'tenant_id']
        bgp_peer_attrs = ['peer_ip', 'remote_as', 'password']
        with context.session.begin(subtransactions=True):
            bgp_speaker = self.get_bgp_speaker(context, bgp_speaker_id,
                                               fields=bgp_speaker_attrs)
            res = dict((k, bgp_speaker[k]) for k in bgp_speaker_attrs)
            res['peers'] = self.get_bgp_peers_by_bgp_speaker(context,
                                                         bgp_speaker['id'],
                                                         fields=bgp_peer_attrs)
            res['advertised_routes'] = self.get_routes_by_bgp_speaker_id(
                                                               context,
                                                               bgp_speaker_id)
            return res

    def update_bgp_speaker(self, context, bgp_speaker_id, bgp_speaker):
        bp = bgp_speaker[bgp_ext.BGP_SPEAKER_BODY_KEY_NAME]
        with context.session.begin(subtransactions=True):
            bgp_speaker_db = self._get_bgp_speaker(context, bgp_speaker_id)
            bgp_speaker_db.update(bp)

        bgp_speaker_dict = self._make_bgp_speaker_dict(bgp_speaker_db)
        return bgp_speaker_dict

    def _save_bgp_speaker(self, context, bgp_speaker, uuid):
        ri = bgp_speaker[bgp_ext.BGP_SPEAKER_BODY_KEY_NAME]
        ri['tenant_id'] = context.tenant_id
        with context.session.begin(subtransactions=True):
            res_keys = ['local_as', 'tenant_id', 'name', 'ip_version',
                        'advertise_floating_ip_host_routes',
                        'advertise_tenant_networks']
            res = dict((k, ri[k]) for k in res_keys)
            res['id'] = uuid
            bgp_speaker_db = BgpSpeaker(**res)
            context.session.add(bgp_speaker_db)

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        bgp_peer_id = self._get_id_for(bgp_peer_info, 'bgp_peer_id')
        self._save_bgp_speaker_peer_binding(context,
                                            bgp_speaker_id,
                                            bgp_peer_id)
        return {'bgp_peer_id': bgp_peer_id}

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        bgp_peer_id = self._get_id_for(bgp_peer_info, 'bgp_peer_id')
        self._remove_bgp_speaker_peer_binding(context,
                                              bgp_speaker_id,
                                              bgp_peer_id)
        return {'bgp_peer_id': bgp_peer_id}

    def add_gateway_network(self, context, bgp_speaker_id, network_info):
        network_id = self._get_id_for(network_info, 'network_id')
        with context.session.begin(subtransactions=True):
            try:
                self._save_bgp_speaker_network_binding(context,
                                                       bgp_speaker_id,
                                                       network_id)
            except oslo_db_exc.DBDuplicateEntry:
                raise bgp_ext.BgpSpeakerNetworkBindingError(
                                                network_id=network_id,
                                                bgp_speaker_id=bgp_speaker_id)
        return {'network_id': network_id}

    def remove_gateway_network(self, context, bgp_speaker_id, network_info):
        with context.session.begin(subtransactions=True):
            network_id = self._get_id_for(network_info, 'network_id')
            self._remove_bgp_speaker_network_binding(context,
                                                     bgp_speaker_id,
                                                     network_id)
        return {'network_id': network_id}

    def delete_bgp_speaker(self, context, bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            bgp_speaker_db = self._get_bgp_speaker(context, bgp_speaker_id)
            context.session.delete(bgp_speaker_db)

    def create_bgp_peer(self, context, bgp_peer):
        ri = bgp_peer[bgp_ext.BGP_PEER_BODY_KEY_NAME]
        auth_type = ri.get('auth_type')
        password = ri.get('password')
        if auth_type == 'md5' and not password:
            raise bgp_ext.InvalidBgpPeerMd5Authentication()

        with context.session.begin(subtransactions=True):
            res_keys = ['tenant_id', 'name', 'remote_as', 'peer_ip',
                        'auth_type', 'password']
            res = dict((k, ri[k]) for k in res_keys)
            res['id'] = uuidutils.generate_uuid()
            bgp_peer_db = BgpPeer(**res)
            context.session.add(bgp_peer_db)
            peer = self._make_bgp_peer_dict(bgp_peer_db)
            peer.pop('password')
            return peer

    def get_bgp_peers(self, context, fields=None, filters=None, sorts=None,
                      limit=None, marker=None, page_reverse=False):
        return self._get_collection(context, BgpPeer,
                                    self._make_bgp_peer_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    page_reverse=page_reverse)

    def get_bgp_peers_by_bgp_speaker(self, context,
                                     bgp_speaker_id, fields=None):
        filters = [BgpSpeakerPeerBinding.bgp_speaker_id == bgp_speaker_id,
                   BgpSpeakerPeerBinding.bgp_peer_id == BgpPeer.id]
        with context.session.begin(subtransactions=True):
            query = context.session.query(BgpPeer)
            query = query.filter(*filters)
            return [self._make_bgp_peer_dict(x) for x in query.all()]

    def get_bgp_peer(self, context, bgp_peer_id, fields=None):
        bgp_peer_db = self._get_bgp_peer(context, bgp_peer_id)
        return self._make_bgp_peer_dict(bgp_peer_db, fields=fields)

    def delete_bgp_peer(self, context, bgp_peer_id):
        with context.session.begin(subtransactions=True):
            bgp_peer_db = self._get_bgp_peer(context, bgp_peer_id)
            context.session.delete(bgp_peer_db)

    def update_bgp_peer(self, context, bgp_peer_id, bgp_peer):
        bp = bgp_peer[bgp_ext.BGP_PEER_BODY_KEY_NAME]
        with context.session.begin(subtransactions=True):
            bgp_peer_db = self._get_bgp_peer(context, bgp_peer_id)
            if ((bp['password'] is not None) and
                (bgp_peer_db['auth_type'] == 'none')):
                raise bgp_ext.BgpPeerNotAuthenticated(bgp_peer_id=bgp_peer_id)
            bgp_peer_db.update(bp)

        bgp_peer_dict = self._make_bgp_peer_dict(bgp_peer_db)
        return bgp_peer_dict

    def _get_bgp_speaker(self, context, bgp_speaker_id):
        try:
            return self._get_by_id(context, BgpSpeaker,
                                   bgp_speaker_id)
        except sa_exc.NoResultFound:
            raise bgp_ext.BgpSpeakerNotFound(id=bgp_speaker_id)

    def _get_bgp_speaker_ids_by_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            network_binding = aliased(BgpSpeakerNetworkBinding)
            r_port = aliased(l3_db.RouterPort)
            query = context.session.query(network_binding.bgp_speaker_id)
            query = query.filter(
                      r_port.router_id == router_id,
                      r_port.port_type == lib_consts.DEVICE_OWNER_ROUTER_GW,
                      r_port.port_id == models_v2.Port.id,
                      models_v2.Port.network_id == network_binding.network_id)

            return [binding.bgp_speaker_id for binding in query.all()]

    def _get_bgp_speaker_ids_by_binding_network(self, context, network_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(
                                      BgpSpeakerNetworkBinding.bgp_speaker_id)
            query = query.filter(
                            BgpSpeakerNetworkBinding.network_id == network_id)
            return query.all()

    def get_advertised_routes(self, context, bgp_speaker_id):
        routes = self.get_routes_by_bgp_speaker_id(context, bgp_speaker_id)
        return self._make_advertised_routes_dict(routes)

    def _get_id_for(self, resource, id_name):
        try:
            return resource.get(id_name)
        except AttributeError:
            msg = _("%s must be specified") % id_name
            raise n_exc.BadRequest(resource=bgp_ext.BGP_SPEAKER_RESOURCE_NAME,
                                   msg=msg)

    def _get_bgp_peers_by_bgp_speaker_binding(self, context, bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(BgpPeer)
            query = query.filter(
                     BgpSpeakerPeerBinding.bgp_speaker_id == bgp_speaker_id,
                     BgpSpeakerPeerBinding.bgp_peer_id == BgpPeer.id)
            return query.all()

    def _save_bgp_speaker_peer_binding(self, context, bgp_speaker_id,
                                       bgp_peer_id):
        with context.session.begin(subtransactions=True):
            try:
                bgp_speaker = self._get_by_id(context, BgpSpeaker,
                                              bgp_speaker_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpSpeakerNotFound(id=bgp_speaker_id)

            try:
                bgp_peer = self._get_by_id(context, BgpPeer,
                                           bgp_peer_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpPeerNotFound(id=bgp_peer_id)

            peers = self._get_bgp_peers_by_bgp_speaker_binding(context,
                                                               bgp_speaker_id)
            self._validate_peer_ips(bgp_speaker_id, peers, bgp_peer)
            binding = BgpSpeakerPeerBinding(bgp_speaker_id=bgp_speaker.id,
                                            bgp_peer_id=bgp_peer.id)
            context.session.add(binding)

    def _validate_peer_ips(self, bgp_speaker_id, current_peers, new_peer):
        for peer in current_peers:
            if peer.peer_ip == new_peer.peer_ip:
                raise bgp_ext.DuplicateBgpPeerIpException(
                                                bgp_peer_id=new_peer.id,
                                                peer_ip=new_peer.peer_ip,
                                                bgp_speaker_id=bgp_speaker_id)

    def _remove_bgp_speaker_peer_binding(self, context, bgp_speaker_id,
                                         bgp_peer_id):
        with context.session.begin(subtransactions=True):

            try:
                binding = self._get_bgp_speaker_peer_binding(context,
                                                             bgp_speaker_id,
                                                             bgp_peer_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpSpeakerPeerNotAssociated(
                                                bgp_peer_id=bgp_peer_id,
                                                bgp_speaker_id=bgp_speaker_id)
            context.session.delete(binding)

    def _save_bgp_speaker_network_binding(self,
                                          context,
                                          bgp_speaker_id,
                                          network_id):
        with context.session.begin(subtransactions=True):
            try:
                bgp_speaker = self._get_by_id(context, BgpSpeaker,
                                              bgp_speaker_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpSpeakerNotFound(id=bgp_speaker_id)

            try:
                network = self._get_by_id(context, models_v2.Network,
                                          network_id)
            except sa_exc.NoResultFound:
                raise n_exc.NetworkNotFound(net_id=network_id)

            binding = BgpSpeakerNetworkBinding(
                                            bgp_speaker_id=bgp_speaker.id,
                                            network_id=network.id,
                                            ip_version=bgp_speaker.ip_version)
            context.session.add(binding)

    def _remove_bgp_speaker_network_binding(self, context,
                                            bgp_speaker_id, network_id):
        with context.session.begin(subtransactions=True):

            try:
                binding = self._get_bgp_speaker_network_binding(
                                                               context,
                                                               bgp_speaker_id,
                                                               network_id)
            except sa_exc.NoResultFound:
                raise bgp_ext.BgpSpeakerNetworkNotAssociated(
                                                network_id=network_id,
                                                bgp_speaker_id=bgp_speaker_id)
            context.session.delete(binding)

    def _make_bgp_speaker_dict(self, bgp_speaker, fields=None):
        attrs = {'id', 'local_as', 'tenant_id', 'name', 'ip_version',
                 'advertise_floating_ip_host_routes',
                 'advertise_tenant_networks'}
        peer_bindings = bgp_speaker['peers']
        network_bindings = bgp_speaker['networks']
        res = dict((k, bgp_speaker[k]) for k in attrs)
        res['peers'] = [x.bgp_peer_id for x in peer_bindings]
        res['networks'] = [x.network_id for x in network_bindings]
        return self._fields(res, fields)

    def _make_advertised_routes_dict(self, routes):
        return {'advertised_routes': list(routes)}

    def _get_bgp_peer(self, context, bgp_peer_id):
        try:
            return self._get_by_id(context, BgpPeer, bgp_peer_id)
        except sa_exc.NoResultFound:
            raise bgp_ext.BgpPeerNotFound(id=bgp_peer_id)

    def _get_bgp_speaker_peer_binding(self, context,
                                      bgp_speaker_id, bgp_peer_id):
        query = self._model_query(context, BgpSpeakerPeerBinding)
        return query.filter(
                        BgpSpeakerPeerBinding.bgp_speaker_id == bgp_speaker_id,
                        BgpSpeakerPeerBinding.bgp_peer_id == bgp_peer_id).one()

    def _get_bgp_speaker_network_binding(self, context,
                                         bgp_speaker_id, network_id):
        query = self._model_query(context, BgpSpeakerNetworkBinding)
        return query.filter(bgp_speaker_id == bgp_speaker_id,
                            network_id == network_id).one()

    def _make_bgp_peer_dict(self, bgp_peer, fields=None):
        attrs = ['tenant_id', 'id', 'name', 'peer_ip', 'remote_as',
                 'auth_type', 'password']
        res = dict((k, bgp_peer[k]) for k in attrs)
        return self._fields(res, fields)

    def _get_address_scope_ids_for_bgp_speaker(self, context, bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            binding = aliased(BgpSpeakerNetworkBinding)
            address_scope = aliased(address_scope_db.AddressScope)
            query = context.session.query(address_scope)
            query = query.filter(
                binding.bgp_speaker_id == bgp_speaker_id,
                models_v2.Subnet.ip_version == binding.ip_version,
                models_v2.Subnet.network_id == binding.network_id,
                models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
                models_v2.SubnetPool.address_scope_id == address_scope.id)
            return [scope.id for scope in query.all()]

    def get_routes_by_bgp_speaker_id(self, context, bgp_speaker_id):
        """Get all routes that should be advertised by a BgpSpeaker."""
        with context.session.begin(subtransactions=True):
            net_routes = self._get_tenant_network_routes_by_bgp_speaker(
                                                               context,
                                                               bgp_speaker_id)
            fip_routes = self._get_central_fip_host_routes_by_bgp_speaker(
                                                               context,
                                                               bgp_speaker_id)
            dvr_fip_routes = self._get_dvr_fip_host_routes_by_bgp_speaker(
                                                               context,
                                                               bgp_speaker_id)
            return itertools.chain(fip_routes, net_routes, dvr_fip_routes)

    def get_routes_by_bgp_speaker_binding(self, context,
                                          bgp_speaker_id, network_id):
        """Get all routes for the given bgp_speaker binding."""
        with context.session.begin(subtransactions=True):
            fip_routes = self._get_central_fip_host_routes_by_binding(
                                                               context,
                                                               network_id,
                                                               bgp_speaker_id)
            net_routes = self._get_tenant_network_routes_by_binding(
                                                           context,
                                                           network_id,
                                                           bgp_speaker_id)
            dvr_fip_routes = self._get_dvr_fip_host_routes_by_binding(
                                                               context,
                                                               network_id,
                                                               bgp_speaker_id)
        return itertools.chain(fip_routes, net_routes, dvr_fip_routes)

    def _get_routes_by_router(self, context, router_id):
        bgp_speaker_ids = self._get_bgp_speaker_ids_by_router(context,
                                                              router_id)
        route_dict = {}
        for bgp_speaker_id in bgp_speaker_ids:
            fip_routes = self._get_central_fip_host_routes_by_router(
                                                               context,
                                                               router_id,
                                                               bgp_speaker_id)
            net_routes = self._get_tenant_network_routes_by_router(
                                                               context,
                                                               router_id,
                                                               bgp_speaker_id)
            dvr_fip_routes = self._get_dvr_fip_host_routes_by_router(
                                                               context,
                                                               router_id,
                                                               bgp_speaker_id)
            routes = itertools.chain(fip_routes, net_routes, dvr_fip_routes)
            route_dict[bgp_speaker_id] = list(routes)
        return route_dict

    def _get_central_fip_host_routes_by_router(self, context, router_id,
                                               bgp_speaker_id):
        """Get floating IP host routes with the given router as nexthop."""
        with context.session.begin(subtransactions=True):
            dest_alias = aliased(l3_db.FloatingIP,
                                 name='destination')
            next_hop_alias = aliased(models_v2.IPAllocation,
                                     name='next_hop')
            binding_alias = aliased(BgpSpeakerNetworkBinding,
                                    name='binding')
            router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                                   name='router_attrs')
            query = context.session.query(dest_alias.floating_ip_address,
                                          next_hop_alias.ip_address)
            query = query.join(
                  next_hop_alias,
                  next_hop_alias.network_id == dest_alias.floating_network_id)
            query = query.join(l3_db.Router,
                               dest_alias.router_id == l3_db.Router.id)
            query = query.filter(
                l3_db.Router.id == router_id,
                dest_alias.router_id == l3_db.Router.id,
                l3_db.Router.id == router_attrs.router_id,
                router_attrs.distributed == sa.sql.false(),
                l3_db.Router.gw_port_id == next_hop_alias.port_id,
                next_hop_alias.subnet_id == models_v2.Subnet.id,
                models_v2.Subnet.ip_version == 4,
                binding_alias.network_id == models_v2.Subnet.network_id,
                binding_alias.bgp_speaker_id == bgp_speaker_id,
                binding_alias.ip_version == 4,
                BgpSpeaker.advertise_floating_ip_host_routes == sa.sql.true())
            query = query.outerjoin(router_attrs,
                                    l3_db.Router.id == router_attrs.router_id)
            query = query.filter(router_attrs.distributed != sa.sql.true())
            return self._host_route_list_from_tuples(query.all())

    def _get_dvr_fip_host_routes_by_router(self, context, bgp_speaker_id,
                                           router_id):
        with context.session.begin(subtransactions=True):
            gw_query = self._get_gateway_query(context, bgp_speaker_id)

            fip_query = self._get_fip_query(context, bgp_speaker_id)
            fip_query.filter(l3_db.FloatingIP.router_id == router_id)

            #Create the join query
            join_query = self._join_fip_by_host_binding_to_agent_gateway(
                context,
                fip_query.subquery(),
                gw_query.subquery())
            return self._host_route_list_from_tuples(join_query.all())

    def _get_central_fip_host_routes_by_binding(self, context,
                                                network_id, bgp_speaker_id):
        """Get all floating IP host routes for the given network binding."""
        with context.session.begin(subtransactions=True):
            # Query the DB for floating IP's and the IP address of the
            # gateway port
            dest_alias = aliased(l3_db.FloatingIP,
                                 name='destination')
            next_hop_alias = aliased(models_v2.IPAllocation,
                                     name='next_hop')
            binding_alias = aliased(BgpSpeakerNetworkBinding,
                                    name='binding')
            router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                                   name='router_attrs')
            query = context.session.query(dest_alias.floating_ip_address,
                                          next_hop_alias.ip_address)
            query = query.join(
                  next_hop_alias,
                  next_hop_alias.network_id == dest_alias.floating_network_id)
            query = query.join(
                   binding_alias,
                   binding_alias.network_id == dest_alias.floating_network_id)
            query = query.join(l3_db.Router,
                               dest_alias.router_id == l3_db.Router.id)
            query = query.filter(
                dest_alias.floating_network_id == network_id,
                dest_alias.router_id == l3_db.Router.id,
                l3_db.Router.gw_port_id == next_hop_alias.port_id,
                next_hop_alias.subnet_id == models_v2.Subnet.id,
                models_v2.Subnet.ip_version == 4,
                binding_alias.network_id == models_v2.Subnet.network_id,
                binding_alias.bgp_speaker_id == BgpSpeaker.id,
                BgpSpeaker.id == bgp_speaker_id,
                BgpSpeaker.advertise_floating_ip_host_routes == sa.sql.true())
            query = query.outerjoin(router_attrs,
                                    l3_db.Router.id == router_attrs.router_id)
            query = query.filter(router_attrs.distributed != sa.sql.true())
            return self._host_route_list_from_tuples(query.all())

    def _get_dvr_fip_host_routes_by_binding(self, context, network_id,
                                            bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            BgpBinding = BgpSpeakerNetworkBinding

            gw_query = self._get_gateway_query(context, bgp_speaker_id)
            gw_query.filter(BgpBinding.network_id == network_id)

            fip_query = self._get_fip_query(context, bgp_speaker_id)
            fip_query.filter(BgpBinding.network_id == network_id)

            #Create the join query
            join_query = self._join_fip_by_host_binding_to_agent_gateway(
                context,
                fip_query.subquery(),
                gw_query.subquery())
            return self._host_route_list_from_tuples(join_query.all())

    def _get_central_fip_host_routes_by_bgp_speaker(self, context,
                                                    bgp_speaker_id):
        """Get all the floating IP host routes advertised by a BgpSpeaker."""
        with context.session.begin(subtransactions=True):
            dest_alias = aliased(l3_db.FloatingIP,
                                 name='destination')
            next_hop_alias = aliased(models_v2.IPAllocation,
                                     name='next_hop')
            speaker_binding = aliased(BgpSpeakerNetworkBinding,
                                      name="speaker_network_mapping")
            router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                                   name='router_attrs')
            query = context.session.query(dest_alias.floating_ip_address,
                                          next_hop_alias.ip_address)
            query = query.select_from(dest_alias,
                                      BgpSpeaker,
                                      l3_db.Router,
                                      models_v2.Subnet)
            query = query.join(
                  next_hop_alias,
                  next_hop_alias.network_id == dest_alias.floating_network_id)
            query = query.join(
                 speaker_binding,
                 speaker_binding.network_id == dest_alias.floating_network_id)
            query = query.join(l3_db.Router,
                               dest_alias.router_id == l3_db.Router.id)
            query = query.filter(
                 BgpSpeaker.id == bgp_speaker_id,
                 BgpSpeaker.advertise_floating_ip_host_routes,
                 speaker_binding.bgp_speaker_id == BgpSpeaker.id,
                 dest_alias.floating_network_id == speaker_binding.network_id,
                 next_hop_alias.network_id == speaker_binding.network_id,
                 dest_alias.router_id == l3_db.Router.id,
                 l3_db.Router.gw_port_id == next_hop_alias.port_id,
                 next_hop_alias.subnet_id == models_v2.Subnet.id,
                 models_v2.Subnet.ip_version == 4)
            query = query.outerjoin(router_attrs,
                                    l3_db.Router.id == router_attrs.router_id)
            query = query.filter(router_attrs.distributed != sa.sql.true())
            return self._host_route_list_from_tuples(query.all())

    def _get_gateway_query(self, context, bgp_speaker_id):
        BgpBinding = BgpSpeakerNetworkBinding
        ML2PortBinding = ml2_models.PortBinding
        IpAllocation = models_v2.IPAllocation
        Port = models_v2.Port
        gw_query = context.session.query(Port.network_id,
                                         ML2PortBinding.host,
                                         IpAllocation.ip_address)

        #Subquery for FIP agent gateway ports
        gw_query = gw_query.filter(
            ML2PortBinding.port_id == Port.id,
            IpAllocation.port_id == Port.id,
            IpAllocation.subnet_id == models_v2.Subnet.id,
            models_v2.Subnet.ip_version == 4,
            Port.device_owner == lib_consts.DEVICE_OWNER_AGENT_GW,
            Port.network_id == BgpBinding.network_id,
            BgpBinding.bgp_speaker_id == bgp_speaker_id,
            BgpBinding.ip_version == 4)
        return gw_query

    def _get_fip_query(self, context, bgp_speaker_id):
        BgpBinding = BgpSpeakerNetworkBinding
        ML2PortBinding = ml2_models.PortBinding

        #Subquery for floating IP's
        fip_query = context.session.query(
            l3_db.FloatingIP.floating_network_id,
            ML2PortBinding.host,
            l3_db.FloatingIP.floating_ip_address)
        fip_query = fip_query.filter(
            l3_db.FloatingIP.fixed_port_id == ML2PortBinding.port_id,
            l3_db.FloatingIP.floating_network_id == BgpBinding.network_id,
            BgpBinding.bgp_speaker_id == bgp_speaker_id)
        return fip_query

    def _get_dvr_fip_host_routes_by_bgp_speaker(self, context,
                                                bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            gw_query = self._get_gateway_query(context, bgp_speaker_id)
            fip_query = self._get_fip_query(context, bgp_speaker_id)

            #Create the join query
            join_query = self._join_fip_by_host_binding_to_agent_gateway(
                context,
                fip_query.subquery(),
                gw_query.subquery())
            return self._host_route_list_from_tuples(join_query.all())

    def _join_fip_by_host_binding_to_agent_gateway(self, context,
                                                   fip_subq, gw_subq):
        join_query = context.session.query(fip_subq.c.floating_ip_address,
                                           gw_subq.c.ip_address)
        and_cond = and_(
            gw_subq.c.host == fip_subq.c.host,
            gw_subq.c.network_id == fip_subq.c.floating_network_id)

        return join_query.join(gw_subq, and_cond)

    def _get_tenant_network_routes_by_binding(self, context,
                                              network_id, bgp_speaker_id):
        """Get all tenant network routes for the given network."""

        with context.session.begin(subtransactions=True):
            tenant_networks_query = self._tenant_networks_by_network_query(
                                                               context,
                                                               network_id,
                                                               bgp_speaker_id)
            nexthops_query = self._nexthop_ip_addresses_by_binding_query(
                                                               context,
                                                               network_id,
                                                               bgp_speaker_id)
            join_q = self._join_tenant_networks_to_next_hops(
                                             context,
                                             tenant_networks_query.subquery(),
                                             nexthops_query.subquery())
            return self._make_advertised_routes_list(join_q.all())

    def _get_tenant_network_routes_by_router(self, context, router_id,
                                             bgp_speaker_id):
        """Get all tenant network routes with the given router as nexthop."""

        with context.session.begin(subtransactions=True):
            scopes = self._get_address_scope_ids_for_bgp_speaker(
                                                               context,
                                                               bgp_speaker_id)
            address_scope = aliased(address_scope_db.AddressScope)
            inside_query = context.session.query(
                                            models_v2.Subnet.cidr,
                                            models_v2.IPAllocation.ip_address,
                                            address_scope.id)
            outside_query = context.session.query(
                                            address_scope.id,
                                            models_v2.IPAllocation.ip_address)
            speaker_binding = aliased(BgpSpeakerNetworkBinding,
                                      name="speaker_network_mapping")
            port_alias = aliased(l3_db.RouterPort, name='routerport')
            inside_query = inside_query.filter(
                    port_alias.router_id == router_id,
                    models_v2.IPAllocation.port_id == port_alias.port_id,
                    models_v2.IPAllocation.subnet_id == models_v2.Subnet.id,
                    models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
                    models_v2.SubnetPool.address_scope_id == address_scope.id,
                    address_scope.id.in_(scopes),
                    port_alias.port_type != lib_consts.DEVICE_OWNER_ROUTER_GW,
                    speaker_binding.bgp_speaker_id == bgp_speaker_id)
            outside_query = outside_query.filter(
                    port_alias.router_id == router_id,
                    port_alias.port_type == lib_consts.DEVICE_OWNER_ROUTER_GW,
                    models_v2.IPAllocation.port_id == port_alias.port_id,
                    models_v2.IPAllocation.subnet_id == models_v2.Subnet.id,
                    models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
                    models_v2.SubnetPool.address_scope_id == address_scope.id,
                    address_scope.id.in_(scopes),
                    speaker_binding.bgp_speaker_id == bgp_speaker_id,
                    speaker_binding.network_id == models_v2.Port.network_id,
                    port_alias.port_id == models_v2.Port.id)
            inside_query = inside_query.subquery()
            outside_query = outside_query.subquery()
            join_query = context.session.query(inside_query.c.cidr,
                                               outside_query.c.ip_address)
            and_cond = and_(inside_query.c.id == outside_query.c.id)
            join_query = join_query.join(outside_query, and_cond)
            return self._make_advertised_routes_list(join_query.all())

    def _get_tenant_network_routes_by_bgp_speaker(self, context,
                                                  bgp_speaker_id):
        """Get all tenant network routes to be advertised by a BgpSpeaker."""

        with context.session.begin(subtransactions=True):
            tenant_nets_q = self._tenant_networks_by_bgp_speaker_query(
                                                               context,
                                                               bgp_speaker_id)
            nexthops_q = self._nexthop_ip_addresses_by_bgp_speaker_query(
                                                               context,
                                                               bgp_speaker_id)
            join_q = self._join_tenant_networks_to_next_hops(
                                                     context,
                                                     tenant_nets_q.subquery(),
                                                     nexthops_q.subquery())

            return self._make_advertised_routes_list(join_q.all())

    def _join_tenant_networks_to_next_hops(self, context,
                                           tenant_networks_subquery,
                                           nexthops_subquery):
        """Join subquery for tenant networks to subquery for nexthop IP's"""
        left_subq = tenant_networks_subquery
        right_subq = nexthops_subquery
        join_query = context.session.query(left_subq.c.cidr,
                                           right_subq.c.ip_address)
        and_cond = and_(left_subq.c.router_id == right_subq.c.router_id,
                      left_subq.c.ip_version == right_subq.c.ip_version)
        join_query = join_query.join(right_subq, and_cond)
        return join_query

    def _tenant_networks_by_network_query(self, context,
                                          network_id, bgp_speaker_id):
        """Return subquery for tenant networks by binding network ID"""
        address_scope = aliased(address_scope_db.AddressScope,
                                name='address_scope')
        router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                               name='router_attrs')
        tenant_networks_query = context.session.query(
                                              l3_db.RouterPort.router_id,
                                              models_v2.Subnet.cidr,
                                              models_v2.Subnet.ip_version,
                                              address_scope.id)
        tenant_networks_query = tenant_networks_query.filter(
             l3_db.RouterPort.port_type != lib_consts.DEVICE_OWNER_ROUTER_GW,
             l3_db.RouterPort.port_type != lib_consts.DEVICE_OWNER_ROUTER_SNAT,
             l3_db.RouterPort.router_id == router_attrs.router_id,
             models_v2.IPAllocation.port_id == l3_db.RouterPort.port_id,
             models_v2.IPAllocation.subnet_id == models_v2.Subnet.id,
             models_v2.Subnet.network_id != network_id,
             models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
             models_v2.SubnetPool.address_scope_id == address_scope.id,
             BgpSpeaker.id == bgp_speaker_id,
             BgpSpeaker.ip_version == address_scope.ip_version,
             models_v2.Subnet.ip_version == address_scope.ip_version)
        return tenant_networks_query

    def _tenant_networks_by_bgp_speaker_query(self, context, bgp_speaker_id):
        """Return subquery for tenant networks by binding bgp_speaker_id"""
        router_id = l3_db.RouterPort.router_id.distinct().label('router_id')
        tenant_nets_subq = context.session.query(router_id,
                                                 models_v2.Subnet.cidr,
                                                 models_v2.Subnet.ip_version)
        scopes = self._get_address_scope_ids_for_bgp_speaker(context,
                                                             bgp_speaker_id)
        filters = self._tenant_networks_by_bgp_speaker_filters(scopes)
        tenant_nets_subq = tenant_nets_subq.filter(*filters)
        return tenant_nets_subq

    def _tenant_networks_by_bgp_speaker_filters(self, address_scope_ids):
        """Return the filters for querying tenant networks by BGP speaker"""
        router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                               name='router_attrs')
        return [models_v2.IPAllocation.port_id == l3_db.RouterPort.port_id,
          l3_db.RouterPort.router_id == router_attrs.router_id,
          l3_db.RouterPort.port_type != lib_consts.DEVICE_OWNER_ROUTER_GW,
          l3_db.RouterPort.port_type != lib_consts.DEVICE_OWNER_ROUTER_SNAT,
          models_v2.IPAllocation.subnet_id == models_v2.Subnet.id,
          models_v2.Subnet.network_id != BgpSpeakerNetworkBinding.network_id,
          models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
          models_v2.SubnetPool.address_scope_id.in_(address_scope_ids),
          models_v2.Subnet.ip_version == BgpSpeakerNetworkBinding.ip_version,
          BgpSpeakerNetworkBinding.bgp_speaker_id == BgpSpeaker.id,
          BgpSpeaker.advertise_tenant_networks == sa.sql.true()]

    def _nexthop_ip_addresses_by_binding_query(self, context,
                                               network_id, bgp_speaker_id):
        """Return the subquery for locating nexthops by binding network"""
        nexthops_query = context.session.query(
                                            l3_db.RouterPort.router_id,
                                            models_v2.IPAllocation.ip_address,
                                            models_v2.Subnet.ip_version)
        filters = self._next_hop_ip_addresses_by_binding_filters(
                                                               network_id,
                                                               bgp_speaker_id)
        nexthops_query = nexthops_query.filter(*filters)
        return nexthops_query

    def _next_hop_ip_addresses_by_binding_filters(self,
                                                  network_id,
                                                  bgp_speaker_id):
        """Return the filters for querying nexthops by binding network"""
        address_scope = aliased(address_scope_db.AddressScope,
                                name='address_scope')
        return [models_v2.IPAllocation.port_id == l3_db.RouterPort.port_id,
            models_v2.IPAllocation.subnet_id == models_v2.Subnet.id,
            BgpSpeaker.id == bgp_speaker_id,
            BgpSpeakerNetworkBinding.bgp_speaker_id == BgpSpeaker.id,
            BgpSpeakerNetworkBinding.network_id == network_id,
            models_v2.Subnet.network_id == BgpSpeakerNetworkBinding.network_id,
            models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
            models_v2.SubnetPool.address_scope_id == address_scope.id,
            models_v2.Subnet.ip_version == address_scope.ip_version,
            l3_db.RouterPort.port_type == DEVICE_OWNER_ROUTER_GW]

    def _nexthop_ip_addresses_by_bgp_speaker_query(self, context,
                                                   bgp_speaker_id):
        """Return the subquery for locating nexthops by BGP speaker"""
        nexthops_query = context.session.query(
                                            l3_db.RouterPort.router_id,
                                            models_v2.IPAllocation.ip_address,
                                            models_v2.Subnet.ip_version)
        filters = self._next_hop_ip_addresses_by_bgp_speaker_filters(
                                                               bgp_speaker_id)
        nexthops_query = nexthops_query.filter(*filters)
        return nexthops_query

    def _next_hop_ip_addresses_by_bgp_speaker_filters(self, bgp_speaker_id):
        """Return the filters for querying nexthops by BGP speaker"""
        router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                               name='router_attrs')

        return [l3_db.RouterPort.port_type == DEVICE_OWNER_ROUTER_GW,
           l3_db.RouterPort.router_id == router_attrs.router_id,
           BgpSpeakerNetworkBinding.network_id == models_v2.Subnet.network_id,
           BgpSpeakerNetworkBinding.ip_version == models_v2.Subnet.ip_version,
           BgpSpeakerNetworkBinding.bgp_speaker_id == bgp_speaker_id,
           models_v2.IPAllocation.port_id == l3_db.RouterPort.port_id,
           models_v2.IPAllocation.subnet_id == models_v2.Subnet.id]

    def _tenant_prefixes_by_router(self, context, router_id, bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(models_v2.Subnet.cidr.distinct())
            filters = self._tenant_prefixes_by_router_filters(router_id,
                                                              bgp_speaker_id)
            query = query.filter(*filters)
            return [x[0] for x in query.all()]

    def _tenant_prefixes_by_router_filters(self, router_id, bgp_speaker_id):
        binding = aliased(BgpSpeakerNetworkBinding, name='network_binding')
        subnetpool = aliased(models_v2.SubnetPool,
                             name='subnetpool')
        router_attrs = aliased(l3_attrs_db.RouterExtraAttributes,
                               name='router_attrs')
        return [models_v2.Subnet.id == models_v2.IPAllocation.subnet_id,
                models_v2.Subnet.subnetpool_id == subnetpool.id,
                l3_db.RouterPort.router_id == router_id,
                l3_db.Router.id == l3_db.RouterPort.router_id,
                l3_db.Router.id == router_attrs.router_id,
                l3_db.Router.gw_port_id == models_v2.Port.id,
                models_v2.Port.network_id == binding.network_id,
                binding.bgp_speaker_id == BgpSpeaker.id,
                l3_db.RouterPort.port_type == DEVICE_OWNER_ROUTER_INTF,
                models_v2.IPAllocation.port_id == l3_db.RouterPort.port_id]

    def _tenant_prefixes_by_router_interface(self,
                                             context,
                                             router_port_id,
                                             bgp_speaker_id):
        with context.session.begin(subtransactions=True):
            query = context.session.query(models_v2.Subnet.cidr.distinct())
            filters = self._tenant_prefixes_by_router_filters(router_port_id,
                                                              bgp_speaker_id)
            query = query.filter(*filters)
            return [x[0] for x in query.all()]

    def _tenant_prefixes_by_router_port_filters(self,
                                                router_port_id,
                                                bgp_speaker_id):
        binding = aliased(BgpSpeakerNetworkBinding, name='network_binding')
        return [models_v2.Subnet.id == models_v2.IPAllocation.subnet_id,
                l3_db.RouterPort.port_id == router_port_id,
                l3_db.Router.id == l3_db.RouterPort.router_id,
                l3_db.Router.gw_port_id == models_v2.Port.id,
                models_v2.Port.network_id == binding.network_id,
                binding.bgp_speaker_id == BgpSpeaker.id,
                models_v2.Subnet.ip_version == binding.ip_version,
                l3_db.RouterPort.port_type == DEVICE_OWNER_ROUTER_INTF,
                models_v2.IPAllocation.port_id == l3_db.RouterPort.port_id]

    def _bgp_speakers_for_gateway_network(self, context, network_id):
        """Return all BgpSpeakers for the given gateway network"""
        with context.session.begin(subtransactions=True):
            query = context.session.query(BgpSpeaker)
            query = query.filter(
                  BgpSpeakerNetworkBinding.network_id == network_id,
                  BgpSpeakerNetworkBinding.bgp_speaker_id == BgpSpeaker.id)
            return query.all()

    def _bgp_speakers_for_gw_network_by_family(self, context,
                                               network_id, ip_version):
        """Return the BgpSpeaker by given gateway network and ip_version"""
        with context.session.begin(subtransactions=True):
            query = context.session.query(BgpSpeaker)
            query = query.filter(
                  BgpSpeakerNetworkBinding.network_id == network_id,
                  BgpSpeakerNetworkBinding.bgp_speaker_id == BgpSpeaker.id,
                  BgpSpeakerNetworkBinding.ip_version == ip_version)
            return query.all()

    def _make_advertised_routes_list(self, routes):
        route_list = ({'destination': x,
                       'next_hop': y} for x, y in routes)
        return route_list

    def _route_list_from_prefixes_and_next_hop(self, routes, next_hop):
        route_list = [{'destination': x,
                       'next_hop': next_hop} for x in routes]
        return route_list

    def _host_route_list_from_tuples(self, ip_next_hop_tuples):
        """Return the list of host routes given a list of (IP, nexthop)"""
        return ({'destination': x + '/32',
                 'next_hop': y} for x, y in ip_next_hop_tuples)
