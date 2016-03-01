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

from oslo_db import exception as oslo_db_exc
from oslo_log import log as logging
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.db import common_db_mixin as common_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import bgp as bgp_ext


LOG = logging.getLogger(__name__)


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
            res['advertised_routes'] = []
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

    def get_advertised_routes(self, context, bgp_speaker_id):
        return self._make_advertised_routes_dict([])

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
