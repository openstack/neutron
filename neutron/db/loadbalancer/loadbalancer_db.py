# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 OpenStack Foundation.  All rights reserved
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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import validates

from neutron.api.v2 import attributes
from neutron.common import exceptions as q_exc
from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import servicetype_db as st_db
from neutron.extensions import loadbalancer
from neutron.extensions.loadbalancer import LoadBalancerPluginBase
from neutron import manager
from neutron.openstack.common.db import exception
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const


LOG = logging.getLogger(__name__)


class SessionPersistence(model_base.BASEV2):

    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey("vips.id"),
                       primary_key=True)
    type = sa.Column(sa.Enum("SOURCE_IP",
                             "HTTP_COOKIE",
                             "APP_COOKIE",
                             name="sesssionpersistences_type"),
                     nullable=False)
    cookie_name = sa.Column(sa.String(1024))


class PoolStatistics(model_base.BASEV2):
    """Represents pool statistics."""

    pool_id = sa.Column(sa.String(36), sa.ForeignKey("pools.id"),
                        primary_key=True)
    bytes_in = sa.Column(sa.Integer, nullable=False)
    bytes_out = sa.Column(sa.Integer, nullable=False)
    active_connections = sa.Column(sa.Integer, nullable=False)
    total_connections = sa.Column(sa.Integer, nullable=False)

    @validates('bytes_in', 'bytes_out',
               'active_connections', 'total_connections')
    def validate_non_negative_int(self, key, value):
        if value < 0:
            data = {'key': key, 'value': value}
            raise ValueError(_('The %(key)s field can not have '
                               'negative value. '
                               'Current value is %(value)d.') % data)
        return value


class Vip(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant,
          models_v2.HasStatusDescription):
    """Represents a v2 neutron loadbalancer vip."""

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    protocol_port = sa.Column(sa.Integer, nullable=False)
    protocol = sa.Column(sa.Enum("HTTP", "HTTPS", "TCP", name="lb_protocols"),
                         nullable=False)
    pool_id = sa.Column(sa.String(36), nullable=False, unique=True)
    session_persistence = orm.relationship(SessionPersistence,
                                           uselist=False,
                                           backref="vips",
                                           cascade="all, delete-orphan")
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    connection_limit = sa.Column(sa.Integer)
    port = orm.relationship(models_v2.Port)


class Member(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant,
             models_v2.HasStatusDescription):
    """Represents a v2 neutron loadbalancer member."""

    pool_id = sa.Column(sa.String(36), sa.ForeignKey("pools.id"),
                        nullable=False)
    address = sa.Column(sa.String(64), nullable=False)
    protocol_port = sa.Column(sa.Integer, nullable=False)
    weight = sa.Column(sa.Integer, nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)


class Pool(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant,
           models_v2.HasStatusDescription):
    """Represents a v2 neutron loadbalancer pool."""

    vip_id = sa.Column(sa.String(36), sa.ForeignKey("vips.id"))
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    subnet_id = sa.Column(sa.String(36), nullable=False)
    protocol = sa.Column(sa.Enum("HTTP", "HTTPS", "TCP", name="lb_protocols"),
                         nullable=False)
    lb_method = sa.Column(sa.Enum("ROUND_ROBIN",
                                  "LEAST_CONNECTIONS",
                                  "SOURCE_IP",
                                  name="pools_lb_method"),
                          nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    stats = orm.relationship(PoolStatistics,
                             uselist=False,
                             backref="pools",
                             cascade="all, delete-orphan")
    members = orm.relationship(Member, backref="pools",
                               cascade="all, delete-orphan")
    monitors = orm.relationship("PoolMonitorAssociation", backref="pools",
                                cascade="all, delete-orphan")
    vip = orm.relationship(Vip, backref='pool')

    provider = orm.relationship(
        st_db.ProviderResourceAssociation,
        uselist=False,
        lazy="joined",
        primaryjoin="Pool.id==ProviderResourceAssociation.resource_id",
        foreign_keys=[st_db.ProviderResourceAssociation.resource_id]
    )


class HealthMonitor(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron loadbalancer healthmonitor."""

    type = sa.Column(sa.Enum("PING", "TCP", "HTTP", "HTTPS",
                             name="healthmontiors_type"),
                     nullable=False)
    delay = sa.Column(sa.Integer, nullable=False)
    timeout = sa.Column(sa.Integer, nullable=False)
    max_retries = sa.Column(sa.Integer, nullable=False)
    http_method = sa.Column(sa.String(16))
    url_path = sa.Column(sa.String(255))
    expected_codes = sa.Column(sa.String(64))
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)

    pools = orm.relationship(
        "PoolMonitorAssociation", backref="healthmonitor",
        cascade="all", lazy="joined"
    )


class PoolMonitorAssociation(model_base.BASEV2,
                             models_v2.HasStatusDescription):
    """Many-to-many association between pool and healthMonitor classes."""

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id"),
                        primary_key=True)
    monitor_id = sa.Column(sa.String(36),
                           sa.ForeignKey("healthmonitors.id"),
                           primary_key=True)


class LoadBalancerPluginDb(LoadBalancerPluginBase,
                           base_db.CommonDbMixin):
    """Wraps loadbalancer with SQLAlchemy models.

    A class that wraps the implementation of the Neutron loadbalancer
    plugin database access interface using SQLAlchemy models.
    """

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def update_status(self, context, model, id, status,
                      status_description=None):
        with context.session.begin(subtransactions=True):
            v_db = self._get_resource(context, model, id)
            if v_db.status != status:
                v_db.status = status
            # update status_description in two cases:
            # - new value is passed
            # - old value is not None (needs to be updated anyway)
            if status_description or v_db['status_description']:
                v_db.status_description = status_description

    def _get_resource(self, context, model, id):
        try:
            r = self._get_by_id(context, model, id)
        except exc.NoResultFound:
            if issubclass(model, Vip):
                raise loadbalancer.VipNotFound(vip_id=id)
            elif issubclass(model, Pool):
                raise loadbalancer.PoolNotFound(pool_id=id)
            elif issubclass(model, Member):
                raise loadbalancer.MemberNotFound(member_id=id)
            elif issubclass(model, HealthMonitor):
                raise loadbalancer.HealthMonitorNotFound(monitor_id=id)
            else:
                raise
        return r

    def assert_modification_allowed(self, obj):
        status = getattr(obj, 'status', None)

        if status == constants.PENDING_DELETE:
            raise loadbalancer.StateInvalid(id=id, state=status)

    ########################################################
    # VIP DB access
    def _make_vip_dict(self, vip, fields=None):
        fixed_ip = (vip.port.fixed_ips or [{}])[0]

        res = {'id': vip['id'],
               'tenant_id': vip['tenant_id'],
               'name': vip['name'],
               'description': vip['description'],
               'subnet_id': fixed_ip.get('subnet_id'),
               'address': fixed_ip.get('ip_address'),
               'port_id': vip['port_id'],
               'protocol_port': vip['protocol_port'],
               'protocol': vip['protocol'],
               'pool_id': vip['pool_id'],
               'connection_limit': vip['connection_limit'],
               'admin_state_up': vip['admin_state_up'],
               'status': vip['status'],
               'status_description': vip['status_description']}

        if vip['session_persistence']:
            s_p = {
                'type': vip['session_persistence']['type']
            }

            if vip['session_persistence']['type'] == 'APP_COOKIE':
                s_p['cookie_name'] = vip['session_persistence']['cookie_name']

            res['session_persistence'] = s_p

        return self._fields(res, fields)

    def _check_session_persistence_info(self, info):
        """Performs sanity check on session persistence info.

        :param info: Session persistence info
        """
        if info['type'] == 'APP_COOKIE':
            if not info.get('cookie_name'):
                raise ValueError(_("'cookie_name' should be specified for this"
                                   " type of session persistence."))
        else:
            if 'cookie_name' in info:
                raise ValueError(_("'cookie_name' is not allowed for this type"
                                   " of session persistence"))

    def _create_session_persistence_db(self, session_info, vip_id):
        self._check_session_persistence_info(session_info)

        sesspersist_db = SessionPersistence(
            type=session_info['type'],
            cookie_name=session_info.get('cookie_name'),
            vip_id=vip_id)
        return sesspersist_db

    def _update_vip_session_persistence(self, context, vip_id, info):
        self._check_session_persistence_info(info)

        vip = self._get_resource(context, Vip, vip_id)

        with context.session.begin(subtransactions=True):
            # Update sessionPersistence table
            sess_qry = context.session.query(SessionPersistence)
            sesspersist_db = sess_qry.filter_by(vip_id=vip_id).first()

            # Insert a None cookie_info if it is not present to overwrite an
            # an existing value in the database.
            if 'cookie_name' not in info:
                info['cookie_name'] = None

            if sesspersist_db:
                sesspersist_db.update(info)
            else:
                sesspersist_db = SessionPersistence(
                    type=info['type'],
                    cookie_name=info['cookie_name'],
                    vip_id=vip_id)
                context.session.add(sesspersist_db)
                # Update vip table
                vip.session_persistence = sesspersist_db
            context.session.add(vip)

    def _delete_session_persistence(self, context, vip_id):
        with context.session.begin(subtransactions=True):
            sess_qry = context.session.query(SessionPersistence)
            sess_qry.filter_by(vip_id=vip_id).delete()

    def _create_port_for_vip(self, context, vip_db, subnet_id, ip_address):
            # resolve subnet and create port
            subnet = self._core_plugin.get_subnet(context, subnet_id)
            fixed_ip = {'subnet_id': subnet['id']}
            if ip_address and ip_address != attributes.ATTR_NOT_SPECIFIED:
                fixed_ip['ip_address'] = ip_address

            port_data = {
                'tenant_id': vip_db.tenant_id,
                'name': 'vip-' + vip_db.id,
                'network_id': subnet['network_id'],
                'mac_address': attributes.ATTR_NOT_SPECIFIED,
                'admin_state_up': False,
                'device_id': '',
                'device_owner': '',
                'fixed_ips': [fixed_ip]
            }

            port = self._core_plugin.create_port(context, {'port': port_data})
            vip_db.port_id = port['id']

    def create_vip(self, context, vip):
        v = vip['vip']
        tenant_id = self._get_tenant_id_for_create(context, v)

        with context.session.begin(subtransactions=True):
            if v['pool_id']:
                pool = self._get_resource(context, Pool, v['pool_id'])
                # validate that the pool has same tenant
                if pool['tenant_id'] != tenant_id:
                    raise q_exc.NotAuthorized()
                # validate that the pool has same protocol
                if pool['protocol'] != v['protocol']:
                    raise loadbalancer.ProtocolMismatch(
                        vip_proto=v['protocol'],
                        pool_proto=pool['protocol'])
                if pool['status'] == constants.PENDING_DELETE:
                    raise loadbalancer.StateInvalid(state=pool['status'],
                                                    id=pool['id'])
            else:
                pool = None

            vip_db = Vip(id=uuidutils.generate_uuid(),
                         tenant_id=tenant_id,
                         name=v['name'],
                         description=v['description'],
                         port_id=None,
                         protocol_port=v['protocol_port'],
                         protocol=v['protocol'],
                         pool_id=v['pool_id'],
                         connection_limit=v['connection_limit'],
                         admin_state_up=v['admin_state_up'],
                         status=constants.PENDING_CREATE)

            session_info = v['session_persistence']

            if session_info:
                s_p = self._create_session_persistence_db(
                    session_info,
                    vip_db['id'])
                vip_db.session_persistence = s_p

            try:
                context.session.add(vip_db)
                context.session.flush()
            except exception.DBDuplicateEntry:
                raise loadbalancer.VipExists(pool_id=v['pool_id'])

            # create a port to reserve address for IPAM
            self._create_port_for_vip(
                context,
                vip_db,
                v['subnet_id'],
                v.get('address')
            )

            if pool:
                pool['vip_id'] = vip_db['id']

        return self._make_vip_dict(vip_db)

    def update_vip(self, context, id, vip):
        v = vip['vip']

        sess_persist = v.pop('session_persistence', None)
        with context.session.begin(subtransactions=True):
            vip_db = self._get_resource(context, Vip, id)

            self.assert_modification_allowed(vip_db)

            if sess_persist:
                self._update_vip_session_persistence(context, id, sess_persist)
            else:
                self._delete_session_persistence(context, id)

            if v:
                try:
                    # in case new pool already has a vip
                    # update will raise integrity error at first query
                    old_pool_id = vip_db['pool_id']
                    vip_db.update(v)
                    # If the pool_id is changed, we need to update
                    # the associated pools
                    if 'pool_id' in v:
                        new_pool = self._get_resource(context, Pool,
                                                      v['pool_id'])
                        self.assert_modification_allowed(new_pool)

                        # check that the pool matches the tenant_id
                        if new_pool['tenant_id'] != vip_db['tenant_id']:
                            raise q_exc.NotAuthorized()
                        # validate that the pool has same protocol
                        if new_pool['protocol'] != vip_db['protocol']:
                            raise loadbalancer.ProtocolMismatch(
                                vip_proto=vip_db['protocol'],
                                pool_proto=new_pool['protocol'])
                        if new_pool['status'] == constants.PENDING_DELETE:
                            raise loadbalancer.StateInvalid(
                                state=new_pool['status'],
                                id=new_pool['id'])

                        if old_pool_id:
                            old_pool = self._get_resource(
                                context,
                                Pool,
                                old_pool_id
                            )
                            old_pool['vip_id'] = None

                        new_pool['vip_id'] = vip_db['id']
                except exception.DBDuplicateEntry:
                    raise loadbalancer.VipExists(pool_id=v['pool_id'])

        return self._make_vip_dict(vip_db)

    def delete_vip(self, context, id):
        with context.session.begin(subtransactions=True):
            vip = self._get_resource(context, Vip, id)
            qry = context.session.query(Pool)
            for pool in qry.filter_by(vip_id=id):
                pool.update({"vip_id": None})

            context.session.delete(vip)
            if vip.port:  # this is a Neutron port
                self._core_plugin.delete_port(context, vip.port.id)

    def get_vip(self, context, id, fields=None):
        vip = self._get_resource(context, Vip, id)
        return self._make_vip_dict(vip, fields)

    def get_vips(self, context, filters=None, fields=None):
        return self._get_collection(context, Vip,
                                    self._make_vip_dict,
                                    filters=filters, fields=fields)

    ########################################################
    # Pool DB access
    def _make_pool_dict(self, pool, fields=None):
        res = {'id': pool['id'],
               'tenant_id': pool['tenant_id'],
               'name': pool['name'],
               'description': pool['description'],
               'subnet_id': pool['subnet_id'],
               'protocol': pool['protocol'],
               'vip_id': pool['vip_id'],
               'lb_method': pool['lb_method'],
               'admin_state_up': pool['admin_state_up'],
               'status': pool['status'],
               'status_description': pool['status_description'],
               'provider': ''
               }

        if pool.provider:
            res['provider'] = pool.provider.provider_name

        # Get the associated members
        res['members'] = [member['id'] for member in pool['members']]

        # Get the associated health_monitors
        res['health_monitors'] = [
            monitor['monitor_id'] for monitor in pool['monitors']]
        res['health_monitors_status'] = [
            {'monitor_id': monitor['monitor_id'],
             'status': monitor['status'],
             'status_description': monitor['status_description']}
            for monitor in pool['monitors']]
        return self._fields(res, fields)

    def update_pool_stats(self, context, pool_id, data=None):
        """Update a pool with new stats structure."""
        data = data or {}
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, Pool, pool_id)
            self.assert_modification_allowed(pool_db)
            pool_db.stats = self._create_pool_stats(context, pool_id, data)

            for member, stats in data.get('members', {}).items():
                stats_status = stats.get(lb_const.STATS_STATUS)
                if stats_status:
                    self.update_status(context, Member, member, stats_status)

    def _create_pool_stats(self, context, pool_id, data=None):
        # This is internal method to add pool statistics. It won't
        # be exposed to API
        if not data:
            data = {}
        stats_db = PoolStatistics(
            pool_id=pool_id,
            bytes_in=data.get(lb_const.STATS_IN_BYTES, 0),
            bytes_out=data.get(lb_const.STATS_OUT_BYTES, 0),
            active_connections=data.get(lb_const.STATS_ACTIVE_CONNECTIONS, 0),
            total_connections=data.get(lb_const.STATS_TOTAL_CONNECTIONS, 0)
        )
        return stats_db

    def _delete_pool_stats(self, context, pool_id):
        # This is internal method to delete pool statistics. It won't
        # be exposed to API
        with context.session.begin(subtransactions=True):
            stats_qry = context.session.query(PoolStatistics)
            try:
                stats = stats_qry.filter_by(pool_id=pool_id).one()
            except exc.NoResultFound:
                raise loadbalancer.PoolStatsNotFound(pool_id=pool_id)
            context.session.delete(stats)

    def create_pool(self, context, pool):
        v = pool['pool']

        tenant_id = self._get_tenant_id_for_create(context, v)
        with context.session.begin(subtransactions=True):
            pool_db = Pool(id=uuidutils.generate_uuid(),
                           tenant_id=tenant_id,
                           name=v['name'],
                           description=v['description'],
                           subnet_id=v['subnet_id'],
                           protocol=v['protocol'],
                           lb_method=v['lb_method'],
                           admin_state_up=v['admin_state_up'],
                           status=constants.PENDING_CREATE)
            pool_db.stats = self._create_pool_stats(context, pool_db['id'])
            context.session.add(pool_db)

        return self._make_pool_dict(pool_db)

    def update_pool(self, context, id, pool):
        p = pool['pool']
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, Pool, id)
            self.assert_modification_allowed(pool_db)
            if p:
                pool_db.update(p)

        return self._make_pool_dict(pool_db)

    def _ensure_pool_delete_conditions(self, context, pool_id):
        if context.session.query(Vip).filter_by(pool_id=pool_id).first():
            raise loadbalancer.PoolInUse(pool_id=pool_id)

    def delete_pool(self, context, pool_id):
        # Check if the pool is in use
        self._ensure_pool_delete_conditions(context, pool_id)

        with context.session.begin(subtransactions=True):
            self._delete_pool_stats(context, pool_id)
            pool_db = self._get_resource(context, Pool, pool_id)
            context.session.delete(pool_db)

    def get_pool(self, context, id, fields=None):
        pool = self._get_resource(context, Pool, id)
        return self._make_pool_dict(pool, fields)

    def get_pools(self, context, filters=None, fields=None):
        collection = self._model_query(context, Pool)
        collection = self._apply_filters_to_query(collection, Pool, filters)
        return [self._make_pool_dict(c, fields)
                for c in collection]

    def stats(self, context, pool_id):
        with context.session.begin(subtransactions=True):
            pool = self._get_resource(context, Pool, pool_id)
            stats = pool['stats']

        res = {lb_const.STATS_IN_BYTES: stats['bytes_in'],
               lb_const.STATS_OUT_BYTES: stats['bytes_out'],
               lb_const.STATS_ACTIVE_CONNECTIONS: stats['active_connections'],
               lb_const.STATS_TOTAL_CONNECTIONS: stats['total_connections']}
        return {'stats': res}

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        monitor_id = health_monitor['health_monitor']['id']
        with context.session.begin(subtransactions=True):
            assoc_qry = context.session.query(PoolMonitorAssociation)
            assoc = assoc_qry.filter_by(pool_id=pool_id,
                                        monitor_id=monitor_id).first()
            if assoc:
                raise loadbalancer.PoolMonitorAssociationExists(
                    monitor_id=monitor_id, pool_id=pool_id)

            pool = self._get_resource(context, Pool, pool_id)

            assoc = PoolMonitorAssociation(pool_id=pool_id,
                                           monitor_id=monitor_id,
                                           status=constants.PENDING_CREATE)
            pool.monitors.append(assoc)
            monitors = [monitor['monitor_id'] for monitor in pool['monitors']]

        res = {"health_monitor": monitors}
        return res

    def delete_pool_health_monitor(self, context, id, pool_id):
        with context.session.begin(subtransactions=True):
            assoc = self._get_pool_health_monitor(context, id, pool_id)
            pool = self._get_resource(context, Pool, pool_id)
            pool.monitors.remove(assoc)

    def _get_pool_health_monitor(self, context, id, pool_id):
        try:
            assoc_qry = context.session.query(PoolMonitorAssociation)
            return assoc_qry.filter_by(monitor_id=id, pool_id=pool_id).one()
        except exc.NoResultFound:
            raise loadbalancer.PoolMonitorAssociationNotFound(
                monitor_id=id, pool_id=pool_id)

    def get_pool_health_monitor(self, context, id, pool_id, fields=None):
        pool_hm = self._get_pool_health_monitor(context, id, pool_id)
        # need to add tenant_id for admin_or_owner policy check to pass
        hm = self.get_health_monitor(context, id)
        res = {'pool_id': pool_id,
               'monitor_id': id,
               'status': pool_hm['status'],
               'status_description': pool_hm['status_description'],
               'tenant_id': hm['tenant_id']}
        return self._fields(res, fields)

    def update_pool_health_monitor(self, context, id, pool_id,
                                   status, status_description=None):
        with context.session.begin(subtransactions=True):
            assoc = self._get_pool_health_monitor(context, id, pool_id)
            self.assert_modification_allowed(assoc)
            assoc.status = status
            assoc.status_description = status_description

    ########################################################
    # Member DB access
    def _make_member_dict(self, member, fields=None):
        res = {'id': member['id'],
               'tenant_id': member['tenant_id'],
               'pool_id': member['pool_id'],
               'address': member['address'],
               'protocol_port': member['protocol_port'],
               'weight': member['weight'],
               'admin_state_up': member['admin_state_up'],
               'status': member['status'],
               'status_description': member['status_description']}

        return self._fields(res, fields)

    def create_member(self, context, member):
        v = member['member']
        tenant_id = self._get_tenant_id_for_create(context, v)

        with context.session.begin(subtransactions=True):
            # ensuring that pool exists
            self._get_resource(context, Pool, v['pool_id'])

            member_db = Member(id=uuidutils.generate_uuid(),
                               tenant_id=tenant_id,
                               pool_id=v['pool_id'],
                               address=v['address'],
                               protocol_port=v['protocol_port'],
                               weight=v['weight'],
                               admin_state_up=v['admin_state_up'],
                               status=constants.PENDING_CREATE)
            context.session.add(member_db)

        return self._make_member_dict(member_db)

    def update_member(self, context, id, member):
        v = member['member']
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, Member, id)
            self.assert_modification_allowed(member_db)
            if v:
                member_db.update(v)

        return self._make_member_dict(member_db)

    def delete_member(self, context, id):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, Member, id)
            context.session.delete(member_db)

    def get_member(self, context, id, fields=None):
        member = self._get_resource(context, Member, id)
        return self._make_member_dict(member, fields)

    def get_members(self, context, filters=None, fields=None):
        return self._get_collection(context, Member,
                                    self._make_member_dict,
                                    filters=filters, fields=fields)

    ########################################################
    # HealthMonitor DB access
    def _make_health_monitor_dict(self, health_monitor, fields=None):
        res = {'id': health_monitor['id'],
               'tenant_id': health_monitor['tenant_id'],
               'type': health_monitor['type'],
               'delay': health_monitor['delay'],
               'timeout': health_monitor['timeout'],
               'max_retries': health_monitor['max_retries'],
               'admin_state_up': health_monitor['admin_state_up']}
        # no point to add the values below to
        # the result if the 'type' is not HTTP/S
        if res['type'] in ['HTTP', 'HTTPS']:
            for attr in ['url_path', 'http_method', 'expected_codes']:
                res[attr] = health_monitor[attr]
        res['pools'] = [{'pool_id': p['pool_id'],
                         'status': p['status'],
                         'status_description': p['status_description']}
                        for p in health_monitor.pools]
        return self._fields(res, fields)

    def create_health_monitor(self, context, health_monitor):
        v = health_monitor['health_monitor']
        tenant_id = self._get_tenant_id_for_create(context, v)
        with context.session.begin(subtransactions=True):
            # setting ACTIVE status sinse healthmon is shared DB object
            monitor_db = HealthMonitor(id=uuidutils.generate_uuid(),
                                       tenant_id=tenant_id,
                                       type=v['type'],
                                       delay=v['delay'],
                                       timeout=v['timeout'],
                                       max_retries=v['max_retries'],
                                       http_method=v['http_method'],
                                       url_path=v['url_path'],
                                       expected_codes=v['expected_codes'],
                                       admin_state_up=v['admin_state_up'])
            context.session.add(monitor_db)
        return self._make_health_monitor_dict(monitor_db)

    def update_health_monitor(self, context, id, health_monitor):
        v = health_monitor['health_monitor']
        with context.session.begin(subtransactions=True):
            monitor_db = self._get_resource(context, HealthMonitor, id)
            self.assert_modification_allowed(monitor_db)
            if v:
                monitor_db.update(v)
        return self._make_health_monitor_dict(monitor_db)

    def delete_health_monitor(self, context, id):
        with context.session.begin(subtransactions=True):
            monitor_db = self._get_resource(context, HealthMonitor, id)
            context.session.delete(monitor_db)

    def get_health_monitor(self, context, id, fields=None):
        healthmonitor = self._get_resource(context, HealthMonitor, id)
        return self._make_health_monitor_dict(healthmonitor, fields)

    def get_health_monitors(self, context, filters=None, fields=None):
        return self._get_collection(context, HealthMonitor,
                                    self._make_health_monitor_dict,
                                    filters=filters, fields=fields)
