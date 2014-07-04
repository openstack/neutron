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
# @author: Brandon Logan, Rackspace
# @author: Vijay Bhamidipati, Ebay Inc.


import sqlalchemy as sa
from sqlalchemy.ext import declarative
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import validates

from neutron.api.v2 import attributes
from neutron.db import db_base_plugin_v2 as base_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import servicetype_db as st_db
from neutron.extensions import loadbalancer
from neutron.extensions import loadbalancerv2
from neutron import manager
from neutron.openstack.common.db import exception
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const


LOG = logging.getLogger(__name__)


class SessionPersistencev2(model_base.BASEV2):

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_sessionpersistences"

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("lbaas_pools.id"),
                        primary_key=True)
    type = sa.Column(sa.Enum("SOURCE_IP",
                             "HTTP_COOKIE",
                             "APP_COOKIE",
                             name="lbaas_sesssionpersistences_type"),
                     nullable=False)
    cookie_name = sa.Column(sa.String(1024))

    def to_dict(self):
        pass


class LoadBalancerStatistics(model_base.BASEV2):
    """Represents load balancer statistics."""

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_loadbalancer_statistics"

    loadbalancer_id = sa.Column(sa.String(36),
                                sa.ForeignKey("lbaas_loadbalancers.id"),
                                primary_key=True)
    bytes_in = sa.Column(sa.BigInteger, nullable=False)
    bytes_out = sa.Column(sa.BigInteger, nullable=False)
    active_connections = sa.Column(sa.BigInteger, nullable=False)
    total_connections = sa.Column(sa.BigInteger, nullable=False)

    @validates('bytes_in', 'bytes_out',
               'active_connections', 'total_connections')
    def validate_non_negative_int(self, key, value):
        if value < 0:
            data = {'key': key, 'value': value}
            raise ValueError(_('The %(key)s field can not have '
                               'negative value. '
                               'Current value is %(value)d.') % data)
        return value

    def to_dict(self):
        res = {lb_const.STATS_IN_BYTES: self.bytes_in,
               lb_const.STATS_OUT_BYTES: self.bytes_out,
               lb_const.STATS_ACTIVE_CONNECTIONS: self.active_connections,
               lb_const.STATS_TOTAL_CONNECTIONS: self.total_connections}
        return {'stats': res}


class MemberV2(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer member."""

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_members"

    __table_args__ = (
        sa.schema.UniqueConstraint('pool_id', 'address', 'protocol_port',
                                   name='uniq_member0pool_id0address0port'),
    )
    pool_id = sa.Column(sa.String(36), sa.ForeignKey("lbaas_pools.id"),
                        nullable=False)
    address = sa.Column(sa.String(64), nullable=False)
    protocol_port = sa.Column(sa.Integer, nullable=False)
    weight = sa.Column(sa.Integer, nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    subnet_id = sa.Column(sa.String(36), nullable=True)
    status = sa.Column(sa.String(16), nullable=False)

    def to_dict(self, pool=False):
        member_dict = {'id': self.id,
                       'tenant_id': self.tenant_id,
                       'address': self.address,
                       'protocol_port': self.protocol_port,
                       'weight': self.weight,
                       'subnet_id': self.subnet_id,
                       'status': self.status,
                       'admin_state_up': self.admin_state_up}
        if pool and self.pool:
            member_dict['pool'] = self.pool.to_dict(members=True,
                                                    listener=True,
                                                    healthmonitor=True,
                                                    sessionpersistence=True)
        return member_dict


class HealthMonitorV2(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer healthmonitor."""

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_healthmonitors"

    type = sa.Column(sa.Enum("PING", "TCP", "HTTP", "HTTPS",
                             name="healthmonitors_type"),
                     nullable=False)
    delay = sa.Column(sa.Integer, nullable=False)
    timeout = sa.Column(sa.Integer, nullable=False)
    max_retries = sa.Column(sa.Integer, nullable=False)
    http_method = sa.Column(sa.String(16))
    url_path = sa.Column(sa.String(255))
    expected_codes = sa.Column(sa.String(64))
    status = sa.Column(sa.String(16), nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)

    def to_dict(self, pool=False):
        hm_dict = {'id': self.id,
                   'type': self.type,
                   'delay': self.delay,
                   'timeout': self.timeout,
                   'max_retries': self.max_retries,
                   'http_method': self.http_method,
                   'url_path': self.url_path,
                   'expected_codes': self.expected_codes,
                   'admin_state_up': self.admin_state_up,
                   'status': self.status}
        if pool and self.pool:
            hm_dict['pool'] = self.pool.to_dict(listener=True,
                                                members=True,
                                                sessionpersistence=True)
        return hm_dict


class PoolV2(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer pool."""

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_pools"

    name = sa.Column(sa.String(255), nullable=True)
    description = sa.Column(sa.String(255), nullable=True)
    healthmonitor_id = sa.Column(sa.String(36),
                                 sa.ForeignKey("lbaas_healthmonitors.id"),
                                 unique=True,
                                 nullable=True)
    protocol = sa.Column(sa.Enum("HTTP", "HTTPS", "TCP", "UDP",
                                 name="lb_protocols"),
                         nullable=False)
    lb_algorithm = sa.Column(sa.Enum("ROUND_ROBIN",
                                     "LEAST_CONNECTIONS",
                                     "SOURCE_IP",
                                     name="lb_methods"),
                             nullable=False)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    members = orm.relationship(MemberV2,
                               backref=orm.backref("pool", uselist=False),
                               cascade="all, delete-orphan")
    healthmonitor = orm.relationship(
        HealthMonitorV2, backref=orm.backref("pool", uselist=False))
    sessionpersistence = orm.relationship(
        SessionPersistencev2,
        uselist=False,
        backref=orm.backref("pool", uselist=False),
        cascade="all, delete-orphan")

    def to_dict(self, members=False, healthmonitor=False, listener=False,
                sessionpersistence=False):
        pool_dict = {'id': self.id,
                     'tenant_id': self.tenant_id,
                     'name': self.name,
                     'description': self.description,
                     'healthmonitor_id': self.healthmonitor_id,
                     'protocol': self.protocol,
                     'lb_algorithm': self.lb_algorithm,
                     'status': self.status,
                     'admin_state_up': self.admin_state_up}
        if members and self.members:
            pool_dict['members'] = [member.to_dict()
                                    for member in self.members]
        if healthmonitor and self.healthmonitor:
            pool_dict['healthmonitor'] = self.healthmonitor.to_dict()
        if listener and self.listener:
            pool_dict['listener'] = self.listener.to_dict(loadbalancer=True)
        if sessionpersistence and self.sessionpersistence:
            pool_dict['sessionpersistence'] = self.sessionpersistence.to_dict()
        return pool_dict


class LoadBalancer(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron load balancer."""

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_loadbalancers"

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    vip_subnet_id = sa.Column(sa.String(36))
    vip_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    vip_address = sa.Column(sa.String(36))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    vip_port = orm.relationship(models_v2.Port)
    stats = orm.relationship(
        LoadBalancerStatistics,
        uselist=False,
        backref=orm.backref("loadbalancer", uselist=False),
        cascade="all, delete-orphan")
    provider = orm.relationship(
        st_db.ProviderResourceAssociation,
        uselist=False,
        lazy="joined",
        primaryjoin="LoadBalancer.id==ProviderResourceAssociation.resource_id",
        foreign_keys=[st_db.ProviderResourceAssociation.resource_id],
        #this is only for old API backwards compatibility because when a load
        #balancer is deleted the pool ID should be the same as the load
        #balancer ID and should not be cleared out in this table
        viewonly=True
    )

    def to_dict(self, listeners=False):
        lb_dict = {'id': self.id,
                   'tenant_id': self.tenant_id,
                   'name': self.name,
                   'description': self.description,
                   'vip_subnet_id': self.vip_subnet_id,
                   'vip_address': self.vip_address,
                   'vip_port_id': self.vip_port_id,
                   'status': self.status,
                   'admin_state_up': self.admin_state_up}
        if listeners and self.listeners:
            lb_dict['listeners'] = [listener.to_dict(default_pool=True)
                                    for listener in self.listeners]
        return lb_dict


class Listener(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron listener."""

    @declarative.declared_attr
    def __tablename__(cls):
        return "lbaas_listeners"

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    default_pool_id = sa.Column(sa.String(36), sa.ForeignKey("lbaas_pools.id"),
                                unique=True)
    loadbalancer_id = sa.Column(sa.String(36), sa.ForeignKey(
        "lbaas_loadbalancers.id"))
    protocol = sa.Column(sa.String(36))
    protocol_port = sa.Column(sa.Integer)
    connection_limit = sa.Column(sa.Integer, nullable=True)
    admin_state_up = sa.Column(sa.Boolean(), nullable=False)
    status = sa.Column(sa.String(16), nullable=False)
    default_pool = orm.relationship(
        PoolV2, backref=orm.backref("listener", uselist=False))
    loadbalancer = orm.relationship(
        LoadBalancer, backref=orm.backref("listeners"))

    def to_dict(self, loadbalancer=False, default_pool=False):
        listener_dict = {'id': self.id,
                         'tenant_id': self.tenant_id,
                         'loadbalancer_id': self.loadbalancer_id,
                         'default_pool_id': self.default_pool_id,
                         'protocol': self.protocol,
                         'protocol_port': self.protocol_port,
                         'connection_limit': self.connection_limit,
                         'admin_state_up': self.admin_state_up,
                         'status': self.status}
        if loadbalancer and self.loadbalancer:
            listener_dict['loadbalancer'] = self.loadbalancer.to_dict(
                listeners=True)
        if default_pool and self.default_pool:
            listener_dict['default_pool'] = self.default_pool.to_dict(
                members=True, healthmonitor=True, sessionpersistence=True)
        return listener_dict


class LoadBalancerPluginDbv2(loadbalancerv2.LoadBalancerPluginBaseV2,
                             base_db.CommonDbMixin):
    """Wraps loadbalancer with SQLAlchemy models.

    A class that wraps the implementation of the Neutron loadbalancer
    plugin database access interface using SQLAlchemy models.
    """

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_resource(self, context, model, id, for_update=False):
        resource = None
        try:
            if for_update:
                query = self._model_query(context, model).filter(
                    model.id == id).with_lockmode('update')
                resource = query.one()
            else:
                resource = self._get_by_id(context, model, id)
        except exc.NoResultFound:
            with excutils.save_and_reraise_exception(reraise=False) as ctx:
                if issubclass(model, LoadBalancer):
                    raise loadbalancerv2.LoadBalancerNotFound(lb_id=id)
                if issubclass(model, Listener):
                    raise loadbalancerv2.ListenerNotFound(listener_id=id)
                elif issubclass(model, PoolV2):
                    raise loadbalancerv2.PoolNotFound(pool_id=id)
                elif issubclass(model, MemberV2):
                    raise loadbalancer.MemberNotFound(member_id=id)
                elif issubclass(model, HealthMonitorV2):
                    raise loadbalancer.HealthMonitorNotFound(monitor_id=id)
                ctx.reraise = True
        return resource

    def _get_resources(self, context, model, filters=None):
        query = self._get_collection_query(context, model,
                                           filters=filters)
        return [lb for lb in query]

    def _create_port_for_load_balancer(self, context, lb_db, ip_address):
        # resolve subnet and create port
        subnet = self._core_plugin.get_subnet(context, lb_db.vip_subnet_id)
        fixed_ip = {'subnet_id': subnet['id']}
        if ip_address and ip_address != attributes.ATTR_NOT_SPECIFIED:
            fixed_ip['ip_address'] = ip_address

        port_data = {
            'tenant_id': lb_db.tenant_id,
            'name': 'loadbalancer-' + lb_db.id,
            'network_id': subnet['network_id'],
            'mac_address': attributes.ATTR_NOT_SPECIFIED,
            'admin_state_up': False,
            'device_id': '',
            'device_owner': '',
            'fixed_ips': [fixed_ip]
        }

        port = self._core_plugin.create_port(context, {'port': port_data})
        lb_db.vip_port_id = port['id']
        for fixed_ip in port['fixed_ips']:
            if fixed_ip['subnet_id'] == lb_db.vip_subnet_id:
                lb_db.vip_address = fixed_ip['ip_address']
                break

    def _create_loadbalancer_stats(self, context, loadbalancer_id, data=None):
        # This is internal method to add load balancer statistics.  It won't
        # be exposed to API
        data = data or {}

        stats_db = LoadBalancerStatistics(
            loadbalancer_id=loadbalancer_id,
            bytes_in=data.get(lb_const.STATS_IN_BYTES, 0),
            bytes_out=data.get(lb_const.STATS_OUT_BYTES, 0),
            active_connections=data.get(lb_const.STATS_ACTIVE_CONNECTIONS, 0),
            total_connections=data.get(lb_const.STATS_TOTAL_CONNECTIONS, 0)
        )
        return stats_db

    def _delete_loadbalancer_stats(self, context, loadbalancer_id):
        # This is internal method to delete pool statistics. It won't
        # be exposed to API
        with context.session.begin(subtransactions=True):
            stats_qry = context.session.query(LoadBalancerStatistics)
            try:
                stats = stats_qry.filter_by(
                    loadbalancer_id=loadbalancer_id).one()
            except exc.NoResultFound:
                raise loadbalancerv2.LoadBalancerStatsNotFound(
                    loadbalancer_id=loadbalancer_id)
            context.session.delete(stats)

    def assert_modification_allowed(self, obj):
        status = getattr(obj, 'status', None)
        id = getattr(obj, 'id', None)

        if status in [constants.PENDING_DELETE, constants.PENDING_UPDATE,
                      constants.PENDING_CREATE]:
            raise loadbalancerv2.StateInvalid(id=id, state=status)

    def test_and_set_status(self, context, model, id, status):
        with context.session.begin(subtransactions=True):
            model_db = self._get_resource(context, model, id, for_update=True)
            self.assert_modification_allowed(model_db)
            if model_db.status != status:
                model_db.status = status

    def update_status(self, context, model, id, status):
        with context.session.begin(subtransactions=True):
            if issubclass(model, LoadBalancer):
                try:
                    model_db = (self._model_query(context, model).
                                filter(model.id == id).
                                options(orm.noload('vip_port')).
                                one())
                except exc.NoResultFound:
                    raise loadbalancer.VipNotFound(vip_id=id)
            else:
                model_db = self._get_resource(context, model, id)
            if model_db.status != status:
                model_db.status = status

    def create_loadbalancer(self, context, loadbalancer):
        tenant_id = self._get_tenant_id_for_create(context, loadbalancer)

        with context.session.begin(subtransactions=True):
            lb_db = LoadBalancer(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=loadbalancer.get('name'),
                description=loadbalancer.get('description'),
                vip_subnet_id=loadbalancer.get('vip_subnet_id'),
                admin_state_up=loadbalancer.get('admin_state_up'),
                status=constants.PENDING_CREATE)
            context.session.add(lb_db)
            context.session.flush()

            self._create_port_for_load_balancer(
                context, lb_db, loadbalancer.get('vip_address'))

            lb_db.stats = self._create_loadbalancer_stats(
                context, lb_db.id)
            context.session.add(lb_db)

        return lb_db

    def update_loadbalancer(self, context, id, loadbalancer):
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, LoadBalancer, id)

            lb_db.update(loadbalancer)

        return lb_db

    def delete_loadbalancer(self, context, id):
        with context.session.begin(subtransactions=True):
            lb_db = self._get_resource(context, LoadBalancer, id)
            if lb_db.listener:
                raise loadbalancerv2.LoadBalancerInUse(
                    listener_id=lb_db.listener.id)
            context.session.delete(lb_db)

    def get_loadbalancers(self, context, filters=None, fields=None):
        return self._get_resources(context, LoadBalancer, filters=filters)

    def get_loadbalancer(self, context, id, fields=None):
        lb = self._get_resource(context, LoadBalancer, id)
        return lb

    def create_listener(self, context, listener):
        tenant_id = self._get_tenant_id_for_create(context, listener)
        with context.session.begin(subtransactions=True):
            listener['status'] = constants.PENDING_CREATE

            #Check for unspecified loadbalancer_id and listener_id and
            #set to None
            if (listener.get('loadbalancer_id') ==
                    attributes.ATTR_NOT_SPECIFIED):
                listener['loadbalancer_id'] = None
            if (listener.get('default_pool_id') ==
                    attributes.ATTR_NOT_SPECIFIED):
                listener['default_pool_id'] = None
            listener_db_entry = Listener(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                name=listener['name'],
                description=listener['description'],
                loadbalancer_id=listener['loadbalancer_id'],
                default_pool_id=listener['default_pool_id'],
                protocol=listener['protocol'],
                protocol_port=listener['protocol_port'],
                connection_limit=listener['connection_limit'],
                admin_state_up=listener['admin_state_up'],
                status=listener['status'])
            context.session.add(listener_db_entry)
        return listener_db_entry

    def update_listener(self, context, id, listener):
        with context.session.begin(subtransactions=True):
            listener_db = self._get_resource(context, Listener, id)

            # if listener is already associated with a load balancer and the
            # loadbalancer_id is specified in the new request, then fail
            if (listener_db.loadbalancer_id and
                listener.get('loadbalancer_id') and
                listener.get('loadbalancer_id') !=
                    attributes.ATTR_NOT_SPECIFIED):
                raise loadbalancerv2.LoadBalancerIDImmutable()

            listener_db.update(listener)
        return listener_db

    def delete_listener(self, context, id):
        listener_db_entry = self._get_resource(context, Listener, id)
        with context.session.begin(subtransactions=True):
            context.session.delete(listener_db_entry)
        return None

    def get_listeners(self, context, filters=None, fields=None):
        return self._get_resources(context, Listener, filters=filters)

    def get_listener(self, context, id, fields=None):
        listener = self._get_resource(context, Listener, id)
        return listener

    def create_pool(self, context, pool):
        tenant_id = self._get_tenant_id_for_create(context, pool)
        with context.session.begin(subtransactions=True):
            pool['status'] = constants.PENDING_CREATE
            if pool['healthmonitor_id'] == attributes.ATTR_NOT_SPECIFIED:
                pool['healthmonitor_id'] = None
            pool_db = PoolV2(id=uuidutils.generate_uuid(),
                             tenant_id=tenant_id,
                             name=pool['name'],
                             description=pool['description'],
                             protocol=pool['protocol'],
                             lb_algorithm=pool['lb_algorithm'],
                             admin_state_up=pool['admin_state_up'],
                             healthmonitor_id=pool['healthmonitor_id'],
                             status=pool['status'])
            context.session.add(pool_db)
        return pool_db

    def update_pool(self, context, id, pool):
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, PoolV2, id)

            pool_db.update(pool)

        return pool_db

    def delete_pool(self, context, id):
        with context.session.begin(subtransactions=True):
            pool_db = self._get_resource(context, PoolV2, id)
            context.session.delete(pool_db)

    def get_pools(self, context, filters=None, fields=None):
        return self._get_resources(context, PoolV2, filters=filters)

    def get_pool(self, context, id, fields=None):
        pool = self._get_resource(context, PoolV2, id)
        return pool

    def create_pool_member(self, context, member, pool_id):
        tenant_id = self._get_tenant_id_for_create(context, member)
        try:
            with context.session.begin(subtransactions=True):
                pool_db = self._get_resource(context, PoolV2, pool_id)

                #set status based on if member's pool is part of a
                #load balancer
                member['status'] = constants.ACTIVE
                if pool_db.listener and pool_db.listener.loadbalancer:
                    member['status'] = constants.PENDING_CREATE

                member_db = MemberV2(
                    id=uuidutils.generate_uuid(),
                    tenant_id=tenant_id,
                    pool_id=pool_id,
                    address=member['address'],
                    protocol_port=member['protocol_port'],
                    weight=member.get('weight') or 1,
                    admin_state_up=member.get('admin_state_up'),
                    subnet_id=member.get('subnet_id'),
                    status=member['status'])
                context.session.add(member_db)
        except exception.DBDuplicateEntry:
            raise loadbalancerv2.MemberExists(address=member['address'],
                                              port=member['protocol_port'],
                                              pool=pool_id)
        return member_db

    def update_pool_member(self, context, id, member, pool_id):
        with context.session.begin(subtransactions=True):
            self._get_resource(context, PoolV2, pool_id)
            member_db = self._get_resource(context, MemberV2, id)
            if member_db:
                member_db.update(member)
        return member_db

    def delete_pool_member(self, context, id, pool_id):
        with context.session.begin(subtransactions=True):
            member_db = self._get_resource(context, MemberV2, id)
            context.session.delete(member_db)

    def get_pool_members(self, context, pool_id, filters=None, fields=None):
        if filters:
            filters.update(filters)
        else:
            filters = {'pool_id': [pool_id]}
        return self._get_resources(context, MemberV2, filters=filters)

    def get_pool_member(self, context, id, pool_id, filters=None, fields=None):
        member = self._get_resource(context, MemberV2, id)
        if member.pool_id != pool_id:
            raise loadbalancerv2.PoolNotFound(pool_id=pool_id)
        return member

    def create_healthmonitor(self, context, healthmonitor):
        tenant_id = self._get_tenant_id_for_create(context, healthmonitor)
        with context.session.begin(subtransactions=True):
            healthmonitor['status'] = constants.PENDING_CREATE
            hm_db_entry = HealthMonitorV2(
                id=uuidutils.generate_uuid(),
                tenant_id=tenant_id,
                type=healthmonitor['type'],
                delay=healthmonitor['delay'],
                timeout=healthmonitor['timeout'],
                http_method=healthmonitor['http_method'],
                url_path=healthmonitor['url_path'],
                expected_codes=healthmonitor['expected_codes'],
                admin_state_up=healthmonitor['admin_state_up'],
                max_retries=healthmonitor['max_retries'],
                status=healthmonitor['status'])
            context.session.add(hm_db_entry)
        return hm_db_entry

    def update_healthmonitor(self, context, id, healthmonitor):
        with context.session.begin(subtransactions=True):
            hm_db = self._get_resource(context, HealthMonitorV2, id)
            hm_db.update(healthmonitor)
        return hm_db

    def delete_healthmonitor(self, context, id):
        with context.session.begin(subtransactions=True):
            hm_db_entry = self._get_resource(context, HealthMonitorV2, id)
            context.session.delete(hm_db_entry)
        return None

    def get_healthmonitor(self, context, id, fields=None):
        return self._get_resource(context, HealthMonitorV2, id)

    def get_healthmonitors(self, context, filters=None, fields=None):
        hms = self._get_resources(context, HealthMonitorV2, filters=filters)
        return hms

    def update_loadbalancer_stats(self, context, loadbalancer_id, stats_data):
        pass

    def stats(self, context, loadbalancer_id):
        with context.session.begin(subtransactions=True):
            loadbalancer = self._get_resource(context, LoadBalancer,
                                              loadbalancer_id)
        return loadbalancer.stats
