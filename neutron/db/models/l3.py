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

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import l3agent as rb_model
from neutron.db import models_v2
from neutron.db import standard_attr


class RouterPort(model_base.BASEV2):
    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routers.id', ondelete="CASCADE"),
        primary_key=True)
    port_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('ports.id', ondelete="CASCADE"),
        primary_key=True,
        unique=True)
    revises_on_change = ('router', )
    # The port_type attribute is redundant as the port table already specifies
    # it in DEVICE_OWNER.However, this redundancy enables more efficient
    # queries on router ports, and also prevents potential error-prone
    # conditions which might originate from users altering the DEVICE_OWNER
    # property of router ports.
    port_type = sa.Column(sa.String(db_const.DEVICE_OWNER_FIELD_SIZE))
    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref('routerport', uselist=False, cascade="all,delete"),
        lazy='joined')


class Router(standard_attr.HasStandardAttributes, model_base.BASEV2,
             model_base.HasId, model_base.HasProject):
    """Represents a v2 neutron router."""

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    status = sa.Column(sa.String(16))
    admin_state_up = sa.Column(sa.Boolean)
    gw_port_id = sa.Column(sa.String(36), sa.ForeignKey('ports.id'))
    gw_port = orm.relationship(models_v2.Port, lazy='joined')
    flavor_id = sa.Column(sa.String(36),
                          sa.ForeignKey("flavors.id"), nullable=True)
    attached_ports = orm.relationship(
        RouterPort,
        backref=orm.backref('router', load_on_pending=True),
        lazy='subquery')
    l3_agents = orm.relationship(
        'Agent', lazy='subquery', viewonly=True,
        secondary=rb_model.RouterL3AgentBinding.__table__)
    api_collections = [l3_apidef.ROUTERS]
    collection_resource_map = {l3_apidef.ROUTERS: l3_apidef.ROUTER}
    tag_support = True


class FloatingIP(standard_attr.HasStandardAttributes, model_base.BASEV2,
                 model_base.HasId, model_base.HasProject):
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
    __table_args__ = (
        sa.UniqueConstraint(
            floating_network_id, fixed_port_id, fixed_ip_address,
            name=('uniq_floatingips0floatingnetworkid'
                 '0fixedportid0fixedipaddress')),
        model_base.BASEV2.__table_args__,)
    api_collections = [l3_apidef.FLOATINGIPS]
    collection_resource_map = {l3_apidef.FLOATINGIPS: l3_apidef.FLOATINGIP}
    tag_support = True


class RouterRoute(model_base.BASEV2, models_v2.Route):
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"),
                          primary_key=True)

    router = orm.relationship(Router, load_on_pending=True,
                              backref=orm.backref("route_list",
                                                  lazy='subquery',
                                                  cascade='delete'))
    revises_on_change = ('router', )
