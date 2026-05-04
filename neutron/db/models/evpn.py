# Copyright 2026 Red Hat, LLC
# All Rights Reserved.
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

from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import vxlan_vlan_allocations as alloc_models


class EVPNL3Instance(model_base.BASEV2):
    """EVPN L3 instance linking a router to a VNI/VLAN mapping.

    CASCADE on mapping_id means deleting the mapping row automatically
    removes this instance. RESTRICT on router_id prevents router
    deletion while an EVPN instance exists - user must explicitly
    remove the VNI first.
    """

    __tablename__ = 'evpn_l3_instances'

    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('routers.id', ondelete='RESTRICT'),
        primary_key=True)
    mapping_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('vni_vlan_mapping.id', ondelete='CASCADE'),
        unique=True,
        nullable=False)

    router = orm.relationship(
        'Router',
        load_on_pending=True,
        viewonly=True,
        backref=orm.backref(
            'evpn_instance',
            lazy='selectin',
            uselist=False,
            viewonly=True))

    mapping = orm.relationship(
        alloc_models.VNIVLANMapping,
        lazy='joined',
        viewonly=True,
        backref=orm.backref('l3_instance', uselist=False, viewonly=True))

    revises_on_change = ('router',)


class EVPNNetwork(model_base.BASEV2):
    """Links a network to an EVPN L3 instance (router).

    RESTRICT on both FKs prevents deletion of network or L3 instance
    while the association exists. router_id references the UNIQUE
    column on evpn_l3_instances, allowing direct insert without
    needing to look up the VNI.
    """

    __tablename__ = 'evpn_networks'

    network_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('networks.id', ondelete='RESTRICT'),
        primary_key=True)
    router_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('evpn_l3_instances.router_id', ondelete='RESTRICT'),
        nullable=False)

    network = orm.relationship(
        'Network',
        lazy='joined',
        viewonly=True)

    l3_instance = orm.relationship(
        EVPNL3Instance,
        foreign_keys=[router_id],
        lazy='joined',
        viewonly=True,
        backref=orm.backref('evpn_networks', viewonly=True))


class EVPNAdvertisedPort(model_base.BASEV2):
    """Ports marked for EVPN advertisement.

    Tracks which ports should have their subnets advertised via EVPN.
    The composite FK on (port_id, network_id) referencing ports(id,
    network_id) guarantees the port belongs to the correct network.
    """

    __tablename__ = 'evpn_advertised_ports'

    port_id = sa.Column(sa.String(36), nullable=False, primary_key=True)
    network_id = sa.Column(sa.String(36), nullable=False)

    __table_args__ = (
        sa.ForeignKeyConstraint(
            ['port_id', 'network_id'],
            ['ports.id', 'ports.network_id'],
            ondelete='CASCADE'),
        sa.ForeignKeyConstraint(
            ['network_id'],
            ['evpn_networks.network_id'],
            ondelete='CASCADE'),
        model_base.BASEV2.__table_args__,
    )

    port = orm.relationship(
        'Port',
        foreign_keys=[port_id],
        lazy='joined',
        viewonly=True)

    evpn_network = orm.relationship(
        EVPNNetwork,
        foreign_keys=[network_id],
        lazy='joined',
        viewonly=True)
