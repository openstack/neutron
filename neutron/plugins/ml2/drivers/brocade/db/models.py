# Copyright 2014 Brocade Communications System, Inc.
# All rights reserved.
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


"""Brocade specific database schema/model."""
import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2


class ML2_BrocadeNetwork(model_base.BASEV2, models_v2.HasId,
                         models_v2.HasTenant):
    """Schema for brocade network."""

    vlan = sa.Column(sa.String(10))
    segment_id = sa.Column(sa.String(36))
    network_type = sa.Column(sa.String(10))


class ML2_BrocadePort(model_base.BASEV2, models_v2.HasId,
                      models_v2.HasTenant):
    """Schema for brocade port."""

    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("ml2_brocadenetworks.id"),
                           nullable=False)
    admin_state_up = sa.Column(sa.Boolean, nullable=False)
    physical_interface = sa.Column(sa.String(36))
    vlan_id = sa.Column(sa.String(36))


def create_network(context, net_id, vlan, segment_id, network_type, tenant_id):
    """Create a brocade specific network/port-profiles."""

    # only network_type of vlan is supported
    session = context.session
    with session.begin(subtransactions=True):
        net = get_network(context, net_id, None)
        if not net:
            net = ML2_BrocadeNetwork(id=net_id, vlan=vlan,
                                     segment_id=segment_id,
                                     network_type='vlan',
                                     tenant_id=tenant_id)
            session.add(net)
    return net


def delete_network(context, net_id):
    """Delete a brocade specific network/port-profiles."""

    session = context.session
    with session.begin(subtransactions=True):
        net = get_network(context, net_id, None)
        if net:
            session.delete(net)


def get_network(context, net_id, fields=None):
    """Get brocade specific network, with vlan extension."""

    session = context.session
    return session.query(ML2_BrocadeNetwork).filter_by(id=net_id).first()


def get_networks(context, filters=None, fields=None):
    """Get all brocade specific networks."""

    session = context.session
    return session.query(ML2_BrocadeNetwork).all()


def create_port(context, port_id, network_id, physical_interface,
                vlan_id, tenant_id, admin_state_up):
    """Create a brocade specific port, has policy like vlan."""

    session = context.session
    with session.begin(subtransactions=True):
        port = get_port(context, port_id)
        if not port:
            port = ML2_BrocadePort(id=port_id,
                                   network_id=network_id,
                                   physical_interface=physical_interface,
                                   vlan_id=vlan_id,
                                   admin_state_up=admin_state_up,
                                   tenant_id=tenant_id)
            session.add(port)

    return port


def get_port(context, port_id):
    """get a brocade specific port."""

    session = context.session
    return session.query(ML2_BrocadePort).filter_by(id=port_id).first()


def get_ports(context, network_id=None):
    """get a brocade specific port."""

    session = context.session
    return session.query(ML2_BrocadePort).filter_by(
        network_id=network_id).all()


def delete_port(context, port_id):
    """delete brocade specific port."""

    session = context.session
    with session.begin(subtransactions=True):
        port = get_port(context, port_id)
        if port:
            session.delete(port)


def update_port_state(context, port_id, admin_state_up):
    """Update port attributes."""

    session = context.session
    with session.begin(subtransactions=True):
        session.query(ML2_BrocadePort).filter_by(
            id=port_id).update({'admin_state_up': admin_state_up})
