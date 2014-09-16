# Copyright 2013 Brocade Communications System, Inc.
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


class BrocadeNetwork(model_base.BASEV2, models_v2.HasId):
    """Schema for brocade network."""

    vlan = sa.Column(sa.String(10))


class BrocadePort(model_base.BASEV2):
    """Schema for brocade port."""

    port_id = sa.Column(sa.String(36), primary_key=True, default="",
                        server_default='')
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey("brocadenetworks.id"),
                           nullable=False)
    admin_state_up = sa.Column(sa.Boolean, nullable=False)
    physical_interface = sa.Column(sa.String(36))
    vlan_id = sa.Column(sa.String(36))
    tenant_id = sa.Column(sa.String(36))


def create_network(context, net_id, vlan):
    """Create a brocade specific network/port-profiles."""

    session = context.session
    with session.begin(subtransactions=True):
        net = BrocadeNetwork(id=net_id, vlan=vlan)
        session.add(net)

    return net


def delete_network(context, net_id):
    """Delete a brocade specific network/port-profiles."""

    session = context.session
    with session.begin(subtransactions=True):
        net = (session.query(BrocadeNetwork).filter_by(id=net_id).first())
        if net is not None:
            session.delete(net)


def get_network(context, net_id, fields=None):
    """Get brocade specific network, with vlan extension."""

    session = context.session
    return (session.query(BrocadeNetwork).filter_by(id=net_id).first())


def get_networks(context, filters=None, fields=None):
    """Get all brocade specific networks."""

    session = context.session
    try:
        nets = session.query(BrocadeNetwork).all()
        return nets
    except sa.exc.SQLAlchemyError:
        return None


def create_port(context, port_id, network_id, physical_interface,
                vlan_id, tenant_id, admin_state_up):
    """Create a brocade specific port, has policy like vlan."""

    # port_id is truncated: since the linux-bridge tap device names are
    # based on truncated port id, this enables port lookups using
    # tap devices
    port_id = port_id[0:11]
    session = context.session
    with session.begin(subtransactions=True):
        port = BrocadePort(port_id=port_id,
                           network_id=network_id,
                           physical_interface=physical_interface,
                           vlan_id=vlan_id,
                           admin_state_up=admin_state_up,
                           tenant_id=tenant_id)
        session.add(port)
    return port


def get_port(context, port_id):
    """get a brocade specific port."""

    port_id = port_id[0:11]
    session = context.session
    port = (session.query(BrocadePort).filter_by(port_id=port_id).first())
    return port


def get_ports(context, network_id=None):
    """get a brocade specific port."""

    session = context.session
    ports = (session.query(BrocadePort).filter_by(network_id=network_id).all())
    return ports


def delete_port(context, port_id):
    """delete brocade specific port."""

    port_id = port_id[0:11]
    session = context.session
    with session.begin(subtransactions=True):
        port = (session.query(BrocadePort).filter_by(port_id=port_id).first())
        if port is not None:
            session.delete(port)


def get_port_from_device(session, port_id):
    """get port from the tap device."""

    # device is same as truncated port_id
    port = (session.query(BrocadePort).filter_by(port_id=port_id).first())
    return port


def update_port_state(context, port_id, admin_state_up):
    """Update port attributes."""

    port_id = port_id[0:11]
    session = context.session
    session.query(BrocadePort).filter_by(
        port_id=port_id).update({'admin_state_up': admin_state_up})
