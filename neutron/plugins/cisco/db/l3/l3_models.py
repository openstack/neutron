# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import agents_db
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2


class HostingDevice(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents an appliance hosting Neutron router(s).

       When the hosting device is a Nova VM 'id' is uuid of that VM.
    """
    __tablename__ = 'cisco_hosting_devices'

    # complementary id to enable identification of associated Neutron resources
    complementary_id = sa.Column(sa.String(36))
    # manufacturer id of the device, e.g., its serial number
    device_id = sa.Column(sa.String(255))
    admin_state_up = sa.Column(sa.Boolean, nullable=False, default=True)
    # 'management_port_id' is the Neutron Port used for management interface
    management_port_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('ports.id',
                                                 ondelete="SET NULL"))
    management_port = orm.relationship(models_v2.Port)
    # 'protocol_port' is udp/tcp port of hosting device. May be empty.
    protocol_port = sa.Column(sa.Integer)
    cfg_agent_id = sa.Column(sa.String(36),
                             sa.ForeignKey('agents.id'),
                             nullable=True)
    cfg_agent = orm.relationship(agents_db.Agent)
    # Service VMs take time to boot so we store creation time
    # so we can give preference to older ones when scheduling
    created_at = sa.Column(sa.DateTime, nullable=False)
    status = sa.Column(sa.String(16))


class HostedHostingPortBinding(model_base.BASEV2):
    """Represents binding of logical resource's port to its hosting port."""
    __tablename__ = 'cisco_port_mappings'

    logical_resource_id = sa.Column(sa.String(36), primary_key=True)
    logical_port_id = sa.Column(sa.String(36),
                                sa.ForeignKey('ports.id',
                                              ondelete="CASCADE"),
                                primary_key=True)
    logical_port = orm.relationship(
        models_v2.Port,
        primaryjoin='Port.id==HostedHostingPortBinding.logical_port_id',
        backref=orm.backref('hosting_info', cascade='all', uselist=False))
    # type of hosted port, e.g., router_interface, ..._gateway, ..._floatingip
    port_type = sa.Column(sa.String(32))
    # type of network the router port belongs to
    network_type = sa.Column(sa.String(32))
    hosting_port_id = sa.Column(sa.String(36),
                                sa.ForeignKey('ports.id',
                                              ondelete='CASCADE'))
    hosting_port = orm.relationship(
        models_v2.Port,
        primaryjoin='Port.id==HostedHostingPortBinding.hosting_port_id')
    # VLAN tag for trunk ports
    segmentation_id = sa.Column(sa.Integer, autoincrement=False)


class RouterHostingDeviceBinding(model_base.BASEV2):
    """Represents binding between Neutron routers and their hosting devices."""
    __tablename__ = 'cisco_router_mappings'

    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete='CASCADE'),
                          primary_key=True)
    router = orm.relationship(
        l3_db.Router,
        backref=orm.backref('hosting_info', cascade='all', uselist=False))
    # If 'auto_schedule' is True then router is automatically scheduled
    # if it lacks a hosting device or its hosting device fails.
    auto_schedule = sa.Column(sa.Boolean, default=True, nullable=False)
    # id of hosting device hosting this router, None/NULL if unscheduled.
    hosting_device_id = sa.Column(sa.String(36),
                                  sa.ForeignKey('cisco_hosting_devices.id',
                                                ondelete='SET NULL'))
    hosting_device = orm.relationship(HostingDevice)
