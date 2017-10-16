# Copyright (c) 2013 OpenStack Foundation
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import models_v2

BINDING_PROFILE_LEN = 4095


class PortBinding(model_base.BASEV2):
    """Represent binding-related state of a port.

    A port binding stores the port attributes required for the
    portbindings extension, as well as internal ml2 state such as
    which MechanismDriver and which segment are used by the port
    binding.
    """

    __tablename__ = 'ml2_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False, default='',
                     server_default='', primary_key=True)
    vnic_type = sa.Column(sa.String(64), nullable=False,
                          default=portbindings.VNIC_NORMAL,
                          server_default=portbindings.VNIC_NORMAL)
    profile = sa.Column(sa.String(BINDING_PROFILE_LEN), nullable=False,
                        default='', server_default='')
    vif_type = sa.Column(sa.String(64), nullable=False)
    vif_details = sa.Column(sa.String(4095), nullable=False, default='',
                            server_default='')
    status = sa.Column(sa.String(16), nullable=False,
                       default=constants.ACTIVE,
                       server_default=constants.ACTIVE)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load port bindings
    port = orm.relationship(
        models_v2.Port,
        load_on_pending=True,
        backref=orm.backref("port_binding",
                            lazy='joined', uselist=False,
                            cascade='delete'))
    revises_on_change = ('port', )


class PortBindingLevel(model_base.BASEV2):
    """Represent each level of a port binding.

    Stores information associated with each level of an established
    port binding. Different levels might correspond to the host and
    ToR switch, for instance.
    """

    __tablename__ = 'ml2_port_binding_levels'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False, primary_key=True)
    level = sa.Column(sa.Integer, primary_key=True, autoincrement=False)
    driver = sa.Column(sa.String(64))
    segment_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networksegments.id',
                                         ondelete="SET NULL"))

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load port bindings
    port = orm.relationship(
        models_v2.Port,
        load_on_pending=True,
        backref=orm.backref("binding_levels", lazy='subquery',
                            cascade='delete'))
    revises_on_change = ('port', )


class DistributedPortBinding(model_base.BASEV2):
    """Represent binding-related state of a Distributed Router(DVR, HA) port.

    Port binding for all the ports associated to a Distributed router(DVR, HA)
    identified by router_id. Currently DEVICE_OWNER_ROUTER_SNAT(DVR+HA router),
    DEVICE_OWNER_DVR_INTERFACE, DEVICE_OWNER_HA_REPLICATED_INT are distributed
    router ports.
    """

    __tablename__ = 'ml2_distributed_port_bindings'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    host = sa.Column(sa.String(255), nullable=False, primary_key=True)
    router_id = sa.Column(sa.String(36), nullable=True)
    vif_type = sa.Column(sa.String(64), nullable=False)
    vif_details = sa.Column(sa.String(4095), nullable=False, default='',
                            server_default='')
    vnic_type = sa.Column(sa.String(64), nullable=False,
                          default=portbindings.VNIC_NORMAL,
                          server_default=portbindings.VNIC_NORMAL)
    profile = sa.Column(sa.String(BINDING_PROFILE_LEN), nullable=False,
                        default='', server_default='')
    status = sa.Column(sa.String(16), nullable=False)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load port bindings
    port = orm.relationship(
        models_v2.Port,
        load_on_pending=True,
        backref=orm.backref("distributed_port_binding",
                            lazy='subquery',
                            cascade='delete'))
    revises_on_change = ('port', )
