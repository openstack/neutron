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

from neutron.db import models_v2


class PortSecurityBinding(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)

    # Add a relationship to the Port model in order to be to able to
    # instruct SQLAlchemy to eagerly load port security binding
    port = orm.relationship(
        models_v2.Port, load_on_pending=True,
        backref=orm.backref("port_security", uselist=False,
                            cascade='delete', lazy='joined'))
    revises_on_change = ('port',)


class NetworkSecurityBinding(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    port_security_enabled = sa.Column(sa.Boolean(), nullable=False)

    # Add a relationship to the Port model in order to be able to instruct
    # SQLAlchemy to eagerly load default port security setting for ports
    # on this network
    network = orm.relationship(
        models_v2.Network, load_on_pending=True,
        backref=orm.backref("port_security", uselist=False,
                            cascade='delete', lazy='joined'))
    revises_on_change = ('network',)
