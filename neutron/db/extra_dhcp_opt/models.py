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


class ExtraDhcpOpt(model_base.BASEV2, model_base.HasId):
    """Represent a generic concept of extra options associated to a port.

    Each port may have none to many dhcp opts associated to it that can
    define specifically different or extra options to DHCP clients.
    These will be written to the <network_id>/opts files, and each option's
    tag will be referenced in the <network_id>/host file.
    """
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        nullable=False)
    opt_name = sa.Column(sa.String(64), nullable=False)
    opt_value = sa.Column(sa.String(255), nullable=False)
    ip_version = sa.Column(sa.Integer, server_default='4', nullable=False)
    __table_args__ = (sa.UniqueConstraint(
        'port_id',
        'opt_name',
        'ip_version',
        name='uniq_extradhcpopts0portid0optname0ipversion'),
                      model_base.BASEV2.__table_args__,)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load extra_dhcp_opts bindings
    ports = orm.relationship(
        models_v2.Port, load_on_pending=True,
        backref=orm.backref("dhcp_opts", lazy='selectin', cascade='delete'))
    revises_on_change = ('ports', )
