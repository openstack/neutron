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

from neutron_lib.db import constants
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy import sql

from neutron.db.models import l3 as l3_models
from neutron.db import models_v2


class NetworkDNSDomain(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True)
    dns_domain = sa.Column(sa.String(255),
                           nullable=False)

    # Add a relationship to the Network model in order to instruct
    # SQLAlchemy to eagerly load this association
    network = orm.relationship(models_v2.Network,
                               load_on_pending=True,
                               backref=orm.backref("dns_domain",
                                                   lazy='joined',
                                                   uselist=False,
                                                   cascade='delete'))
    revises_on_change = ('network', )


class FloatingIPDNS(model_base.BASEV2):

    __tablename__ = 'floatingipdnses'

    floatingip_id = sa.Column(sa.String(36),
                              sa.ForeignKey('floatingips.id',
                                            ondelete="CASCADE"),
                              primary_key=True)
    dns_name = sa.Column(sa.String(255),
                         nullable=False)
    dns_domain = sa.Column(sa.String(255),
                           nullable=False)
    published_dns_name = sa.Column(sa.String(255),
                                   nullable=False)
    published_dns_domain = sa.Column(sa.String(255),
                                     nullable=False)

    # Add a relationship to the FloatingIP model in order to instruct
    # SQLAlchemy to eagerly load this association
    floatingip = orm.relationship(l3_models.FloatingIP,
                                  load_on_pending=True,
                                  backref=orm.backref("dns",
                                                      lazy='joined',
                                                      uselist=False,
                                                      cascade='delete'))
    revises_on_change = ('floatingip', )


class PortDNS(model_base.BASEV2):

    __tablename__ = 'portdnses'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id',
                                      ondelete="CASCADE"),
                        primary_key=True)
    current_dns_name = sa.Column(sa.String(255),
                                 nullable=False)
    current_dns_domain = sa.Column(sa.String(255),
                                   nullable=False)
    previous_dns_name = sa.Column(sa.String(255),
                                  nullable=False)
    previous_dns_domain = sa.Column(sa.String(255),
                                    nullable=False)
    dns_name = sa.Column(sa.String(255), nullable=False)
    dns_domain = sa.Column(sa.String(constants.FQDN_FIELD_SIZE),
                           nullable=False,
                           server_default='')
    # Add a relationship to the Port model in order to instruct
    # SQLAlchemy to eagerly load this association
    port = orm.relationship(models_v2.Port,
                            load_on_pending=True,
                            backref=orm.backref("dns",
                                                lazy='joined',
                                                uselist=False,
                                                cascade='delete'))
    revises_on_change = ('port', )


class SubnetDNSPublishFixedIP(model_base.BASEV2):
    __tablename__ = "subnet_dns_publish_fixed_ips"

    subnet_id = sa.Column(sa.String(constants.UUID_FIELD_SIZE),
                          sa.ForeignKey('subnets.id', ondelete="CASCADE"),
                          primary_key=True)
    dns_publish_fixed_ip = sa.Column(sa.Boolean(),
                                     nullable=False,
                                     server_default=sql.false())

    # Add a relationship to the Subnet model in order to instruct
    # SQLAlchemy to eagerly load this association
    subnet = orm.relationship(models_v2.Subnet,
                              load_on_pending=True,
                              backref=orm.backref("dns_publish_fixed_ip",
                                                  lazy='joined',
                                                  uselist=False,
                                                  cascade='delete'))
    revises_on_change = ('subnet', )
