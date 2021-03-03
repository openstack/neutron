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

from neutron_lib.api.definitions import address_group as ag
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import rbac_db_models
from neutron.db import standard_attr


class AddressAssociation(model_base.BASEV2):
    """Represents a neutron address group's address association."""
    __tablename__ = "address_associations"

    address = sa.Column(sa.String(length=db_const.IP_ADDR_FIELD_SIZE),
                        nullable=False, primary_key=True)
    address_group_id = sa.Column(sa.String(length=db_const.UUID_FIELD_SIZE),
                                 sa.ForeignKey("address_groups.id",
                                               ondelete="CASCADE"),
                                 nullable=False, primary_key=True)
    revises_on_change = ('address_groups',)


class AddressGroup(standard_attr.HasStandardAttributes,
                   model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represents a neutron address group."""
    __tablename__ = "address_groups"

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    addresses = orm.relationship(AddressAssociation,
                                 backref=orm.backref('address_groups',
                                                     load_on_pending=True),
                                 lazy='subquery',
                                 cascade='all, delete-orphan')
    rbac_entries = sa.orm.relationship(rbac_db_models.AddressGroupRBAC,
                                       backref='address_groups',
                                       lazy='subquery',
                                       cascade='all, delete, delete-orphan')
    api_collections = [ag.ALIAS]
