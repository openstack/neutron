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

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
import sqlalchemy as sa
from sqlalchemy import orm


class Flavor(model_base.BASEV2, model_base.HasId):
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    description = sa.Column(sa.String(db_const.LONG_DESCRIPTION_FIELD_SIZE))
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    # Make it True for multi-type flavors
    service_type = sa.Column(sa.String(36), nullable=True)


class ServiceProfile(model_base.BASEV2, model_base.HasId):
    description = sa.Column(sa.String(db_const.LONG_DESCRIPTION_FIELD_SIZE))
    driver = sa.Column(sa.String(1024), nullable=False)
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    metainfo = sa.Column(sa.String(4096))


class FlavorServiceProfileBinding(model_base.BASEV2):
    flavor_id = sa.Column(sa.String(36),
                          sa.ForeignKey("flavors.id",
                                        ondelete="CASCADE"),
                          nullable=False, primary_key=True)
    flavor = orm.relationship(Flavor,
                              backref=orm.backref(
                                  "service_profiles",
                                  lazy='subquery',
                                  cascade="all, delete-orphan"))
    service_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey("serviceprofiles.id",
                                                 ondelete="CASCADE"),
                                   nullable=False, primary_key=True)
    service_profile = orm.relationship(ServiceProfile,
                                       backref="flavors")
