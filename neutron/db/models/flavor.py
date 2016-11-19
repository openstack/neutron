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

from neutron.api.v2 import attributes as attr


class Flavor(model_base.BASEV2, model_base.HasId):
    name = sa.Column(sa.String(attr.NAME_MAX_LEN))
    description = sa.Column(sa.String(attr.LONG_DESCRIPTION_MAX_LEN))
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    # Make it True for multi-type flavors
    service_type = sa.Column(sa.String(36), nullable=True)
    service_profiles = orm.relationship("FlavorServiceProfileBinding",
        cascade="all, delete-orphan")


class ServiceProfile(model_base.BASEV2, model_base.HasId):
    description = sa.Column(sa.String(attr.LONG_DESCRIPTION_MAX_LEN))
    driver = sa.Column(sa.String(1024), nullable=False)
    enabled = sa.Column(sa.Boolean, nullable=False, default=True,
                        server_default=sa.sql.true())
    metainfo = sa.Column(sa.String(4096))
    flavors = orm.relationship("FlavorServiceProfileBinding")


class FlavorServiceProfileBinding(model_base.BASEV2):
    flavor_id = sa.Column(sa.String(36),
                          sa.ForeignKey("flavors.id",
                                        ondelete="CASCADE"),
                          nullable=False, primary_key=True)
    flavor = orm.relationship(Flavor)
    service_profile_id = sa.Column(sa.String(36),
                                   sa.ForeignKey("serviceprofiles.id",
                                                 ondelete="CASCADE"),
                                   nullable=False, primary_key=True)
    service_profile = orm.relationship(ServiceProfile)
