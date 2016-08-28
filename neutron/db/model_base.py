# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import debtcollector
from oslo_db.sqlalchemy import models
from oslo_utils import uuidutils
import sqlalchemy as sa
from sqlalchemy.ext import declarative
from sqlalchemy import orm

from neutron.api.v2 import attributes as attr


class HasProject(object):
    """Project mixin, add to subclasses that have a user."""

    # NOTE(jkoelker) project_id is just a free form string ;(
    project_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN), index=True)

    def get_tenant_id(self):
        return self.project_id

    def set_tenant_id(self, value):
        self.project_id = value

    @declarative.declared_attr
    def tenant_id(cls):
        return orm.synonym(
            'project_id',
            descriptor=property(cls.get_tenant_id, cls.set_tenant_id))


HasTenant = debtcollector.moves.moved_class(HasProject, "HasTenant", __name__)


class HasProjectNoIndex(HasProject):
    """Project mixin, add to subclasses that have a user."""

    # NOTE(jkoelker) project_id is just a free form string ;(
    project_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN))


class HasProjectPrimaryKeyIndex(HasProject):
    """Project mixin, add to subclasses that have a user."""

    # NOTE(jkoelker) project_id is just a free form string ;(
    project_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN), nullable=False,
                           primary_key=True, index=True)


class HasProjectPrimaryKey(HasProject):
    """Project mixin, add to subclasses that have a user."""

    # NOTE(jkoelker) project_id is just a free form string ;(
    project_id = sa.Column(sa.String(attr.TENANT_ID_MAX_LEN), nullable=False,
                           primary_key=True)


class HasId(object):
    """id mixin, add to subclasses that have an id."""

    def __init__(self, *args, **kwargs):
        # NOTE(dasm): debtcollector requires init in class
        super(HasId, self).__init__(*args, **kwargs)

    id = sa.Column(sa.String(36),
                   primary_key=True,
                   default=uuidutils.generate_uuid)


class HasStatusDescription(object):
    """Status with description mixin."""

    def __init__(self, *args, **kwargs):
        # NOTE(dasm): debtcollector requires init in class
        super(HasStatusDescription, self).__init__(*args, **kwargs)

    status = sa.Column(sa.String(16), nullable=False)
    status_description = sa.Column(sa.String(attr.DESCRIPTION_MAX_LEN))


class NeutronBase(models.ModelBase):
    """Base class for Neutron Models."""

    __table_args__ = {'mysql_engine': 'InnoDB'}

    def __iter__(self):
        self._i = iter(orm.object_mapper(self).columns)
        return self

    def next(self):
        n = next(self._i).name
        return n, getattr(self, n)

    __next__ = next

    def __repr__(self):
        """sqlalchemy based automatic __repr__ method."""
        items = ['%s=%r' % (col.name, getattr(self, col.name))
                 for col in self.__table__.columns]
        return "<%s.%s[object at %x] {%s}>" % (self.__class__.__module__,
                                               self.__class__.__name__,
                                               id(self), ', '.join(items))


class NeutronBaseV2(NeutronBase):

    @declarative.declared_attr
    def __tablename__(cls):
        # NOTE(jkoelker) use the pluralized name of the class as the table
        return cls.__name__.lower() + 's'


BASEV2 = declarative.declarative_base(cls=NeutronBaseV2)


def get_unique_keys(model):
    try:
        constraints = model.__table__.constraints
    except AttributeError:
        constraints = []
    return [[c.name for c in constraint.columns]
            for constraint in constraints
            if isinstance(constraint, sa.UniqueConstraint)]
