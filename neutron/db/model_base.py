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

from oslo_db.sqlalchemy import models
from sqlalchemy.ext import declarative
from sqlalchemy import orm


class NeutronBase(models.ModelBase):
    """Base class for Neutron Models."""

    __table_args__ = {'mysql_engine': 'InnoDB'}

    def __iter__(self):
        self._i = iter(orm.object_mapper(self).columns)
        return self

    def next(self):
        n = self._i.next().name
        return n, getattr(self, n)

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
