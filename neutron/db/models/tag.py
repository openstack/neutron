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
#

from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa
from sqlalchemy import orm


class Tag(model_base.BASEV2):
    standard_attr_id = sa.Column(
        sa.BigInteger().with_variant(sa.Integer(), 'sqlite'),
        sa.ForeignKey(standard_attr.StandardAttribute.id, ondelete="CASCADE"),
        nullable=False, primary_key=True)
    tag = sa.Column(sa.String(255), nullable=False, primary_key=True)
    standard_attr = orm.relationship(
        'StandardAttribute', load_on_pending=True,
        backref=orm.backref('tags', lazy='joined', viewonly=True),
        sync_backref=False)
    revises_on_change = ('standard_attr', )
