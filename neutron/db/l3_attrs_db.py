# Copyright (c) 2014 OpenStack Foundation.  All rights reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.extensions import l3


class RouterExtraAttributes(model_base.BASEV2):
    """Additional attributes for a Virtual Router."""

    # NOTE(armando-migliaccio): this model can be a good place to
    # add extension attributes to a Router model. Each case needs
    # to be individually examined, however 'distributed' and other
    # simple ones fit the pattern well.
    __tablename__ = "router_extra_attributes"
    router_id = sa.Column(sa.String(36),
                          sa.ForeignKey('routers.id', ondelete="CASCADE"),
                          primary_key=True)
    # Whether the router is a legacy (centralized) or a distributed one
    distributed = sa.Column(sa.Boolean, default=False,
                            server_default=sa.sql.false(),
                            nullable=False)
    # Whether the router is to be considered a 'service' router
    service_router = sa.Column(sa.Boolean, default=False,
                               server_default=sa.sql.false(),
                               nullable=False)
    ha = sa.Column(sa.Boolean, default=False,
                   server_default=sa.sql.false(),
                   nullable=False)
    ha_vr_id = sa.Column(sa.Integer())

    router = orm.relationship(
        l3_db.Router,
        backref=orm.backref("extra_attributes", lazy='joined',
                            uselist=False, cascade='delete'))


class ExtraAttributesMixin(object):
    """Mixin class to enable router's extra attributes."""

    extra_attributes = []

    def _extend_extra_router_dict(self, router_res, router_db):
        extra_attrs = router_db['extra_attributes'] or {}
        for attr in self.extra_attributes:
            name = attr['name']
            default = attr['default']
            router_res[name] = (
                extra_attrs[name] if name in extra_attrs else default)

    def _get_extra_attributes(self, router, extra_attributes):
        return (dict((attr['name'],
                      router.get(attr['name'], attr['default']))
                for attr in extra_attributes))

    def _process_extra_attr_router_create(
        self, context, router_db, router_req):
        kwargs = self._get_extra_attributes(router_req, self.extra_attributes)
        # extra_attributes reference is populated via backref
        if not router_db['extra_attributes']:
            attributes_db = RouterExtraAttributes(
                router_id=router_db['id'], **kwargs)
            context.session.add(attributes_db)
            router_db['extra_attributes'] = attributes_db
        else:
            # The record will exist if RouterExtraAttributes model's
            # attributes are added with db migrations over time
            router_db['extra_attributes'].update(kwargs)

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, ['_extend_extra_router_dict'])
