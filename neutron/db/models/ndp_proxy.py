# Copyright 2022 Troila
# All Rights Reserved.
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

from neutron_lib.api.definitions import l3_ndp_proxy as apidef
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa
from sqlalchemy import orm

from neutron.db.models import l3


class NDPProxy(standard_attr.HasStandardAttributes,
               model_base.BASEV2, model_base.HasId,
               model_base.HasProject):

    __tablename__ = 'ndp_proxies'

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    router_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"),
                          nullable=False)
    port_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                        sa.ForeignKey('ports.id',
                                      ondelete="CASCADE"),
                        nullable=False)
    ip_address = sa.Column(sa.String(db_const.IP_ADDR_FIELD_SIZE),
                           nullable=False)
    api_collections = [apidef.COLLECTION_NAME]
    collection_resource_map = {apidef.COLLECTION_NAME:
                               apidef.RESOURCE_NAME}


class RouterNDPProxyState(model_base.BASEV2):

    __tablename__ = 'router_ndp_proxy_state'

    router_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                          sa.ForeignKey('routers.id',
                                        ondelete="CASCADE"),
                          nullable=False, primary_key=True)
    enable_ndp_proxy = sa.Column(sa.Boolean(), nullable=False)
    router = orm.relationship(
        l3.Router, load_on_pending=True,
        backref=orm.backref("ndp_proxy_state",
                            lazy='subquery', uselist=False,
                            cascade='delete')
    )
