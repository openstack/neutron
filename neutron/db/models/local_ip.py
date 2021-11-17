# Copyright 2021 Huawei, Inc.
# All rights reserved.
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

from neutron_lib.api.definitions import local_ip as local_ip_apidef
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa
from sqlalchemy import orm


class LocalIP(standard_attr.HasStandardAttributes, model_base.BASEV2,
              model_base.HasId, model_base.HasProject):
    """Represents a Local IP address.

    This IP address may or may not be allocated to a tenant, and may or
    may not be associated with one or more internal ports.
    """

    __tablename__ = 'local_ips'

    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))
    local_port_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                              sa.ForeignKey('ports.id'),
                              nullable=False)
    network_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                           nullable=False)
    local_ip_address = sa.Column(sa.String(db_const.IP_ADDR_FIELD_SIZE),
                                 nullable=False)
    ip_mode = sa.Column(sa.String(32), nullable=False)

    api_collections = [local_ip_apidef.COLLECTION_NAME]
    collection_resource_map = {
        local_ip_apidef.COLLECTION_NAME: local_ip_apidef.RESOURCE_NAME}


class LocalIPAssociation(model_base.BASEV2):
    """Represents an association between a Local IP and an internal Port."""

    __tablename__ = 'local_ip_associations'

    local_ip_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                            sa.ForeignKey('local_ips.id'),
                            primary_key=True)
    fixed_port_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE),
                              sa.ForeignKey('ports.id', ondelete='CASCADE'),
                              primary_key=True)
    fixed_ip = sa.Column(sa.String(db_const.IP_ADDR_FIELD_SIZE),
                         nullable=False)
    port = orm.relationship("Port",
                            lazy='joined',
                            foreign_keys=fixed_port_id)
    local_ip = orm.relationship("LocalIP",
                                lazy='joined',
                                foreign_keys=local_ip_id,
                                backref=orm.backref("port_associations",
                                                    uselist=True))

    # standard attributes support:
    api_collections = []
    api_sub_resources = [local_ip_apidef.LOCAL_IP_ASSOCIATIONS]
    collection_resource_map = {local_ip_apidef.LOCAL_IP_ASSOCIATIONS:
                               local_ip_apidef.LOCAL_IP_ASSOCIATION}
