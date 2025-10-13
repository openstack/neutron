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

from neutron_lib import constants
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib.db import standard_attr
import sqlalchemy as sa

from neutron.extensions import security_groups_default_rules


class SecurityGroupDefaultRule(standard_attr.HasStandardAttributes,
                               model_base.BASEV2,
                               model_base.HasId):
    """Represents a template of the default neutron security group rules."""

    direction = sa.Column(sa.Enum(constants.INGRESS_DIRECTION,
                                  constants.EGRESS_DIRECTION,
                                  name='defaultsecuritygrouprules_direction'),
                          nullable=False)
    ethertype = sa.Column(sa.String(db_const.ETHERTYPE_FIELD_SIZE))
    remote_group_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE))
    protocol = sa.Column(sa.String(40))
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    remote_ip_prefix = sa.Column(sa.String(255))
    remote_address_group_id = sa.Column(sa.String(db_const.UUID_FIELD_SIZE))
    used_in_default_sg = sa.Column(sa.Boolean(),
                                   server_default=sa.sql.false(),
                                   nullable=False,
                                   default=False)
    used_in_non_default_sg = sa.Column(sa.Boolean(),
                                       server_default=sa.sql.true(),
                                       nullable=False,
                                       default=True)

    api_collections = [security_groups_default_rules.COLLECTION_NAME]
