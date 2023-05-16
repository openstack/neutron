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

from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import securitygroup_default_rules
from neutron.objects import base


@base.NeutronObjectRegistry.register
class SecurityGroupDefaultRule(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = securitygroup_default_rules.SecurityGroupDefaultRule

    fields = {
        'id': common_types.UUIDField(),
        'remote_group_id': obj_fields.StringField(nullable=True),
        'direction': common_types.FlowDirectionEnumField(nullable=True),
        'ethertype': common_types.EtherTypeEnumField(nullable=True),
        'protocol': common_types.IpProtocolEnumField(nullable=True),
        'port_range_min': common_types.PortRangeWith0Field(nullable=True),
        'port_range_max': common_types.PortRangeWith0Field(nullable=True),
        'remote_ip_prefix': common_types.IPNetworkField(nullable=True),
        'remote_address_group_id': common_types.UUIDField(nullable=True),
        'used_in_default_sg': obj_fields.BooleanField(),
        'used_in_non_default_sg': obj_fields.BooleanField(),
    }

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(SecurityGroupDefaultRule,
                       cls).modify_fields_to_db(fields)
        remote_ip_prefix = result.get('remote_ip_prefix')
        if remote_ip_prefix:
            result['remote_ip_prefix'] = cls.filter_to_str(remote_ip_prefix)
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(SecurityGroupDefaultRule,
                       cls).modify_fields_from_db(db_obj)
        if 'remote_ip_prefix' in fields:
            fields['remote_ip_prefix'] = (
                net_utils.AuthenticIPNetwork(fields['remote_ip_prefix']))
        return fields
