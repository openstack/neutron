# Copyright (c) 2016 Intel Corporation.
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

from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import metering as metering_models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class MeteringLabelRule(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 2.0: Source and destination field for the metering label rule
    VERSION = '2.0'

    db_model = metering_models.MeteringLabelRule

    foreign_keys = {'MeteringLabel': {'metering_label_id': 'id'}}

    fields = {
        'id': common_types.UUIDField(),
        'direction': common_types.FlowDirectionEnumField(nullable=True),
        'remote_ip_prefix': common_types.IPNetworkField(nullable=True),
        'source_ip_prefix': common_types.IPNetworkField(nullable=True),
        'destination_ip_prefix': common_types.IPNetworkField(nullable=True),
        'metering_label_id': common_types.UUIDField(),
        'excluded': obj_fields.BooleanField(default=False),
    }

    fields_no_update = ['metering_label_id']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super().modify_fields_from_db(db_obj)

        cls.ip_field_from_db(result, "remote_ip_prefix")
        cls.ip_field_from_db(result, "source_ip_prefix")
        cls.ip_field_from_db(result, "destination_ip_prefix")

        return result

    @classmethod
    def ip_field_from_db(cls, result, attribute_name):
        if attribute_name in result:
            result[attribute_name] = net_utils.AuthenticIPNetwork(
                result[attribute_name])

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)

        cls.ip_field_to_db(result, "remote_ip_prefix")
        cls.ip_field_to_db(result, "source_ip_prefix")
        cls.ip_field_to_db(result, "destination_ip_prefix")

        return result

    @classmethod
    def ip_field_to_db(cls, result, attribute_name):
        if attribute_name in result:
            result[attribute_name] = cls.filter_to_str(result[attribute_name])


@base.NeutronObjectRegistry.register
class MeteringLabel(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = metering_models.MeteringLabel
    synthetic_fields = ['rules']

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(),
        'description': obj_fields.StringField(),
        'rules': obj_fields.ListOfObjectsField('MeteringLabelRule',
                                               nullable=True),
        'shared': obj_fields.BooleanField(default=False),
    }
