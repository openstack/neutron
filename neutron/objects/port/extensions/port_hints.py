# Copyright 2023 Ericsson Software Technology
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron_lib.objects import common_types

from neutron.db.models import port_hints
from neutron.objects import base


@base.NeutronObjectRegistry.register
class PortHints(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = port_hints.PortHints

    primary_keys = ['port_id']

    fields = {
        'port_id': common_types.UUIDField(),
        'hints': common_types.DictOfMiscValuesField(),
    }

    foreign_keys = {'Port': {'port_id': 'id'}}

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        if 'hints' in result:
            # dump field into string, set '' if empty '{}' or None
            result['hints'] = (
                cls.filter_to_json_str(result['hints'], default=''))
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super().modify_fields_from_db(db_obj)
        if 'hints' in fields:
            # load string from DB into dict, set None if hints is ''
            fields['hints'] = (
                cls.load_json_from_str(fields['hints']))
        return fields
