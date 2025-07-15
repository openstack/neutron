# Copyright (c) 2024
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

from ovs.db import idl
import ovs.ovsuuid


# Temporarily fix ovs.db.idl.Transaction._substitute_uuids to support handling
# the persist_uuid feature
def _substitute_uuids(self, json):
    if isinstance(json, list | tuple):
        if (len(json) == 2 and
                json[0] == 'uuid' and
                ovs.ovsuuid.is_valid_string(json[1])):
            uuid = ovs.ovsuuid.from_string(json[1])
            row = self._txn_rows.get(uuid, None)
            if row and row._data is None and not row._persist_uuid:
                return ["named-uuid", idl._uuid_name_from_uuid(uuid)]
        else:
            return [self._substitute_uuids(elem) for elem in json]
    return json


def apply_ovs_fixes():
    idl.Transaction._substitute_uuids = _substitute_uuids
