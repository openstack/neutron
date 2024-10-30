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

from neutron_lib.api.definitions import port_hints as phints_def
from oslo_serialization import jsonutils

from neutron.objects.port.extensions import port_hints as phints_obj


class PortHintsMixin:
    """Mixin class to add hints to a port"""

    def _process_create_port(self, context, data, result):
        if not data.get(phints_def.HINTS):
            result[phints_def.HINTS] = None
            return

        obj = phints_obj.PortHints(
            context, port_id=result['id'],
            hints=data[phints_def.HINTS])
        obj.create()
        result[phints_def.HINTS] = data[phints_def.HINTS]

    def _process_update_port(self, context, data, result):
        obj = phints_obj.PortHints.get_object(
            context, port_id=result['id'])

        if obj:
            if data[phints_def.HINTS]:
                obj.hints = data[phints_def.HINTS]
                obj.update()
            else:
                obj.delete()
            result[phints_def.HINTS] = data[phints_def.HINTS]
        else:
            self._process_create_port(context, data, result)

    def _extend_port_dict(self, port_db, result):
        if port_db.hints:
            result[phints_def.HINTS] = jsonutils.loads(port_db.hints.hints)
        else:
            result[phints_def.HINTS] = None
