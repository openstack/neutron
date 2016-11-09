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

from oslo_versionedobjects import fields as obj_fields

from neutron._i18n import _
from neutron.services.logapi.common import constants as log_const


class SecurityEvent(obj_fields.String):
    def __init__(self, valid_values, **kwargs):
        self._valid_values = valid_values
        super(SecurityEvent, self).__init__(**kwargs)

    def coerce(self, obj, attr, value):
        if value not in self._valid_values:
            msg = (
                _("Field value %(value)s is not in the list "
                  "of valid values: %(values)s") %
                {'value': value, 'values': self._valid_values}
            )
            raise ValueError(msg)
        return super(SecurityEvent, self).coerce(obj, attr, value)


class SecurityEventField(obj_fields.AutoTypedField):
    AUTO_TYPE = SecurityEvent(valid_values=log_const.LOG_EVENTS)
