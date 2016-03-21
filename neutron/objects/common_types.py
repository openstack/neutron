# Copyright 2016 OpenStack Foundation
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
import six

from neutron._i18n import _
from neutron.common import constants


class IPV6ModeEnum(obj_fields.Enum):
    """IPV6 Mode custom Enum"""
    def __init__(self, **kwargs):
        super(IPV6ModeEnum, self).__init__(valid_values=constants.IPV6_MODES,
                                           **kwargs)


class IPV6ModeEnumField(obj_fields.BaseEnumField):
    def __init__(self, **kwargs):
        self.AUTO_TYPE = IPV6ModeEnum()
        super(IPV6ModeEnumField, self).__init__(**kwargs)


class IntegerEnum(obj_fields.Integer):
    def __init__(self, valid_values=None, **kwargs):
        if not valid_values:
            msg = _("No possible values specified")
            raise ValueError(msg)
        for value in valid_values:
            if not isinstance(value, six.integer_types):
                msg = _("Possible value %s is not an integer") % value
                raise ValueError(msg)
        self._valid_values = valid_values
        super(IntegerEnum, self).__init__(**kwargs)

    def _validate_value(self, value):
        if not isinstance(value, six.integer_types):
            msg = _("Field value %s is not an integer") % value
            raise ValueError(msg)
        if value not in self._valid_values:
            msg = (
                _("Field value %(value)s is not in the list "
                  "of valid values: %(values)s") %
                {'value': value, 'values': self._valid_values}
            )
            raise ValueError(msg)

    def coerce(self, obj, attr, value):
        self._validate_value(value)
        return super(IntegerEnum, self).coerce(obj, attr, value)

    def stringify(self, value):
        self._validate_value(value)
        return super(IntegerEnum, self).stringify(value)


class DscpMark(IntegerEnum):
    def __init__(self, valid_values=None, **kwargs):
        super(DscpMark, self).__init__(
            valid_values=constants.VALID_DSCP_MARKS)


class DscpMarkField(obj_fields.AutoTypedField):
    AUTO_TYPE = DscpMark()


class FlowDirectionEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.VALID_DIRECTIONS)


class EtherTypeEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.VALID_ETHERTYPES)


class IpProtocolEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(
        valid_values=list(constants.IP_PROTOCOL_MAP.keys()))
