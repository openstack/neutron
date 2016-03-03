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

import netaddr
from neutron_lib import constants as n_const
from oslo_versionedobjects import fields as obj_fields
import six

from neutron._i18n import _
from neutron.common import constants
from neutron.common import exceptions


class NeutronRangeConstrainedIntegerInvalidLimit(exceptions.NeutronException):
    message = _("Incorrect range limits specified: "
                "start = %(start)s, end = %(end)s")


class IPV6ModeEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.IPV6_MODES)


class RangeConstrainedInteger(obj_fields.Integer):
    def __init__(self, start, end, **kwargs):
        try:
            self._start = int(start)
            self._end = int(end)
        except (TypeError, ValueError):
            raise NeutronRangeConstrainedIntegerInvalidLimit(
                start=start, end=end)
        super(RangeConstrainedInteger, self).__init__(**kwargs)

    def coerce(self, obj, attr, value):
        if not isinstance(value, six.integer_types):
            msg = _("Field value %s is not an integer") % value
            raise ValueError(msg)
        if not self._start <= value <= self._end:
            msg = _("Field value %s is invalid") % value
            raise ValueError(msg)
        return super(RangeConstrainedInteger, self).coerce(obj, attr, value)


class IPNetworkPrefixLen(RangeConstrainedInteger):
    """IP network (CIDR) prefix length custom Enum"""
    def __init__(self, **kwargs):
        super(IPNetworkPrefixLen, self).__init__(
              start=0, end=constants.IPV6_MAX_PREFIXLEN,
              **kwargs)


class IPNetworkPrefixLenField(obj_fields.AutoTypedField):
    AUTO_TYPE = IPNetworkPrefixLen()


class ListOfIPNetworksField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.List(obj_fields.IPNetwork())


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

    def coerce(self, obj, attr, value):
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
        return super(IntegerEnum, self).coerce(obj, attr, value)


class IPVersionEnum(IntegerEnum):
    """IP version integer Enum"""
    def __init__(self, **kwargs):
        super(IPVersionEnum, self).__init__(
            valid_values=constants.IP_ALLOWED_VERSIONS, **kwargs)


class IPVersionEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = IPVersionEnum()


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
        valid_values=list(n_const.IP_PROTOCOL_MAP.keys()))


class MACAddress(obj_fields.FieldType):
    """MACAddress custom field.

    This custom field is different from the one provided by
    oslo.versionedobjects library: it uses netaddr.EUI type instead of strings.
    """
    def coerce(self, obj, attr, value):
        if not isinstance(value, netaddr.EUI):
            msg = _("Field value %s is not a netaddr.EUI") % value
            raise ValueError(msg)
        return super(MACAddress, self).coerce(obj, attr, value)


class MACAddressField(obj_fields.AutoTypedField):
    AUTO_TYPE = MACAddress()


class IPNetwork(obj_fields.FieldType):
    """IPNetwork custom field.

    This custom field is different from the one provided by
    oslo.versionedobjects library: it does not reset string representation for
    the field.
    """
    def coerce(self, obj, attr, value):
        if not isinstance(value, netaddr.IPNetwork):
            msg = _("Field value %s is not a netaddr.IPNetwork") % value
            raise ValueError(msg)
        return super(IPNetwork, self).coerce(obj, attr, value)


class IPNetworkField(obj_fields.AutoTypedField):
    AUTO_TYPE = IPNetwork()
