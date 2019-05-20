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

import collections
import itertools
import uuid

import netaddr
from neutron_lib import constants as lib_constants
from neutron_lib.db import constants as lib_db_const
from neutron_lib.objects import exceptions as o_exc

from oslo_serialization import jsonutils
from oslo_versionedobjects import fields as obj_fields
import six

from neutron._i18n import _
from neutron.common import constants
from neutron.common import utils


class HARouterEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.VALID_HA_STATES)


class IPV6ModeEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=lib_constants.IPV6_MODES)


class RangeConstrainedInteger(obj_fields.Integer):
    def __init__(self, start, end, **kwargs):
        try:
            self._start = int(start)
            self._end = int(end)
        except (TypeError, ValueError):
            raise o_exc.NeutronRangeConstrainedIntegerInvalidLimit(
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
              start=0, end=lib_constants.IPv6_BITS,
              **kwargs)


class IPNetworkPrefixLenField(obj_fields.AutoTypedField):
    AUTO_TYPE = IPNetworkPrefixLen()


class PortRange(RangeConstrainedInteger):
    def __init__(self, start=constants.PORT_RANGE_MIN, **kwargs):
        super(PortRange, self).__init__(start=start,
                                        end=constants.PORT_RANGE_MAX, **kwargs)


class PortRangeField(obj_fields.AutoTypedField):
    AUTO_TYPE = PortRange()


class PortRangeWith0Field(obj_fields.AutoTypedField):
    AUTO_TYPE = PortRange(start=0)


class VlanIdRange(RangeConstrainedInteger):
    def __init__(self, **kwargs):
        super(VlanIdRange, self).__init__(start=lib_constants.MIN_VLAN_TAG,
                                          end=lib_constants.MAX_VLAN_TAG,
                                          **kwargs)


class VlanIdRangeField(obj_fields.AutoTypedField):
    AUTO_TYPE = VlanIdRange()


class ListOfIPNetworksField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.List(obj_fields.IPNetwork())


class SetOfUUIDsField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Set(obj_fields.UUID())


class DomainName(obj_fields.String):
    def coerce(self, obj, attr, value):
        if not isinstance(value, six.string_types):
            msg = _("Field value %s is not a string") % value
            raise ValueError(msg)
        if len(value) > lib_db_const.FQDN_FIELD_SIZE:
            msg = _("Domain name %s is too long") % value
            raise ValueError(msg)
        return super(DomainName, self).coerce(obj, attr, value)


class DomainNameField(obj_fields.AutoTypedField):
    AUTO_TYPE = DomainName()


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
            valid_values=lib_constants.VALID_DSCP_MARKS)


class DscpMarkField(obj_fields.AutoTypedField):
    AUTO_TYPE = DscpMark()


class FlowDirectionEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=lib_constants.VALID_DIRECTIONS)


class IpamAllocationStatusEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(
        valid_values=constants.VALID_IPAM_ALLOCATION_STATUSES)


class EtherTypeEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.VALID_ETHERTYPES)


class IpProtocolEnum(obj_fields.Enum):
    """IP protocol number Enum"""
    def __init__(self, **kwargs):
        super(IpProtocolEnum, self).__init__(
            valid_values=list(
                itertools.chain(
                    lib_constants.IP_PROTOCOL_MAP.keys(),
                    [str(v) for v in range(256)]
                )
            ),
            **kwargs)


class PortBindingStatusEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.PORT_BINDING_STATUSES)


class IpProtocolEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = IpProtocolEnum()


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

    @staticmethod
    def to_primitive(obj, attr, value):
        return str(value)

    @staticmethod
    def from_primitive(obj, attr, value):
        try:
            return utils.AuthenticEUI(value)
        except Exception:
            msg = _("Field value %s is not a netaddr.EUI") % value
            raise ValueError(msg)


class MACAddressField(obj_fields.AutoTypedField):
    AUTO_TYPE = MACAddress()


class DictOfMiscValues(obj_fields.FieldType):
    """DictOfMiscValues custom field

    This custom field is handling dictionary with miscellaneous value types,
    including integer, float, boolean and list and nested dictionaries.
    """
    @staticmethod
    def coerce(obj, attr, value):
        if isinstance(value, dict):
            return value
        if isinstance(value, six.string_types):
            try:
                return jsonutils.loads(value)
            except Exception:
                msg = _("Field value %s is not stringified JSON") % value
                raise ValueError(msg)
        msg = (_("Field value %s is not type of dict or stringified JSON")
               % value)
        raise ValueError(msg)

    @staticmethod
    def from_primitive(obj, attr, value):
        return DictOfMiscValues.coerce(obj, attr, value)

    @staticmethod
    def to_primitive(obj, attr, value):
        return jsonutils.dumps(value)

    @staticmethod
    def stringify(value):
        return jsonutils.dumps(value)


class DictOfMiscValuesField(obj_fields.AutoTypedField):
    AUTO_TYPE = DictOfMiscValues


class ListOfDictOfMiscValuesField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.List(DictOfMiscValuesField())


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

    @staticmethod
    def to_primitive(obj, attr, value):
        return str(value)

    @staticmethod
    def from_primitive(obj, attr, value):
        try:
            return utils.AuthenticIPNetwork(value)
        except Exception:
            msg = _("Field value %s is not a netaddr.IPNetwork") % value
            raise ValueError(msg)


class IPNetworkField(obj_fields.AutoTypedField):
    AUTO_TYPE = IPNetwork()


class UUID(obj_fields.UUID):
    def coerce(self, obj, attr, value):
        uuid.UUID(str(value))
        return str(value)


class UUIDField(obj_fields.AutoTypedField):
    AUTO_TYPE = UUID()


class FloatingIPStatusEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.VALID_FLOATINGIP_STATUS)


class RouterStatusEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=constants.VALID_ROUTER_STATUS)


# Duplicate some fixes in later oslo.versionedobjects, so we can backport
# fixes without modifying requirements.
class List(obj_fields.List):
    def coerce(self, obj, attr, value):
        if (not isinstance(value, collections.Iterable) or
           isinstance(value, six.string_types + (collections.Mapping,))):
            raise ValueError(_('A list is required in field %(attr)s, '
                               'not a %(type)s') %
                             {'attr': attr, 'type': type(value).__name__})
        coerced_list = obj_fields.CoercedList()
        coerced_list.enable_coercing(self._element_type, obj, attr)
        coerced_list.extend(value)
        return coerced_list


class ListOfObjectsField(obj_fields.AutoTypedField):
    def __init__(self, objtype, subclasses=False, **kwargs):
        self.AUTO_TYPE = List(obj_fields.Object(objtype, subclasses))
        self.objname = objtype
        super(ListOfObjectsField, self).__init__(**kwargs)
