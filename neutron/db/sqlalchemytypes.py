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

"""Custom SQLAlchemy types."""

import netaddr
from sqlalchemy import types

from neutron._i18n import _


class IPAddress(types.TypeDecorator):

    impl = types.String(64)

    def process_result_value(self, value, dialect):
        return netaddr.IPAddress(value)

    def process_bind_param(self, value, dialect):
        if not isinstance(value, netaddr.IPAddress):
            raise AttributeError(_("Received type '%(type)s' and value "
                                   "'%(value)s'. Expecting netaddr.IPAddress "
                                   "type.") % {'type': type(value),
                                               'value': value})

        return str(value)


class CIDR(types.TypeDecorator):

    impl = types.String(64)

    def process_result_value(self, value, dialect):
        return netaddr.IPNetwork(value)

    def process_bind_param(self, value, dialect):
        if not isinstance(value, netaddr.IPNetwork):
            raise AttributeError(_("Received type '%(type)s' and value "
                                   "'%(value)s'. Expecting netaddr.IPNetwork "
                                   "type.") % {'type': type(value),
                                               'value': value})
        return str(value)


class MACAddress(types.TypeDecorator):

    impl = types.String(64)

    def process_result_value(self, value, dialect):
        return netaddr.EUI(value)

    def process_bind_param(self, value, dialect):
        if not isinstance(value, netaddr.EUI):
            raise AttributeError(_("Received type '%(type)s' and value "
                                   "'%(value)s'. Expecting netaddr.EUI "
                                   "type.") % {'type': type(value),
                                               'value': value})
        return str(value)


class TruncatedDateTime(types.TypeDecorator):
    """Truncates microseconds.

    Use this for datetime fields so we don't have to worry about DB-specific
    behavior when it comes to rounding/truncating microseconds off of
    timestamps.
    """

    impl = types.DateTime

    def process_bind_param(self, value, dialect):
        return value.replace(microsecond=0) if value else value

    process_result_value = process_bind_param
