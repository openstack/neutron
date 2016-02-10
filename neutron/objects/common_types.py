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
