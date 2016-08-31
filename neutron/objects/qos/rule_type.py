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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron import manager
from neutron.objects import base
from neutron.services.qos import qos_consts


class RuleTypeField(obj_fields.BaseEnumField):

    def __init__(self, **kwargs):
        self.AUTO_TYPE = obj_fields.Enum(
            valid_values=qos_consts.VALID_RULE_TYPES)
        super(RuleTypeField, self).__init__(**kwargs)


@obj_base.VersionedObjectRegistry.register
class QosRuleType(base.NeutronObject):
    # Version 1.0: Initial version
    # Version 1.1: Added QosDscpMarkingRule
    # Version 1.2: Added QosMinimumBandwidthRule
    VERSION = '1.2'

    fields = {
        'type': RuleTypeField(),
    }

    # we don't receive context because we don't need db access at all
    @classmethod
    def get_objects(cls, **kwargs):
        cls.validate_filters(**kwargs)
        core_plugin = manager.NeutronManager.get_plugin()
        return [cls(type=type_)
                for type_ in core_plugin.supported_qos_rule_types]
