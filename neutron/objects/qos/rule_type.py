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

from neutron.plugins.common import constants
from neutron_lib.plugins import directory
from oslo_log import log as logging
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron._i18n import _LW
from neutron.objects import base
from neutron.services.qos import qos_consts

LOG = logging.getLogger(__name__)


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
    def get_objects(cls, validate_filters=True, **kwargs):
        if validate_filters:
            cls.validate_filters(**kwargs)

        #TODO(mangelajo): remove in backwards compatible available rule
        #                 inspection in Pike

        core_plugin_supported_rules = getattr(
            directory.get_plugin(), 'supported_qos_rule_types', None)

        rule_types = (
            core_plugin_supported_rules or
            directory.get_plugin(alias=constants.QOS).supported_rule_types)

        if core_plugin_supported_rules:
            LOG.warning(_LW(
                "Your core plugin defines supported_qos_rule_types which is "
                "deprecated and shall be implemented through a QoS driver."
            ))

        # TODO(ihrachys): apply filters to returned result
        return [cls(type=type_) for type_ in rule_types]
