#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib.services.qos import constants as qos_consts

# TODO(liuyulong): Because of the development sequence, the rule must
# be implemented in Neutron first. Then the following can be moved
# to neutron-lib after neutron has the new rule.
# Add qos rule packet rate limit
RULE_TYPE_PACKET_RATE_LIMIT = 'packet_rate_limit'
# NOTE(przszc): Ensure that there are no duplicates in the list. Order of the
# items in the list must be stable, as QosRuleType OVO hash value depends on
# it.
# TODO(przszc): When a rule type is moved to neutron-lib, it can be removed
# from the list below.
VALID_RULE_TYPES = (qos_consts.VALID_RULE_TYPES +
    ([RULE_TYPE_PACKET_RATE_LIMIT] if RULE_TYPE_PACKET_RATE_LIMIT not in
        qos_consts.VALID_RULE_TYPES else [])
)
