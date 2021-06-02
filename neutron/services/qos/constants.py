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
VALID_RULE_TYPES = qos_consts.VALID_RULE_TYPES + [RULE_TYPE_PACKET_RATE_LIMIT]
