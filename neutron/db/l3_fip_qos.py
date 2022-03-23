#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.db import resource_extend
from neutron_lib.services.qos import constants as qos_consts


@resource_extend.has_resource_extenders
class FloatingQoSDbMixin(object):
    """Mixin class to enable floating IP's QoS extra attributes."""

    @staticmethod
    @resource_extend.extends([l3_apidef.FLOATINGIPS])
    def _extend_extra_fip_dict(fip_res, fip_db):
        qos_id = (fip_db.qos_policy_binding.policy_id if
                  fip_db.qos_policy_binding else None)
        fip_res[qos_consts.QOS_POLICY_ID] = qos_id
        qos_id = (fip_db.qos_network_policy_binding.policy_id if
                  fip_db.qos_network_policy_binding else None)
        fip_res[qos_consts.QOS_NETWORK_POLICY_ID] = qos_id
        return fip_res
