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

from neutron.objects.qos import policy as policy_object


@resource_extend.has_resource_extenders
class FloatingQoSDbMixin(object):
    """Mixin class to enable floating IP's QoS extra attributes."""

    @staticmethod
    @resource_extend.extends([l3_apidef.FLOATINGIPS])
    def _extend_extra_fip_dict(fip_res, fip_db):
        if fip_db.get('qos_policy_binding'):
            fip_res[qos_consts.QOS_POLICY_ID] = (
                fip_db.qos_policy_binding.policy_id)
        else:
            fip_res[qos_consts.QOS_POLICY_ID] = None
        return fip_res

    def _create_fip_qos_db(self, context, fip_id, policy_id):
        policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
        policy.attach_floatingip(fip_id)

    def _delete_fip_qos_db(self, context, fip_id, policy_id):
        policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
        policy.detach_floatingip(fip_id)

    def _process_extra_fip_qos_create(self, context, fip_id, fip):
        qos_policy_id = fip.get(qos_consts.QOS_POLICY_ID)
        if not qos_policy_id:
            return
        self._create_fip_qos_db(context, fip_id, qos_policy_id)

    def _process_extra_fip_qos_update(
            self, context, floatingip_obj, fip, old_floatingip):
        if qos_consts.QOS_POLICY_ID not in fip:
            # No qos_policy_id in API input, do nothing
            return

        new_qos_policy_id = fip.get(qos_consts.QOS_POLICY_ID)
        old_qos_policy_id = old_floatingip.get(qos_consts.QOS_POLICY_ID)

        if old_qos_policy_id == new_qos_policy_id:
            return
        if old_qos_policy_id:
            self._delete_fip_qos_db(context,
                                    floatingip_obj['id'],
                                    old_qos_policy_id)
        if not new_qos_policy_id:
            return
        self._create_fip_qos_db(
            context, floatingip_obj['id'], new_qos_policy_id)
