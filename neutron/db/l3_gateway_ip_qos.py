# Copyright 2018 OpenStack Foundation
# Copyright 2017 Letv Cloud Computing
# All Rights Reserved.
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
from neutron_lib.api.definitions import qos_gateway_ip
from neutron_lib.api import extensions
from neutron_lib.db import resource_extend
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.objects.qos import policy as policy_object

LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class L3_gw_ip_qos_dbonly_mixin(l3_gwmode_db.L3_NAT_dbonly_mixin):
    """Mixin class to add router gateway IP's QoS extra attributes."""

    _gw_ip_qos = None

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict_gw_qos(router_res, router_db):
        if router_db.gw_port_id and router_db.get('qos_policy_binding'):
            policy_id = router_db.qos_policy_binding.policy_id
            router_res[l3_apidef.EXTERNAL_GW_INFO].update(
                {qos_consts.QOS_POLICY_ID: policy_id})

    @property
    def _is_gw_ip_qos_supported(self):
        if self._gw_ip_qos is None:
            # Check L3 service plugin
            self._gw_ip_qos = extensions.is_extension_supported(
                self, qos_gateway_ip.ALIAS)
        return self._gw_ip_qos

    def _create_gw_ip_qos_db(self, context, router_id, policy_id):
        policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
        policy.attach_router(router_id)

    def _delete_gw_ip_qos_db(self, context, router_id, policy_id):
        policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
        policy.detach_router(router_id)

    def _update_router_gw_info(self, context, router_id, info, router=None):
        # Calls superclass, pass router db object for avoiding re-loading
        router = super(L3_gw_ip_qos_dbonly_mixin,
                       self)._update_router_gw_info(
            context, router_id, info, router)

        if self._is_gw_ip_qos_supported and router.gw_port:
            self._update_router_gw_qos_policy(context, router_id,
                                              info, router)

        return router

    def _get_router_gateway_policy_binding(self, context, router_id):
        router = self._get_router(context, router_id)
        return router.qos_policy_binding

    def _update_router_gw_qos_policy(self, context, router_id, info, router):
        if not info or qos_consts.QOS_POLICY_ID not in info:
            # An explicit 'None' for `qos_polcy_id` indicates to clear
            # the router gateway IP policy. So if info does not have
            # the key `qos_polcy_id`, we can not decide what behavior
            # to be done, then directly return here.
            return

        new_qos_policy_id = info[qos_consts.QOS_POLICY_ID]
        if router.qos_policy_binding:
            old_qos_policy_id = router.qos_policy_binding.policy_id

            if old_qos_policy_id == new_qos_policy_id:
                return
            if old_qos_policy_id:
                self._delete_gw_ip_qos_db(context,
                                          router_id,
                                          old_qos_policy_id)

        with context.session.begin(subtransactions=True):
            context.session.refresh(router)

        if new_qos_policy_id:
            self._create_gw_ip_qos_db(
                context, router_id, new_qos_policy_id)

    def _build_routers_list(self, context, routers, gw_ports):
        routers = super(L3_gw_ip_qos_dbonly_mixin,
                        self)._build_routers_list(
                            context, routers, gw_ports)

        if not self._is_gw_ip_qos_supported:
            return routers

        for rtr in routers:
            gw_port_id = rtr['gw_port_id']
            # Collect gw ports only if available
            if gw_port_id and gw_ports.get(gw_port_id):
                rtr['gw_port'] = gw_ports[gw_port_id]
                router_gateway_policy_binding = (
                    self._get_router_gateway_policy_binding(
                        context, rtr['id']))
                qos_policy_id = None
                if router_gateway_policy_binding:
                    qos_policy_id = router_gateway_policy_binding.policy_id
                rtr['gw_port'][qos_consts.QOS_POLICY_ID] = qos_policy_id
        return routers


class L3_gw_ip_qos_db_mixin(L3_gw_ip_qos_dbonly_mixin,
                            l3_db.L3_NAT_db_mixin):
    pass
