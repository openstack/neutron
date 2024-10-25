# Copyright (c) 2016 Hewlett Packard Enterprise Development Company, L.P.
# All Rights Reserved.
#
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

import neutron.db.l3_dvrscheduler_db as l3agent_dvr_sch_db
import neutron.db.l3_hascheduler_db as l3_ha_sch_db


class L3_DVR_HA_scheduler_db_mixin(l3agent_dvr_sch_db.L3_DVRsch_db_mixin,
                                   l3_ha_sch_db.L3_HA_scheduler_db_mixin):

    def get_dvr_routers_to_remove(self, context, port_id,
                                  get_related_hosts_info=True):
        """Returns info about which routers should be removed

        In case dvr serviceable port was deleted we need to check
        if any dvr routers should be removed from l3 agent on port's host
        """
        remove_router_info = super().get_dvr_routers_to_remove(
                context, port_id, get_related_hosts_info)
        # Process the router information which was returned to make
        # sure we don't delete routers which have dvrhs snat bindings.
        processed_remove_router_info = []
        for router_info in remove_router_info:
            router_id = router_info['router_id']
            agent_id = router_info['agent_id']
            if not self._check_router_agent_ha_binding(
                    context, router_id, agent_id):
                processed_remove_router_info.append(router_info)

        return processed_remove_router_info
