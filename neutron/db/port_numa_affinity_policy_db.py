# Copyright (c) 2020 Red Hat, Inc.
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

from neutron_lib.api.definitions import port_numa_affinity_policy as pnap
from neutron_lib.api.definitions import portbindings
from neutron_lib import exceptions as n_exc

from neutron.objects.port.extensions import port_numa_affinity_policy as \
    pnap_obj


class PortNumaAffinityPolicyDbMixin:
    """Mixin class to add NUMA affinity policy to a port"""

    def _process_create_port(self, context, data, result):
        if not data.get(pnap.NUMA_AFFINITY_POLICY):
            result[pnap.NUMA_AFFINITY_POLICY] = None
            return

        obj = pnap_obj.PortNumaAffinityPolicy(
            context, port_id=result['id'],
            numa_affinity_policy=data[pnap.NUMA_AFFINITY_POLICY])
        obj.create()
        result[pnap.NUMA_AFFINITY_POLICY] = data[pnap.NUMA_AFFINITY_POLICY]

    def _process_update_port(self, context, data, result):
        if pnap.NUMA_AFFINITY_POLICY not in data:
            return

        if (result[portbindings.VIF_TYPE] not in
                portbindings.VIF_UNPLUGGED_TYPES):
            raise n_exc.PortBoundNUMAAffinityPolicy(
                port_id=result['id'], host_id=result[portbindings.HOST_ID],
                numa_affinity_policy=data[pnap.NUMA_AFFINITY_POLICY])

        obj = pnap_obj.PortNumaAffinityPolicy.get_object(context,
                                                         port_id=result['id'])

        if data[pnap.NUMA_AFFINITY_POLICY]:
            if not obj:
                return self._process_create_port(context, data, result)
            obj.update_fields(
                {pnap.NUMA_AFFINITY_POLICY: data[pnap.NUMA_AFFINITY_POLICY]})
            obj.update()
        elif obj:
            obj.delete()

        result[pnap.NUMA_AFFINITY_POLICY] = data[pnap.NUMA_AFFINITY_POLICY]

    def _extend_port_dict(self, port_db, result):
        if port_db.numa_affinity_policy:
            result[pnap.NUMA_AFFINITY_POLICY] = (
                port_db.numa_affinity_policy.numa_affinity_policy)
        else:
            result[pnap.NUMA_AFFINITY_POLICY] = None
