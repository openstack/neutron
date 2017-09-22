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

from rally import consts
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.neutron import utils
from rally.task import atomic
from rally.task import validation


"""Scenarios for VLAN Aware VMs."""


@validation.required_services(consts.Service.NEUTRON)
@validation.required_openstack(users=True)
@scenario.configure(context={"cleanup@openstack": ["neutron"]},
                    name="NeutronTrunks.create_and_list_trunk_subports")
class TrunkLifeCycle(utils.NeutronScenario):

    def run(self, subport_count=50):
        net = self._create_network({})
        self._create_subnet(net, {'cidr': '10.0.0.0/8'})
        ports = [self._create_port(net, {}) for i in range(subport_count)]
        parent, subports = ports[0], ports[1:]
        subport_payload = [{'port_id': p['port']['id'],
                            'segmentation_type': 'vlan',
                            'segmentation_id': seg_id}
                           for seg_id, p in enumerate(subports, start=1)]
        trunk_payload = {'port_id': parent['port']['id'],
                         'sub_ports': subport_payload}
        trunk = self._create_trunk(trunk_payload)
        self._update_port(parent, {'device_id': 'sometrunk'})
        self._list_trunks(id=trunk['trunk']['id'])
        self._list_ports_by_device_id("sometrunk")
        self._delete_trunk(trunk['trunk']['id'])

    @atomic.action_timer("neutron.delete_trunk")
    def _delete_trunk(self, trunk_id):
        self.clients("neutron").delete_trunk(trunk_id)

    @atomic.action_timer("neutron.create_trunk")
    def _create_trunk(self, trunk_payload):
        return self.clients("neutron").create_trunk({'trunk': trunk_payload})

    @atomic.optional_action_timer("neutron.list_trunks")
    def _list_trunks(self, **kwargs):
        return self.clients("neutron").list_trunks(**kwargs)["trunks"]

    @atomic.optional_action_timer("neutron.list_ports_by_device_id")
    def _list_ports_by_device_id(self, device_id):
        return self.clients("neutron").list_ports(device_id=device_id)
