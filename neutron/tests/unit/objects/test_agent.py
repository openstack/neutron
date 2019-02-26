# Copyright (c) 2016 Intel Corporation.
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

from neutron.objects import agent
from neutron.tests.unit.objects import test_base as obj_test_base
from neutron.tests.unit import testlib_api


class AgentIfaceObjectTestCase(obj_test_base.BaseObjectIfaceTestCase):

    _test_class = agent.Agent


class AgentDbObjectTestCase(obj_test_base.BaseDbObjectTestCase,
                            testlib_api.SqlTestCase):

    _test_class = agent.Agent

    def test_configurations(self):
        obj = self.objs[0]
        obj.create()

        obj.configurations = {}
        obj.update()

        db_fields = obj.modify_fields_to_db(obj)
        self.assertEqual('', db_fields['configurations'])

        obj = agent.Agent.get_object(self.context, id=obj.id)
        self.assertEqual({}, obj.configurations)

        conf = {"tunnel_types": ["vxlan"],
                "tunneling_ip": "20.0.0.1",
                "bridge_mappings": {"phys_net1": "br-eth-1"}}
        obj.configurations = conf
        obj.update()

        obj = agent.Agent.get_object(self.context, id=obj.id)
        self.assertEqual(conf, obj.configurations)

    def test_resource_versions(self):
        obj = self.objs[0]
        versions = {'obj1': 'ver1', 'obj2': 1.1}
        obj.resource_versions = versions
        obj.create()

        obj = agent.Agent.get_object(self.context, id=obj.id)
        self.assertEqual(versions, obj.resource_versions)

        obj.resource_versions = {}
        obj.update()

        db_fields = obj.modify_fields_to_db(obj)
        self.assertIsNone(db_fields['resource_versions'])

        obj = agent.Agent.get_object(self.context, id=obj.id)
        self.assertIsNone(obj.resource_versions)

        obj.resource_versions = None
        obj.update()
        self.assertIsNone(obj.resource_versions)

        db_fields = obj.modify_fields_to_db(obj)
        self.assertIsNone(db_fields['resource_versions'])

    def test_resources_synced_10(self):
        obj = agent.Agent()
        primitive = obj.obj_to_primitive(target_version='1.0')
        self.assertNotIn(
            'resources_synced', primitive['versioned_object.data'])
