# Copyright 2014 Red Hat, Inc.
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


from neutron.agent.l3 import agent


class TestL3NATAgent(agent.L3NATAgentWithStateReport):
    NESTED_NAMESPACE_SEPARATOR = '@'

    def get_ns_name(self, router_id):
        ns_name = super(TestL3NATAgent, self).get_ns_name(router_id)
        return "%s%s%s" % (ns_name, self.NESTED_NAMESPACE_SEPARATOR, self.host)

    def get_router_id(self, ns_name):
        # 'ns_name' should be in the format of: 'qrouter-<id>@<host>'.
        return super(TestL3NATAgent, self).get_router_id(
            ns_name.split(self.NESTED_NAMESPACE_SEPARATOR)[0])
