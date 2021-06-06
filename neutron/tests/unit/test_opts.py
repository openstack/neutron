# Copyright (c) 2016 OpenStack Foundation.
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


from neutron import opts
from neutron.tests import base


class OptsTestCase(base.BaseTestCase):

    def test_list_sriov_agent_opts(self):
        sriov_agent_opts = opts.list_sriov_agent_opts()
        self.assertEqual('DEFAULT', sriov_agent_opts[0][0])
        self.assertEqual('sriov_nic', sriov_agent_opts[1][0])
        self.assertEqual('agent', sriov_agent_opts[2][0])
