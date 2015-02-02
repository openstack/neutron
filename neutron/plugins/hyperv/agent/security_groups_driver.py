#Copyright 2014 Cloudbase Solutions SRL
#All Rights Reserved.
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

from hyperv.neutron import security_groups_driver as sg_driver

from neutron.agent import firewall


class HyperVSecurityGroupsDriver(sg_driver.HyperVSecurityGroupsDriverMixin,
                                 firewall.FirewallDriver):
    """Security Groups Driver.

    Security Groups implementation for Hyper-V VMs.
    """
    pass
