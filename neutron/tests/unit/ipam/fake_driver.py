# Copyright (c) 2015 Infoblox Inc.
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

from neutron.ipam import driver


class FakeDriver(driver.Pool):
    """Fake IPAM driver for tests only

    Just implement IPAM Driver interface without any functionality inside
    """

    def allocate_subnet(self, subnet):
        return driver.Subnet()

    def get_subnet(self, cidr):
        return driver.Subnet()

    def update_subnet(self, request):
        return driver.Subnet()

    def remove_subnet(self, cidr):
        pass
