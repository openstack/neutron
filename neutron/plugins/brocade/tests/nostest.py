# Copyright (c) 2013 Brocade Communications Systems, Inc.
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


"""Brocade NOS Driver Test."""
from __future__ import print_function

import sys

from neutron.plugins.brocade.nos import nosdriver as nos


def nostest(host, username, password):
    # Driver
    driver = nos.NOSdriver()

    # Neutron operations
    vlan = 1001
    mac = '0050.56bf.0001'
    driver.create_network(host, username, password, vlan)
    driver.associate_mac_to_network(host, username, password, vlan, mac)
    driver.dissociate_mac_from_network(host, username, password, vlan, mac)
    driver.delete_network(host, username, password, vlan)

    # AMPP enumeration
    with driver.connect(host, username, password) as mgr:
        print(driver.get_port_profiles(mgr))
        print(driver.get_port_profile(mgr, 'default'))


if __name__ == '__main__':
    nostest(sys.argv[1], sys.argv[2], sys.argv[3])
