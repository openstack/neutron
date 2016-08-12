# Copyright 2016 Hewlett Packard Enterprise Development Company LP
#
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from neutron.services.trunk.drivers.linuxbridge import driver as lxb_driver
from neutron.services.trunk.drivers.openvswitch import driver as ovs_driver


def register():
    """Load in-tree drivers for the service plugin."""
    # Enable the trunk plugin to work with ML2/OVS. Support for other
    # drivers can be added similarly by executing the registration
    # code at the time of plugin/mech driver initialization. There should
    # be at least one compatible driver enabled in the deployment for trunk
    # setup to be successful. The plugin fails to initialize if no compatible
    # driver is found in the deployment.
    lxb_driver.register()
    ovs_driver.register()
