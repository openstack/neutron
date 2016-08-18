# Copyright 2016 Hewlett Packard Enterprise Development LP
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

from neutron_lib import constants

from neutron.plugins.ml2.drivers.agent import capabilities
from neutron.services.trunk.drivers.openvswitch.agent import driver


def register():
    """Register OVS capabilities."""
    # Add capabilities to be loaded during agent initialization
    capabilities.register(driver.init_handler, constants.AGENT_TYPE_OVS)
