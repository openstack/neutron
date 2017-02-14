# All Rights Reserved.
#
# Based on openvswitch mechanism driver.
#
# Copyright (c) 2013 OpenStack Foundation
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

from neutron.plugins.ml2.drivers import mech_agent


class FaultyAgentMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """ML2 mechanism driver for testing of handlers for faulty drivers

    The purpose of this class is to test the ml2 plugin manager handlers for
    on_load_failure_callback parameter provided by the
    stevedore.named.NamedExtensionManager class.
    """

    def __init__(self):
        raise Exception("Using a faulty driver for testing purposes.")

    def get_allowed_network_types(self, agent):
        pass

    def get_mappings(self, agent):
        pass
