# Copyright (c) 2015 Mirantis, Inc.
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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron import policy


def initialize_all():
    ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
    ext_mgr.extend_resources("2.0", attributes.RESOURCE_ATTRIBUTE_MAP)
    for ext in ext_mgr.extensions.values():
        # make each extension populate its plurals
        if hasattr(ext, 'get_resources'):
            ext.get_resources()
        if hasattr(ext, 'get_extended_resources'):
            ext.get_extended_resources('v2.0')
    # Certain policy checks require that the extensions are loaded
    # and the RESOURCE_ATTRIBUTE_MAP populated before they can be
    # properly initialized. This can only be claimed with certainty
    # once this point in the code has been reached. In the event
    # that the policies have been initialized before this point,
    # calling reset will cause the next policy check to
    # re-initialize with all of the required data in place.
    policy.reset()
