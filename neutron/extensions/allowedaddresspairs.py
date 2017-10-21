# Copyright 2013 VMware, Inc.  All rights reserved.
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

from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api import extensions

from neutron.conf.extensions import allowedaddresspairs as addr_pair


addr_pair.register_allowed_address_pair_opts()


class Allowedaddresspairs(extensions.APIExtensionDescriptor):
    """Extension class supporting allowed address pairs."""
    api_definition = addr_apidef
