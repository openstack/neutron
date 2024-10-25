# Copyright (c) 2014 OpenStack Foundation.  All rights reserved.
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

import abc

from neutron_lib.api.definitions import dvr as apidef
from neutron_lib.api import extensions


class Dvr(extensions.APIExtensionDescriptor):
    """Extension class supporting distributed virtual router."""

    api_definition = apidef


class DVRMacAddressPluginBase(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_dvr_mac_address_list(self, context):
        pass

    @abc.abstractmethod
    def get_dvr_mac_address_by_host(self, context, host):
        pass
