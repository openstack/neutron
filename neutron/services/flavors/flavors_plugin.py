# Copyright (c) 2015, Hewlett-Packard Development Company, L.P.
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

from neutron_lib.api.definitions import flavors
from neutron_lib.api.definitions import servicetype
from neutron_lib.plugins import constants
from neutron_lib.services import base as service_base

from neutron.db import flavors_db


class FlavorsPlugin(service_base.ServicePluginBase,
                    flavors_db.FlavorsDbMixin):
    """Implements Neutron Flavors Service plugin."""

    supported_extension_aliases = [flavors.ALIAS, servicetype.ALIAS]

    __filter_validation_support = True

    @classmethod
    def get_plugin_type(cls):
        return constants.FLAVORS

    def get_plugin_description(self):
        return "Neutron Flavors and Service Profiles manager plugin"
