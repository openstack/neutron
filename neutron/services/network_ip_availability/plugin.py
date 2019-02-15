# Copyright 2016 GoDaddy.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
#  implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from neutron_lib.api.definitions import network_ip_availability
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions

import neutron.db.db_base_plugin_v2 as db_base_plugin_v2
import neutron.db.network_ip_availability_db as ip_availability_db


class NetworkIPAvailabilityPlugin(ip_availability_db.IpAvailabilityMixin,
                                  db_base_plugin_v2.NeutronDbPluginV2):
    """This plugin exposes IP availability data for networks and subnets."""
    _instance = None

    supported_extension_aliases = [network_ip_availability.ALIAS]

    __filter_validation_support = True

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def get_plugin_description(self):
        return "Provides IP availability data for each network and subnet."

    @classmethod
    def get_plugin_type(cls):
        return "network-ip-availability"

    def get_network_ip_availabilities(self, context, filters=None,
                                      fields=None):
        """Returns ip availability data for a collection of networks."""
        net_ip_availabilities = super(
            NetworkIPAvailabilityPlugin, self
        ).get_network_ip_availabilities(context, filters)
        return [db_utils.resource_fields(net_ip_availability, fields)
                for net_ip_availability in net_ip_availabilities]

    def get_network_ip_availability(self, context, id=None, fields=None):
        """Return ip availability data for a specific network id."""
        filters = {'network_id': [id]}
        result = self.get_network_ip_availabilities(context, filters)
        if result:
            return db_utils.resource_fields(result[0], fields)
        else:
            raise exceptions.NetworkNotFound(net_id=id)
