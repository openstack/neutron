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

from neutron_lib import exceptions as lib_exc
from neutron_lib.plugins import constants as plugin_constants
from oslo_log import log

from neutron.db import servicetype_db as st_db
from neutron.services.l3_router.service_providers import driver_controller
from neutron.services import provider_configuration


LOG = log.getLogger(__name__)


class DriverController(driver_controller.DriverController):
    """Driver controller for the OVN L3 service plugin.

    This component is responsible for dispatching router requests to L3
    service providers and for performing the bookkeeping about which
    driver is associated with a given router.

    This is not intended to be accessed by the drivers or the l3 plugin.
    All of the methods are marked as private to reflect this.
    """

    def __init__(self, l3_plugin):
        self.l3_plugin = l3_plugin
        self._stm = st_db.ServiceTypeManager.get_instance()
        self._stm.add_provider_configuration(
            plugin_constants.L3, _OvnPlusProviderConfiguration())
        self._load_drivers()

    def _get_provider_for_create(self, context, router):
        """Get provider based on flavor or default provider."""
        if not driver_controller.flavor_specified(router):
            return self.drivers[self.default_provider]
        return self._get_l3_driver_by_flavor(context, router['flavor_id'])


class _OvnPlusProviderConfiguration(
        provider_configuration.ProviderConfiguration):

    def __init__(self):
        # loads up the OVN provider automatically and sets it as default.
        super().__init__(
            svc_type=plugin_constants.L3)
        path = 'neutron.services.ovn_l3.service_providers.ovn.OvnDriver'
        try:
            self.add_provider({'service_type': plugin_constants.L3,
                               'name': 'ovn', 'driver': path, 'default': True})
        except lib_exc.Invalid:
            LOG.debug("Could not add L3 provider ovn, it may have "
                      "already been explicitly defined.")
