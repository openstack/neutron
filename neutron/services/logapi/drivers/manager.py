# Copyright (c) 2017 Fujitsu Limited
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

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from oslo_log import log as logging

from neutron.services.logapi.common import constants as log_const

LOG = logging.getLogger(__name__)


class LoggingServiceDriverManager(object):

    def __init__(self):
        self._drivers = set()
        registry.notify(log_const.LOGGING_PLUGIN, events.AFTER_INIT, self)

    @property
    def drivers(self):
        return self._drivers

    def register_driver(self, driver):
        """Register driver with logging plugin.

        This method is called from drivers on INIT event.
        """
        self._drivers.add(driver)

    @property
    def supported_logging_types(self):
        if not self._drivers:
            return set()

        log_types = set()

        for driver in self._drivers:
            log_types |= set(driver.supported_logging_types)
        LOG.debug("Supported logging types (logging types supported "
                  "by at least one loaded log_driver): %s", log_types)
        return log_types
