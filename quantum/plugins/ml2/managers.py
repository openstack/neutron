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

import sys

from oslo.config import cfg
import stevedore

from quantum.common import exceptions as exc
from quantum.openstack.common import log
from quantum.plugins.ml2 import driver_api as api


LOG = log.getLogger(__name__)


class TypeManager(stevedore.named.NamedExtensionManager):
    """Manage network segment types using drivers."""

    # Mapping from type name to DriverManager
    drivers = {}

    def __init__(self):
        # REVISIT(rkukura): Need way to make stevedore use our logging
        # configuration. Currently, nothing is logged if loading a
        # driver fails.

        LOG.info(_("Configured type driver names: %s"),
                 cfg.CONF.ml2.type_drivers)
        super(TypeManager, self).__init__('quantum.ml2.type_drivers',
                                          cfg.CONF.ml2.type_drivers,
                                          invoke_on_load=True)
        LOG.info(_("Loaded type driver names: %s"), self.names())
        self._register_types()
        self._check_tenant_network_types(cfg.CONF.ml2.tenant_network_types)

    def _register_types(self):
        for ext in self:
            type = ext.obj.get_type()
            if type in self.drivers:
                LOG.error(_("Type driver '%(new_driver)s' ignored because type"
                            " driver '%(old_driver)s' is already registered"
                            " for type '%(type)s'"),
                          {'new_driver': ext.name,
                           'old_driver': self.drivers[type].name,
                           'type': type})
            else:
                self.drivers[type] = ext
        LOG.info(_("Registered types: %s"), self.drivers.keys())

    def _check_tenant_network_types(self, types):
        self.tenant_network_types = []
        for network_type in types:
            if network_type in self.drivers:
                self.tenant_network_types.append(network_type)
            else:
                LOG.error(_("No type driver for tenant network_type: %s. "
                            "Service terminated!"),
                          network_type)
                sys.exit(1)
        LOG.info(_("Tenant network_types: %s"), self.tenant_network_types)

    def initialize(self):
        for type, driver in self.drivers.iteritems():
            LOG.info(_("Initializing driver for type '%s'"), type)
            driver.obj.initialize()

    def validate_provider_segment(self, segment):
        network_type = segment[api.NETWORK_TYPE]
        driver = self.drivers.get(network_type)
        if driver:
            return driver.obj.validate_provider_segment(segment)
        else:
            msg = _("network_type value '%s' not supported") % network_type
            raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        driver.obj.reserve_provider_segment(session, segment)

    def allocate_tenant_segment(self, session):
        for network_type in self.tenant_network_types:
            driver = self.drivers.get(network_type)
            segment = driver.obj.allocate_tenant_segment(session)
            if segment:
                return segment
        raise exc.NoNetworkAvailable()

    def release_segment(self, session, segment):
        network_type = segment.get(api.NETWORK_TYPE)
        driver = self.drivers.get(network_type)
        driver.obj.release_segment(session, segment)


class MechanismManager(stevedore.named.NamedExtensionManager):
    """Manage networking mechanisms using drivers.

    Note that this is currently a stub class, but it is expected to be
    functional for the H-2 milestone. It currently serves mainly to
    help solidify the architectural distinction between TypeDrivers
    and MechanismDrivers.
    """

    def __init__(self):
        # REVISIT(rkukura): Need way to make stevedore use our logging
        # configuration. Currently, nothing is logged if loading a
        # driver fails.

        LOG.info(_("Configured mechanism driver names: %s"),
                 cfg.CONF.ml2.mechanism_drivers)
        super(MechanismManager, self).__init__('quantum.ml2.mechanism_drivers',
                                               cfg.CONF.ml2.mechanism_drivers,
                                               invoke_on_load=True)
        LOG.info(_("Loaded mechanism driver names: %s"), self.names())
        # TODO(rkukura): Register mechanisms.

    def initialize(self):
        pass

    # TODO(rkukura): Define mechanism dispatch methods
