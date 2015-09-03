# Copyright 2012 OpenStack Foundation.
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

import abc

from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import importutils
import six

from neutron.api import extensions
from neutron.db import servicetype_db as sdb
from neutron.i18n import _LE, _LI
from neutron.services import provider_configuration as pconf

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class ServicePluginBase(extensions.PluginInterface):
    """Define base interface for any Advanced Service plugin."""
    supported_extension_aliases = []

    @abc.abstractmethod
    def get_plugin_type(self):
        """Return one of predefined service types.

        See neutron/plugins/common/constants.py
        """
        pass

    @abc.abstractmethod
    def get_plugin_description(self):
        """Return string description of the plugin."""
        pass


def load_drivers(service_type, plugin):
    """Loads drivers for specific service.

    Passes plugin instance to driver's constructor
    """
    service_type_manager = sdb.ServiceTypeManager.get_instance()
    providers = (service_type_manager.
                 get_service_providers(
                     None,
                     filters={'service_type': [service_type]})
                 )
    if not providers:
        msg = (_("No providers specified for '%s' service, exiting") %
               service_type)
        LOG.error(msg)
        raise SystemExit(1)

    drivers = {}
    for provider in providers:
        try:
            drivers[provider['name']] = importutils.import_object(
                provider['driver'], plugin
            )
            LOG.debug("Loaded '%(provider)s' provider for service "
                      "%(service_type)s",
                      {'provider': provider['driver'],
                       'service_type': service_type})
        except ImportError:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("Error loading provider '%(provider)s' for "
                                  "service %(service_type)s"),
                              {'provider': provider['driver'],
                               'service_type': service_type})

    default_provider = None
    try:
        provider = service_type_manager.get_default_service_provider(
            None, service_type)
        default_provider = provider['name']
    except pconf.DefaultServiceProviderNotFound:
        LOG.info(_LI("Default provider is not specified for service type %s"),
                 service_type)

    return drivers, default_provider
