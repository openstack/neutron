# Copyright 2013 OpenStack Foundation.
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

import importlib
import itertools
import os

from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_log import versionutils
import stevedore

from neutron._i18n import _
from neutron.conf.services import provider_configuration as prov_config
from neutron.db import _utils as db_utils

LOG = logging.getLogger(__name__)

SERVICE_PROVIDERS = 'neutron.service_providers'

# TODO(HenryG): use MovedGlobals to deprecate this.
serviceprovider_opts = prov_config.serviceprovider_opts

prov_config.register_service_provider_opts()


class NeutronModule(object):
    """A Neutron extension module."""

    def __init__(self, service_module):
        self.module_name = service_module
        self.repo = {
            'mod': self._import_or_none(),
            'ini': None
        }

    def _import_or_none(self):
        try:
            return importlib.import_module(self.module_name)
        except ImportError:
            return None

    def installed(self):
        LOG.debug("NeutronModule installed = %s", self.module_name)
        return self.module_name

    def module(self):
        return self.repo['mod']

    # Return an INI parser for the child module
    def ini(self, neutron_dir=None):
        if self.repo['ini'] is None:
            ini_file = cfg.ConfigOpts()
            prov_config.register_service_provider_opts(ini_file)

            if neutron_dir is not None:
                neutron_dirs = [neutron_dir]
            else:
                try:
                    neutron_dirs = cfg.CONF.config_dirs
                except cfg.NoSuchOptError:
                    neutron_dirs = None
                if not neutron_dirs:
                    neutron_dirs = ['/etc/neutron']

            # load configuration from all matching files to reflect oslo.config
            # behaviour
            config_files = []
            for neutron_dir in neutron_dirs:
                ini_path = os.path.join(neutron_dir,
                                        '%s.conf' % self.module_name)
                if os.path.exists(ini_path):
                    config_files.append(ini_path)

            # NOTE(ihrachys): we could pass project=self.module_name instead to
            # rely on oslo.config to find configuration files for us, but:
            # 1. that would render neutron_dir argument ineffective;
            # 2. that would break loading configuration file from under
            # /etc/neutron in case no --config-dir is passed.
            # That's why we need to explicitly construct CLI here.
            ini_file(args=list(itertools.chain.from_iterable(
                ['--config-file', file_] for file_ in config_files
            )))
            self.repo['ini'] = ini_file

        return self.repo['ini']

    def service_providers(self):
        """Return the service providers for the extension module."""
        providers = []
        # Attempt to read the config from cfg.CONF first; when passing
        # --config-dir, the option is merged from all the definitions
        # made across all the imported config files
        try:
            providers = cfg.CONF.service_providers.service_provider
        except cfg.NoSuchOptError:
            pass

        # Alternatively, if the option is not available, try to load
        # it from the provider module's config file; this may be
        # necessary, if modules are loaded on the fly (DevStack may
        # be an example)
        if not providers:
            providers = self.ini().service_providers.service_provider

            if providers:
                versionutils.report_deprecated_feature(
                    LOG,
                    'Implicit loading of service providers from '
                    'neutron_*.conf files is deprecated and will be '
                    'removed in Ocata release.')

        return providers


# global scope function that should be used in service APIs
def normalize_provider_name(name):
    return name.lower()


def get_provider_driver_class(driver, namespace=SERVICE_PROVIDERS):
    """Return path to provider driver class

    In order to keep backward compatibility with configs < Kilo, we need to
    translate driver class paths after advanced services split. This is done by
    defining old class path as entry point in neutron package.
    """
    try:
        driver_manager = stevedore.driver.DriverManager(
            namespace, driver).driver
    except ImportError:
        return driver
    except RuntimeError:
        return driver
    new_driver = "%s.%s" % (driver_manager.__module__,
                            driver_manager.__name__)
    LOG.warning(
        "The configured driver %(driver)s has been moved, automatically "
        "using %(new_driver)s instead. Please update your config files, "
        "as this automatic fixup will be removed in a future release.",
        {'driver': driver, 'new_driver': new_driver})
    return new_driver


def parse_service_provider_opt(service_module='neutron'):

    """Parse service definition opts and returns result."""
    def validate_name(name):
        if len(name) > db_const.NAME_FIELD_SIZE:
            raise n_exc.Invalid(
                _("Provider name %(name)s is limited by %(len)s characters")
                % {'name': name, 'len': db_const.NAME_FIELD_SIZE})

    neutron_mod = NeutronModule(service_module)
    svc_providers_opt = neutron_mod.service_providers()

    LOG.debug("Service providers = %s", svc_providers_opt)

    res = []
    for prov_def in svc_providers_opt:
        split = prov_def.split(':')
        try:
            svc_type, name, driver = split[:3]
        except ValueError:
            raise n_exc.Invalid(_("Invalid service provider format"))
        validate_name(name)
        name = normalize_provider_name(name)
        default = False
        if len(split) == 4 and split[3]:
            if split[3] == 'default':
                default = True
            else:
                msg = (_("Invalid provider format. "
                         "Last part should be 'default' or empty: %s") %
                       prov_def)
                LOG.error(msg)
                raise n_exc.Invalid(msg)

        driver = get_provider_driver_class(driver)
        res.append({'service_type': svc_type,
                    'name': name,
                    'driver': driver,
                    'default': default})
    return res


class ServiceProviderNotFound(n_exc.InvalidInput):
    message = _("Service provider '%(provider)s' could not be found "
                "for service type %(service_type)s")


class DefaultServiceProviderNotFound(n_exc.InvalidInput):
    message = _("Service type %(service_type)s does not have a default "
                "service provider")


class ServiceProviderAlreadyAssociated(n_exc.Conflict):
    message = _("Resource '%(resource_id)s' is already associated with "
                "provider '%(provider)s' for service type '%(service_type)s'")


class ProviderConfiguration(object):

    def __init__(self, svc_module='neutron'):
        self.providers = {}
        for prov in parse_service_provider_opt(svc_module):
            self.add_provider(prov)

    def _ensure_driver_unique(self, driver):
        for v in self.providers.values():
            if v['driver'] == driver:
                msg = (_("Driver %s is not unique across providers") %
                       driver)
                LOG.error(msg)
                raise n_exc.Invalid(msg)

    def _ensure_default_unique(self, type, default):
        if not default:
            return
        for k, v in self.providers.items():
            if k[0] == type and v['default']:
                msg = _("Multiple default providers "
                        "for service %s") % type
                LOG.error(msg)
                raise n_exc.Invalid(msg)

    def add_provider(self, provider):
        self._ensure_driver_unique(provider['driver'])
        self._ensure_default_unique(provider['service_type'],
                                    provider['default'])
        provider_type = (provider['service_type'], provider['name'])
        if provider_type in self.providers:
            msg = (_("Multiple providers specified for service "
                     "%s") % provider['service_type'])
            LOG.error(msg)
            raise n_exc.Invalid(msg)
        self.providers[provider_type] = {'driver': provider['driver'],
                                         'default': provider['default']}

    def _check_entry(self, k, v, filters):
        # small helper to deal with query filters
        if not filters:
            return True
        for index, key in enumerate(['service_type', 'name']):
            if key in filters:
                if k[index] not in filters[key]:
                    return False

        for key in ['driver', 'default']:
            if key in filters:
                if v[key] not in filters[key]:
                    return False
        return True

    def get_service_providers(self, filters=None, fields=None):
        return [db_utils.resource_fields({'service_type': k[0],
                                          'name': k[1],
                                          'driver': v['driver'],
                                          'default': v['default']},
                                         fields)
                for k, v in self.providers.items()
                if self._check_entry(k, v, filters)]
