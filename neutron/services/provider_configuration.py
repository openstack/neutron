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
import os

from oslo_config import cfg
from oslo_log import log as logging
from six.moves import configparser as ConfigParser
import stevedore

from neutron.common import exceptions as n_exc
from neutron.i18n import _LW

LOG = logging.getLogger(__name__)

SERVICE_PROVIDERS = 'neutron.service_providers'

serviceprovider_opts = [
    cfg.MultiStrOpt('service_provider', default=[],
                    help=_('Defines providers for advanced services '
                           'using the format: '
                           '<service_type>:<name>:<driver>[:default]'))
]

cfg.CONF.register_opts(serviceprovider_opts, 'service_providers')


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

    # Return an INI parser for the child module. oslo.config is a bit too
    # magical in its INI loading, and in one notable case, we need to merge
    # together the [service_providers] section across at least four
    # repositories.
    def ini(self):
        if self.repo['ini'] is None:
            neutron_dir = None
            try:
                neutron_dir = cfg.CONF.config_dir
            except cfg.NoSuchOptError:
                pass

            if neutron_dir is None:
                neutron_dir = '/etc/neutron'

            ini = ConfigParser.SafeConfigParser()
            ini_path = os.path.join(neutron_dir, '%s.conf' % self.module_name)
            if os.path.exists(ini_path):
                ini.read(ini_path)

            self.repo['ini'] = ini

        return self.repo['ini']

    def service_providers(self):
        ini = self.ini()

        sp = []
        try:
            for name, value in ini.items('service_providers'):
                if name == 'service_provider':
                    sp.append(value)
        except ConfigParser.NoSectionError:
            pass

        return sp


#global scope function that should be used in service APIs
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
    LOG.warning(_LW(
        "The configured driver %(driver)s has been moved, automatically "
        "using %(new_driver)s instead. Please update your config files, "
        "as this automatic fixup will be removed in a future release."),
        {'driver': driver, 'new_driver': new_driver})
    return new_driver


def parse_service_provider_opt(service_module='neutron'):

    """Parse service definition opts and returns result."""
    def validate_name(name):
        if len(name) > 255:
            raise n_exc.Invalid(
                _("Provider name is limited by 255 characters: %s") % name)

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
        for k, v in self.providers.items():
            if v['driver'] == driver:
                msg = (_("Driver %s is not unique across providers") %
                       driver)
                LOG.exception(msg)
                raise n_exc.Invalid(msg)

    def _ensure_default_unique(self, type, default):
        if not default:
            return
        for k, v in self.providers.items():
            if k[0] == type and v['default']:
                msg = _("Multiple default providers "
                        "for service %s") % type
                LOG.exception(msg)
                raise n_exc.Invalid(msg)

    def add_provider(self, provider):
        self._ensure_driver_unique(provider['driver'])
        self._ensure_default_unique(provider['service_type'],
                                    provider['default'])
        provider_type = (provider['service_type'], provider['name'])
        if provider_type in self.providers:
            msg = (_("Multiple providers specified for service "
                     "%s") % provider['service_type'])
            LOG.exception(msg)
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

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource

    def get_service_providers(self, filters=None, fields=None):
        return [self._fields({'service_type': k[0],
                              'name': k[1],
                              'driver': v['driver'],
                              'default': v['default']},
                             fields)
                for k, v in self.providers.items()
                if self._check_entry(k, v, filters)]
