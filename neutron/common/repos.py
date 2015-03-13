# Copyright (c) 2015, A10 Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ConfigParser
import importlib
import os

from oslo_config import cfg
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NeutronModules(object):

    MODULES = {
        'neutron_fwaas': {
            'alembic-name': 'fwaas',
        },
        'neutron_lbaas': {
            'alembic-name': 'lbaas',
        },
        'neutron_vpnaas': {
            'alembic-name': 'vpnaas',
        },
    }

    def __init__(self):
        self.repos = {}
        for repo in self.MODULES:
            self.repos[repo] = {}
            self.repos[repo]['mod'] = self._import_or_none(repo)
            self.repos[repo]['ini'] = None

    def _import_or_none(self, module):
            try:
                return importlib.import_module(module)
            except ImportError:
                return None

    def installed_list(self):
        z = filter(lambda k: self.repos[k]['mod'] is not None, self.repos)
        LOG.debug("NeutronModules related repos installed = %s", z)
        return z

    def module(self, module):
        return self.repos[module]['mod']

    def alembic_name(self, module):
        return self.MODULES[module]['alembic-name']

    # Return an INI parser for the child module. oslo.config is a bit too
    # magical in its INI loading, and in one notable case, we need to merge
    # together the [service_providers] section across at least four
    # repositories.
    def ini(self, module):
        if self.repos[module]['ini'] is None:
            neutron_dir = None
            try:
                neutron_dir = cfg.CONF.config_dir
            except cfg.NoSuchOptError:
                pass

            if neutron_dir is None:
                neutron_dir = '/etc/neutron'

            ini = ConfigParser.SafeConfigParser()
            ini_path = os.path.join(neutron_dir, '%s.conf' % module)
            if os.path.exists(ini_path):
                ini.read(ini_path)

            self.repos[module]['ini'] = ini

        return self.repos[module]['ini']

    def service_providers(self, module):
        ini = self.ini(module)

        sp = []
        try:
            for name, value in ini.items('service_providers'):
                if name == 'service_provider':
                    sp.append(value)
        except ConfigParser.NoSectionError:
            pass

        return sp
