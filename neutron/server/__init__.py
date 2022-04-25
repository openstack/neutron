# Copyright 2011 VMware, Inc.
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

# If ../neutron/__init__.py exists, add ../ to Python search path, so that
# it will override what happens to be installed in /usr/(local/)lib/python...

import os
import sys

from oslo_config import cfg

from neutron._i18n import _
from neutron.common import config

# NOTE(annp): These environment variables are required for deploying
# neutron-api under mod_wsgi. Currently, these variables are set as DevStack's
# default. If you intend to use other tools for deploying neutron-api under
# mod_wsgi, you should export these variables with your values.

NEUTRON_CONF = 'neutron.conf'
NEUTRON_CONF_DIR = '/etc/neutron/'
NEUTRON_PLUGIN_CONF = 'plugins/ml2/ml2_conf.ini'


def _get_config_files(env=None):
    if env is None:
        env = os.environ
    dirname = env.get('OS_NEUTRON_CONFIG_DIR', NEUTRON_CONF_DIR).strip()

    files = [s.strip() for s in
             env.get('OS_NEUTRON_CONFIG_FILES', '').split(';') if s.strip()]

    if not files:
        files = [NEUTRON_CONF, NEUTRON_PLUGIN_CONF]

    return [os.path.join(dirname, fname) for fname in files]


def _init_configuration():
    # the configuration will be read into the cfg.CONF global data structure
    conf_files = _get_config_files()

    config.init(sys.argv[1:], default_config_files=conf_files)
    config.setup_logging()
    config.set_config_defaults()
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))


def boot_server(server_func):
    _init_configuration()
    try:
        return server_func()
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        sys.exit(_("ERROR: %s") % e)
