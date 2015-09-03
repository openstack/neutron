# Copyright 2015 Cloudbase Solutions.
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

import os

from oslo_log import log as logging
from oslo_utils import importutils

from neutron.i18n import _LE


if os.name == 'nt':
    from neutron.agent.windows import utils
else:
    from neutron.agent.linux import utils


LOG = logging.getLogger(__name__)


execute = utils.execute


def load_interface_driver(conf):
    if not conf.interface_driver:
        LOG.error(_LE('An interface driver must be specified'))
        raise SystemExit(1)
    try:
        return importutils.import_object(conf.interface_driver, conf)
    except ImportError as e:
        LOG.error(_LE("Error importing interface driver "
                      "'%(driver)s': %(inner)s"),
                  {'driver': conf.interface_driver,
                   'inner': e})
        raise SystemExit(1)
