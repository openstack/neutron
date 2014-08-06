# Copyright 2013 Cloudbase Solutions SRL
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

from neutron.openstack.common import log as logging
from neutron.plugins.hyperv.agent import utils
from neutron.plugins.hyperv.agent import utilsv2

# Check needed for unit testing on Unix
if sys.platform == 'win32':
    import wmi

hyper_opts = [
    cfg.BoolOpt('force_hyperv_utils_v1',
                default=False,
                help=_('Force V1 WMI utility classes')),
]

CONF = cfg.CONF
CONF.register_opts(hyper_opts, 'hyperv')

LOG = logging.getLogger(__name__)


def _get_windows_version():
    return wmi.WMI(moniker='//./root/cimv2').Win32_OperatingSystem()[0].Version


def _check_min_windows_version(major, minor, build=0):
    version_str = _get_windows_version()
    return map(int, version_str.split('.')) >= [major, minor, build]


def get_hypervutils():
    # V1 virtualization namespace features are supported up to
    # Windows Server / Hyper-V Server 2012
    # V2 virtualization namespace features are supported starting with
    # Windows Server / Hyper-V Server 2012
    # Windows Server / Hyper-V Server 2012 R2 uses the V2 namespace and
    # introduces additional features

    force_v1_flag = CONF.hyperv.force_hyperv_utils_v1
    if _check_min_windows_version(6, 3):
        if force_v1_flag:
            LOG.warning(_('V1 virtualization namespace no longer supported on '
                          'Windows Server / Hyper-V Server 2012 R2 or above.'))
        cls = utilsv2.HyperVUtilsV2R2
    elif not force_v1_flag and _check_min_windows_version(6, 2):
        cls = utilsv2.HyperVUtilsV2
    else:
        cls = utils.HyperVUtils
    LOG.debug(_("Loading class: %(module_name)s.%(class_name)s"),
              {'module_name': cls.__module__, 'class_name': cls.__name__})
    return cls()
