# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
# @author: Claudiu Belu, Cloudbase Solutions Srl

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


def _get_class(v1_class, v2_class, force_v1_flag):
    # V2 classes are supported starting from Hyper-V Server 2012 and
    # Windows Server 2012 (kernel version 6.2)
    if not force_v1_flag and _check_min_windows_version(6, 2):
        cls = v2_class
    else:
        cls = v1_class
    LOG.debug(_("Loading class: %(module_name)s.%(class_name)s"),
              {'module_name': cls.__module__, 'class_name': cls.__name__})
    return cls


def get_hypervutils():
    return _get_class(utils.HyperVUtils, utilsv2.HyperVUtilsV2,
                      CONF.hyperv.force_hyperv_utils_v1)()
