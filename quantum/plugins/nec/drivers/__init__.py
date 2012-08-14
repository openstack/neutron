# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import logging

from quantum.openstack.common import importutils


LOG = logging.getLogger(__name__)
DRIVER_PATH = "quantum.plugins.nec.drivers.%s"
DRIVER_LIST = {
    'trema': DRIVER_PATH % "trema.TremaPortBaseDriver",
    'trema_port': DRIVER_PATH % "trema.TremaPortBaseDriver",
    'trema_portmac': DRIVER_PATH % "trema.TremaPortMACBaseDriver",
    'trema_mac': DRIVER_PATH % "trema.TremaMACBaseDriver",
    'pfc': DRIVER_PATH % "pfc.PFCDriver"}


def get_driver(driver_name):
    LOG.info("Loading OFC driver: %s" % driver_name)
    driver_klass = DRIVER_LIST.get(driver_name) or driver_name
    return importutils.import_class(driver_klass)
