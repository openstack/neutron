# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Cisco Systems, Inc.  All rights reserved.
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
#
# @author: Sumit Naiksatam, Cisco Systems, Inc.


import logging
import os

from quantum.common.utils import find_config_file
from quantum.openstack.common import importutils
from quantum.plugins.cisco.common import cisco_configparser as confp
from quantum.plugins.cisco.common import cisco_constants as const
from quantum.plugins.cisco.common import cisco_credentials_v2 as cred
from quantum.plugins.cisco.ucs import (
    cisco_ucs_inventory_configuration as conf,
)
from quantum.plugins.cisco.ucs import cisco_ucs_inventory_v2


LOG = logging.getLogger(__name__)


def curdir(*p):
    return os.path.join(os.path.dirname(__file__), *p)


class UCSInventory(cisco_ucs_inventory_v2.UCSInventory):
    """
    Inventory implementation for testing
    """

    def __init__(self):
        fake_ucs_driver = "quantum.plugins.cisco.tests.unit.v2.ucs." + \
                          "fake_ucs_driver.CiscoUCSMFakeDriver"
        self._client = importutils.import_object(fake_ucs_driver)
        conf_parser = confp.CiscoConfigParser(curdir("fake_ucs_inventory.ini"))

        conf.INVENTORY = conf_parser.walk(conf_parser.dummy)
        for ucsm in conf.INVENTORY.keys():
            ucsm_ip = conf.INVENTORY[ucsm][const.IP_ADDRESS]
            try:
                cred.Store.put_credential(ucsm_ip, "username", "password")
            except:
                pass
        self._load_inventory()
