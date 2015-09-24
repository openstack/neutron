# Copyright 2016 Cloudbase Solutions.
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

import netifaces

from oslo_log import log as logging

from neutron._i18n import _LE

LOG = logging.getLogger(__name__)

OPTS = []


class IPWrapper(object):

    def get_device_by_ip(self, ip):
        if not ip:
            return

        for device in self.get_devices():
            if device.device_has_ip(ip):
                return device

    def get_devices(self):
        try:
            return [IPDevice(iface) for iface in netifaces.interfaces()]
        except (OSError, MemoryError):
            LOG.error(_LE("Failed to get network interfaces."))
            return []


class IPDevice(object):

    def __init__(self, name):
        self.device_name = name

    def device_has_ip(self, ip):
        try:
            addresses = [ip_addr['addr'] for ip_addr in
                netifaces.ifaddresses(self.device_name).get(
                    netifaces.AF_INET, [])]
            return ip in addresses
        except OSError:
            LOG.error(_LE("Failed to get ip addresses for interface: %s."),
                self.device_name)
            return False
