# Copyright 2014 Mellanox Technologies, Ltd
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

from neutron.common import exceptions as n_exc


class SriovNicError(n_exc.NeutronException):
    pass


class InvalidDeviceError(SriovNicError):
    message = _("Invalid Device %(dev_name)s: %(reason)s")


class IpCommandError(SriovNicError):
    message = _("ip command failed on device %(dev_name)s: %(reason)s")


class InvalidPciSlotError(SriovNicError):
    message = _("Invalid pci slot %(pci_slot)s")
