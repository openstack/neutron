# Copyright 2013 Mellanox Technologies, Ltd
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

from neutron.common import exceptions as qexc


class MlnxException(qexc.NeutronException):
    message = _("Mlnx Exception: %(err_msg)s")


class RequestTimeout(qexc.NeutronException):
    message = _("Request Timeout: no response from eSwitchD")


class OperationFailed(qexc.NeutronException):
    message = _("Operation Failed: %(err_msg)s")
