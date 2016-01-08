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

from neutron._i18n import _
from neutron.common import exceptions


class CallbackWrongResourceType(exceptions.NeutronException):
    message = _('Callback for %(resource_type)s returned wrong resource type')


class CallbackNotFound(exceptions.NeutronException):
    message = _('Callback for %(resource_type)s not found')


class CallbacksMaxLimitReached(exceptions.NeutronException):
    message = _("Cannot add multiple callbacks for %(resource_type)s")


class VersionsCallbackNotFound(exceptions.NeutronException):
    message = _("No versions callback provided in ResourceVersionsManager")
