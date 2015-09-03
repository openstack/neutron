# Copyright 2014 Juniper Networks.  All rights reserved.
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

from neutron.common import exceptions as exc


class ContrailError(exc.NeutronException):
    message = '%(msg)s'


class ContrailNotFoundError(exc.NotFound):
    message = '%(msg)s'


class ContrailConflictError(exc.Conflict):
    message = '%(msg)s'


class ContrailBadRequestError(exc.BadRequest):
    message = '%(msg)s'


class ContrailServiceUnavailableError(exc.ServiceUnavailable):
    message = '%(msg)s'


class ContrailNotAuthorizedError(exc.NotAuthorized):
    message = '%(msg)s'
