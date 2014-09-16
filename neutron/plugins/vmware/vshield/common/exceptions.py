# Copyright 2013 VMware, Inc
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

from neutron.common import exceptions


class VcnsException(exceptions.NeutronException):
    pass


class VcnsGeneralException(VcnsException):
    def __init__(self, message):
        self.message = message
        super(VcnsGeneralException, self).__init__()


class VcnsBadRequest(exceptions.BadRequest):
    pass


class VcnsNotFound(exceptions.NotFound):
    message = _('%(resource)s not found: %(msg)s')


class VcnsApiException(VcnsException):
    message = _("An unknown exception %(status)s occurred: %(response)s.")

    def __init__(self, **kwargs):
        super(VcnsApiException, self).__init__(**kwargs)

        self.status = kwargs.get('status')
        self.header = kwargs.get('header')
        self.response = kwargs.get('response')


class ResourceRedirect(VcnsApiException):
    message = _("Resource %(uri)s has been redirected")


class RequestBad(VcnsApiException):
    message = _("Request %(uri)s is Bad, response %(response)s")


class Forbidden(VcnsApiException):
    message = _("Forbidden: %(uri)s")


class ResourceNotFound(VcnsApiException):
    message = _("Resource %(uri)s not found")


class MediaTypeUnsupport(VcnsApiException):
    message = _("Media Type %(uri)s is not supported")


class ServiceUnavailable(VcnsApiException):
    message = _("Service Unavailable: %(uri)s")
