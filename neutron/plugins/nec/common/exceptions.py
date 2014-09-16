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

from neutron.common import exceptions as qexc


class OFCException(qexc.NeutronException):
    message = _("An OFC exception has occurred: %(reason)s")

    def __init__(self, **kwargs):
        super(OFCException, self).__init__(**kwargs)
        self.status = kwargs.get('status')
        self.err_msg = kwargs.get('err_msg')
        self.err_code = kwargs.get('err_code')


class OFCResourceNotFound(qexc.NotFound):
    message = _("The specified OFC resource (%(resource)s) is not found.")


class NECDBException(qexc.NeutronException):
    message = _("An exception occurred in NECPluginV2 DB: %(reason)s")


class OFCMappingNotFound(qexc.NotFound):
    message = _("Neutron-OFC resource mapping for "
                "%(resource)s %(neutron_id)s is not found. "
                "It may be deleted during processing.")


class OFCServiceUnavailable(OFCException):
    message = _("OFC returns Server Unavailable (503) "
                "(Retry-After=%(retry_after)s)")

    def __init__(self, **kwargs):
        super(OFCServiceUnavailable, self).__init__(**kwargs)
        self.retry_after = kwargs.get('retry_after')


class PortInfoNotFound(qexc.NotFound):
    message = _("PortInfo %(id)s could not be found")


class ProfilePortInfoInvalidDataPathId(qexc.InvalidInput):
    message = _('Invalid input for operation: '
                'datapath_id should be a hex string '
                'with at most 8 bytes')


class ProfilePortInfoInvalidPortNo(qexc.InvalidInput):
    message = _('Invalid input for operation: '
                'port_no should be [0:65535]')


class RouterExternalGatewayNotSupported(qexc.BadRequest):
    message = _("Router (provider=%(provider)s) does not support "
                "an external network")


class ProviderNotFound(qexc.NotFound):
    message = _("Provider %(provider)s could not be found")


class RouterOverLimit(qexc.Conflict):
    message = _("Cannot create more routers with provider=%(provider)s")


class RouterProviderMismatch(qexc.Conflict):
    message = _("Provider of Router %(router_id)s is %(provider)s. "
                "This operation is supported only for router provider "
                "%(expected_provider)s.")
