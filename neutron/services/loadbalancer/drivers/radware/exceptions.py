# Copyright 2013 Radware LTD.
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


class RadwareLBaasException(exceptions.NeutronException):
    message = _('An unknown exception occurred in Radware LBaaS provider.')


class AuthenticationMissing(RadwareLBaasException):
    message = _('vDirect user/password missing. '
                'Specify in configuration file, under [radware] section')


class WorkflowMissing(RadwareLBaasException):
    message = _('Workflow %(workflow)s is missing on vDirect server. '
                'Upload missing workflow')


class RESTRequestFailure(RadwareLBaasException):
    message = _('REST request failed with status %(status)s. '
                'Reason: %(reason)s, Description: %(description)s. '
                'Success status codes are %(success_codes)s')


class UnsupportedEntityOperation(RadwareLBaasException):
    message = _('%(operation)s operation is not supported for %(entity)s.')
