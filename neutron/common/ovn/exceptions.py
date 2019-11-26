# Copyright 2019 Red Hat, Inc.
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

from neutron_lib import exceptions as n_exc

from neutron._i18n import _


class RevisionConflict(n_exc.NeutronException):
    message = _('OVN revision number for %(resource_id)s (type: '
                '%(resource_type)s) is equal or higher than the given '
                'resource. Skipping update')


class UnknownResourceType(n_exc.NeutronException):
    message = _('Uknown resource type: %(resource_type)s')


class StandardAttributeIDNotFound(n_exc.NeutronException):
    message = _('Standard attribute ID not found for %(resource_uuid)s')


class HashRingIsEmpty(n_exc.NeutronException):
    message = _('Hash Ring returned empty when hashing "%(key)s". '
                'This should never happen in a normal situation, please '
                'check the status of your cluster')
