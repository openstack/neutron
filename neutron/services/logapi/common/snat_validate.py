# Copyright (c) 2018 Fujitsu Limited
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

from oslo_log import log as logging

from neutron.objects import router
from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators

LOG = logging.getLogger(__name__)

EVENTS_DISABLE = [log_const.DROP_EVENT, log_const.ACCEPT_EVENT]


def _get_router(context, router_id):
    router_obj = router.Router.get_object(context, id=router_id)
    if not router_obj:
        raise log_exc.ResourceNotFound(resource_id=router_id)
    return router_obj


@validators.ResourceValidateRequest.register(log_const.SNAT)
def validate_snat_request(context, log_data):
    """Validate the incoming SNAT log request

    This method validates whether SNAT log request is satisfied or not.

    A ResourceNotFound will be raised if resource_id in log_data does not
    belong to any Router object. This method will also raise a
    RouterNotEnabledSnat exception in the case of a indicated router does not
    enable SNAT feature.
    """

    resource_id = log_data.get('resource_id')
    event = log_data.get('event')
    if not resource_id:
        raise log_exc.ResourceIdNotSpecified(resource_type=log_const.SNAT)
    if event in EVENTS_DISABLE:
        raise log_exc.EventsDisabled(events=EVENTS_DISABLE,
                                     resource_type=log_const.SNAT)
    router_obj = _get_router(context, resource_id)
    # Check whether SNAT is enabled or not
    if not router_obj.enable_snat:
        raise log_exc.RouterNotEnabledSnat(resource_id=resource_id)
    # Check whether router gateway is set or not.
    if not router_obj.gw_port_id:
        raise log_exc.RouterGatewayNotSet(resource_id=resource_id)
