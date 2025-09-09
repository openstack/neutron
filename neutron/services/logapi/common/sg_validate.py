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

from neutron_lib.db import api as db_api
from neutron_lib.services.logapi import constants as log_const
from oslo_log import log as logging
from sqlalchemy.orm import exc as orm_exc

from neutron.db import _utils as db_utils
from neutron.db.models import securitygroup as sg_db
from neutron.objects import ports
from neutron.objects import securitygroup as sg_object
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.common import validators

LOG = logging.getLogger(__name__)


def _check_port_bound_sg(context, sg_id, port_id):
    try:
        with db_api.CONTEXT_READER.using(context):
            db_utils.model_query(context, sg_db.SecurityGroupPortBinding)\
                .filter_by(security_group_id=sg_id, port_id=port_id).one()
    except orm_exc.NoResultFound:
        raise log_exc.InvalidResourceConstraint(
            resource=log_const.SECURITY_GROUP,
            resource_id=sg_id,
            target_resource=log_const.PORT,
            target_id=port_id
        )


def _check_sg_exists(context, sg_id):
    if sg_object.SecurityGroup.count(context, id=sg_id) < 1:
        raise log_exc.ResourceNotFound(resource_id=sg_id)


def _get_port(context, port_id):
    port = ports.Port.get_object(context, id=port_id)
    if not port:
        raise log_exc.TargetResourceNotFound(target_id=port_id)
    return port


@validators.ResourceValidateRequest.register(log_const.SECURITY_GROUP)
def validate_security_group_request(context, log_data):
    """Validate a log request

    This method validates log request is satisfied or not.

    A ResourceNotFound will be raised if resource_id in log_data not exists or
    a TargetResourceNotFound will be raised if target_id in log_data not
    exists. This method will also raise a LoggingTypeNotSupported, if there is
    no log_driver supporting for resource_type in log_data.

    In addition, if log_data specify both resource_id and target_id. A
    InvalidResourceConstraint will be raised if there is no constraint between
    resource_id and target_id.

    """

    resource_id = log_data.get('resource_id')
    target_id = log_data.get('target_id')
    if resource_id:
        _check_sg_exists(context, resource_id)
    if target_id:
        port = _get_port(context, target_id)
        if not validators.validate_log_type_for_port(
                log_const.SECURITY_GROUP, port):
            raise log_exc.LoggingTypeNotSupported(
                log_type=log_const.SECURITY_GROUP,
                port_id=target_id)
    if resource_id and target_id:
        _check_port_bound_sg(context, resource_id, target_id)
