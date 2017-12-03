# Copyright (c) 2017 Fujitsu Limited
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

from neutron_lib.api.definitions import portbindings
from neutron_lib.plugins import constants as plugin_const
from neutron_lib.plugins import directory
from oslo_log import log as logging
from sqlalchemy.orm import exc as orm_exc

from neutron.db import _utils as db_utils
from neutron.db.models import securitygroup as sg_db
from neutron.objects import ports
from neutron.objects import securitygroup as sg_object
from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import exceptions as log_exc

LOG = logging.getLogger(__name__)

SKIPPED_VIF_TYPES = [
    portbindings.VIF_TYPE_UNBOUND,
    portbindings.VIF_TYPE_BINDING_FAILED,
]


def _check_port_bound_sg(context, sg_id, port_id):
    try:
        db_utils.model_query(context, sg_db.SecurityGroupPortBinding)\
            .filter_by(security_group_id=sg_id, port_id=port_id).one()
    except orm_exc.NoResultFound:
        raise log_exc.InvalidResourceConstraint(resource='security_group',
                                                resource_id=sg_id,
                                                target_resource='port',
                                                target_id=port_id)


def _check_secgroup_exists(context, sg_id):
    number_of_matching = sg_object.SecurityGroup.count(context, id=sg_id)
    if number_of_matching < 1:
        raise log_exc.ResourceNotFound(resource_id=sg_id)


def _get_port(context, port_id):
    port = ports.Port.get_object(context, id=port_id)
    if not port:
        raise log_exc.TargetResourceNotFound(target_id=port_id)
    return port


def _validate_vnic_type(driver, vnic_type, port_id):
    if driver.is_vnic_compatible(vnic_type):
        return True
    LOG.debug("vnic_type %(vnic_type)s of port %(port_id)s "
              "is not compatible with logging driver %(driver)s",
              {'vnic_type': vnic_type,
               'port_id': port_id,
               'driver': driver.name})
    return False


def _validate_vif_type(driver, vif_type, port_id):
    if driver.is_vif_type_compatible(vif_type):
        return True
    LOG.debug("vif_type %(vif_type)s of port %(port_id)s "
              "is not compatible with logging driver %(driver)s",
              {'vif_type': vif_type,
               'port_id': port_id,
               'driver': driver.name})
    return False


def validate_log_type_for_port(log_type, port):
    """Validate a specific logging type on a specific port

    This method checks whether or not existing a log_driver which supports for
    the logging type on the port.

    :param log_type: a logging type (e.g security_group)
    :param port: a port object

    """

    log_plugin = directory.get_plugin(alias=plugin_const.LOG_API)
    drivers = log_plugin.driver_manager.drivers
    for driver in drivers:
        vif_type = port.binding.vif_type
        if vif_type not in SKIPPED_VIF_TYPES:
            if not _validate_vif_type(driver, vif_type, port['id']):
                continue
        else:
            vnic_type = port.binding.vnic_type
            if not _validate_vnic_type(driver, vnic_type, port['id']):
                continue

        if driver.is_logging_type_supported(log_type):
            return True
    return False


def validate_request(context, log_data):
    """Validate a log request

    This method validates log request is satisfied or not. A ResourceNotFound
    will be raised if resource_id in log_data not exists or a
    TargetResourceNotFound will be raised if target_id in log_data not exists.
    This method will also raise a LoggingTypeNotSupported, if there is no
    log_driver supporting for resource_type in log_data.

    In addition, if log_data specify both resource_id and target_id. A
    InvalidResourceConstraint will be raised if there is no constraint
    between resource_id and target_id.

    """
    resource_id = log_data.get('resource_id')
    target_id = log_data.get('target_id')
    resource_type = log_data.get('resource_type')
    if resource_type == log_const.SECURITY_GROUP:
        if resource_id:
            _check_secgroup_exists(context, resource_id)
        if target_id:
            port = _get_port(context, target_id)
            if not validate_log_type_for_port(resource_type, port):
                raise log_exc.LoggingTypeNotSupported(log_type=resource_type,
                                                      port_id=target_id)
        if resource_id and target_id:
            _check_port_bound_sg(context, resource_id, target_id)
