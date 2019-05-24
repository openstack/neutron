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

from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.services.logapi import constants
from oslo_log import log as logging
from sqlalchemy.orm import exc as orm_exc

from neutron.db.models import securitygroup as sg_db
from neutron.objects.logapi import logging_resource as log_object
from neutron.objects import ports as port_objects
from neutron.objects import securitygroup as sg_object
from neutron.services.logapi.common import validators

LOG = logging.getLogger(__name__)


def _get_ports_attached_to_sg(context, sg_id):
    """Return a list of ports attached to a security group"""

    with db_api.CONTEXT_READER.using(context):
        ports = context.session.query(
            sg_db.SecurityGroupPortBinding.port_id).filter(
            sg_db.SecurityGroupPortBinding.security_group_id ==
            sg_id).all()
    return [port for (port,) in ports]


def _get_ports_filter_in_tenant(context, tenant_id):
    """Return a list of ports filter under a tenant"""

    try:
        sg_id = sg_db.SecurityGroupPortBinding.security_group_id
        with db_api.CONTEXT_READER.using(context):
            ports = context.session.query(
                sg_db.SecurityGroupPortBinding.port_id).join(
                sg_db.SecurityGroup, sg_db.SecurityGroup.id == sg_id).filter(
                sg_db.SecurityGroup.tenant_id == tenant_id).all()
            return list({port for (port,) in ports})
    except orm_exc.NoResultFound:
        return []


def _get_sgs_attached_to_port(context, port_id):
    """Return a list of security groups are associated to a port"""

    with db_api.CONTEXT_READER.using(context):
        sg_ids = context.session.query(
            sg_db.SecurityGroupPortBinding.security_group_id).filter(
            sg_db.SecurityGroupPortBinding.port_id == port_id).all()
    return [sg_id for (sg_id, ) in sg_ids]


def _get_ports_being_logged(context, sg_log):
    """Return a list of ports being logged for a log_resource"""

    target_id = sg_log['target_id']
    resource_id = sg_log['resource_id']

    # if 'target_id' (port_id) is specified in a log_resource
    if target_id is not None:
        port_ids = [target_id]
    # if 'resource_id' (sg_id) is specified in a log_resource
    elif resource_id is not None:
        port_ids = _get_ports_attached_to_sg(context, resource_id)
    # both 'resource_id' and 'target_id' aren't specified in a log_resource
    else:
        port_ids = _get_ports_filter_in_tenant(context, sg_log['project_id'])

    # list of validated ports's being logged
    validated_port_ids = []
    ports = port_objects.Port.get_objects(context, id=port_ids)
    for port in ports:
        if port.status != const.PORT_STATUS_ACTIVE:
            continue
        if validators.validate_log_type_for_port('security_group', port):
            validated_port_ids.append(port.id)
        else:
            msg = ("Logging type %(log_type)s is not supported on "
                   "port %(port_id)s." %
                   {'log_type': 'security_group', 'port_id': port.id})
            LOG.warning(msg)

    return validated_port_ids


def _get_sg_ids_log_for_port(context, sg_log, port_id):
    """Return a list of security group ids being logged for a port"""

    sg_ids = _get_sgs_attached_to_port(context, port_id)
    resource_id = sg_log['resource_id']

    # if resource_id is not specified
    if not resource_id:
        return sg_ids

    # if resource_id is specified and belong a set of sgs are
    # associated to port
    if resource_id in sg_ids:
        return [resource_id]

    return []


def _create_sg_rule_dict(rule_in_db):
    """Return a dict of a security group rule"""
    direction = rule_in_db['direction']
    rule_dict = {
        'direction': direction,
        'ethertype': rule_in_db['ethertype']}

    rule_dict.update({
        key: rule_in_db[key]
        for key in ('protocol', 'port_range_min', 'port_range_max',
                    'remote_group_id') if rule_in_db[key] is not None})

    remote_ip_prefix = rule_in_db['remote_ip_prefix']
    if remote_ip_prefix is not None:
        direction_ip_prefix = constants.DIRECTION_IP_PREFIX[direction]
        rule_dict[direction_ip_prefix] = remote_ip_prefix

    rule_dict['security_group_id'] = rule_in_db['security_group_id']

    return rule_dict


def _get_sg_rules(context, sg_log, port_id):
    """Return a list of sg_rules log for a port being logged"""

    sg_ids = _get_sg_ids_log_for_port(context, sg_log, port_id)
    if not sg_ids:
        return []
    filters = {'security_group_id': sg_ids}
    rules_in_db = sg_object.SecurityGroupRule.get_objects(context, **filters)
    return [_create_sg_rule_dict(rule_in_db) for rule_in_db in rules_in_db]


def _get_port_log_dict(context, port_id, sg_log):
    return {
        'port_id': port_id,
        'security_group_rules': _get_sg_rules(context, sg_log, port_id)
    }


def _make_log_dict(context, sg_log, port_ids_log):
    return {
        'id': sg_log['id'],
        'ports_log': [_get_port_log_dict(context, port_id, sg_log)
                      for port_id in port_ids_log],
        'event': sg_log['event'],
        'project_id': sg_log['project_id']
    }


def get_logs_bound_port(context, port_id):
    """Return a list of log_resources bound to a port"""

    port = port_objects.Port.get_object(context, id=port_id)
    project_id = port['project_id']
    logs = log_object.Log.get_objects(context,
                                      project_id=project_id,
                                      resource_type=constants.SECURITY_GROUP,
                                      enabled=True)
    is_bound = lambda log: (log.resource_id in port.security_group_ids or
                            log.target_id == port.id or
                            (not log.target_id and not log.resource_id))
    return [log for log in logs if is_bound(log)]


def get_logs_bound_sg(context, sg_id):
    """Return a list of log_resources bound to a security group"""

    project_id = context.tenant_id
    log_objs = log_object.Log.get_objects(
        context,
        project_id=project_id,
        resource_type=constants.SECURITY_GROUP,
        enabled=True)

    log_resources = []
    for log_obj in log_objs:
        if log_obj.resource_id == sg_id:
            log_resources.append(log_obj)
        elif log_obj.target_id:
            port = port_objects.Port.get_object(
                context, id=log_obj.target_id)
            if sg_id in port.security_group_ids:
                log_resources.append(log_obj)
        elif not log_obj.resource_id and not log_obj.target_id:
            log_resources.append(log_obj)
    return log_resources


def get_sg_log_info_for_port(context, port_id):
    """Return a list of security groups log info for a port

    This method provides a list of security groups log info for a port.
    The list has format as below:

        [
            {'id': xxx,
             'ports_log': [{'port_id': u'xxx',
                            'security_group_rules': [{
                                'direction': u'egress',
                                'ethertype': u'IPv6',
                                'security_group_id': u'xxx'},
                                {...}]
                            }]
             'event': u'ALL',
             'project_id': u'xxx'
             },
             ...
        ]
    :param context: current running context information
    :param port_id: port ID which needed to get security groups log info

    """

    sg_logs = get_logs_bound_port(context, port_id)
    return [_make_log_dict(context, sg_log, [port_id])
            for sg_log in sg_logs]


def get_sg_log_info_for_log_resources(context, log_resources):
    """Return a list of security groups log info for list of log_resources

    This method provides a list of security groups log info for list of
    log_resources. The list has format as below:

        [
            {'id': xxx,
             'ports_log': [{'port_id': u'xxx',
                            'security_group_rules': [{
                                'direction': u'egress',
                                'ethertype': u'IPv6',
                                'security_group_id': u'xxx'},
                                {...}]
                            }, ...]
             'event': u'ALL',
             'project_id': u'xxx'
             },
             ...
        ]
    :param context: current running context information
    :param log_resources: list of log_resources, which needed to get
                          security groups log info

    """

    logs_info = []
    for sg_log in log_resources:
        port_ids = _get_ports_being_logged(context, sg_log)
        logs_info.append(_make_log_dict(context, sg_log, port_ids))
    return logs_info
