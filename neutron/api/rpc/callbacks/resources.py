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
from neutron.objects.logapi import logging_resource as log_object
from neutron.objects import network
from neutron.objects import ports
from neutron.objects.qos import policy
from neutron.objects import securitygroup
from neutron.objects import subnet
from neutron.objects import trunk


# Supported types
LOGGING_RESOURCE = log_object.Log.obj_name()
TRUNK = trunk.Trunk.obj_name()
QOS_POLICY = policy.QosPolicy.obj_name()
SUBPORT = trunk.SubPort.obj_name()
PORT = ports.Port.obj_name()
NETWORK = network.Network.obj_name()
SUBNET = subnet.Subnet.obj_name()
SECURITYGROUP = securitygroup.SecurityGroup.obj_name()
SECURITYGROUPRULE = securitygroup.SecurityGroupRule.obj_name()


_VALID_CLS = (
    policy.QosPolicy,
    trunk.Trunk,
    trunk.SubPort,
    ports.Port,
    subnet.Subnet,
    network.Network,
    securitygroup.SecurityGroup,
    securitygroup.SecurityGroupRule,
    log_object.Log,
)

_TYPE_TO_CLS_MAP = {cls.obj_name(): cls for cls in _VALID_CLS}

LOCAL_RESOURCE_VERSIONS = {
    resource_type: cls.VERSION
    for resource_type, cls in _TYPE_TO_CLS_MAP.items()
}


def get_resource_type(resource_cls):
    if not resource_cls:
        return None

    if not hasattr(resource_cls, 'obj_name'):
        return None

    return resource_cls.obj_name()


def register_resource_class(resource_cls):
    resource_type = get_resource_type(resource_cls)
    if not resource_type:
        msg = _("cannot find resource type for %s class") % resource_cls
        raise ValueError(msg)
    if resource_type not in _TYPE_TO_CLS_MAP:
        _TYPE_TO_CLS_MAP[resource_type] = resource_cls
    if resource_type not in LOCAL_RESOURCE_VERSIONS:
        LOCAL_RESOURCE_VERSIONS[resource_type] = resource_cls.VERSION


def is_valid_resource_type(resource_type):
    return resource_type in _TYPE_TO_CLS_MAP


def get_resource_cls(resource_type):
    return _TYPE_TO_CLS_MAP.get(resource_type)
