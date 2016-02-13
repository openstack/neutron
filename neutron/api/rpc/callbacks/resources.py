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

from neutron.objects.qos import policy


_QOS_POLICY_CLS = policy.QosPolicy

_VALID_CLS = (
    _QOS_POLICY_CLS,
)

_VALID_TYPES = [cls.obj_name() for cls in _VALID_CLS]


# Supported types
QOS_POLICY = _QOS_POLICY_CLS.obj_name()


_TYPE_TO_CLS_MAP = {
    QOS_POLICY: _QOS_POLICY_CLS,
}

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


def is_valid_resource_type(resource_type):
    return resource_type in _VALID_TYPES


def get_resource_cls(resource_type):
    return _TYPE_TO_CLS_MAP.get(resource_type)
