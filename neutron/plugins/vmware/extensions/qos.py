# Copyright 2013 VMware, Inc.
# All Rights Reserved
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
#

import abc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as nexception
from neutron import manager


# For policy.json/Auth
qos_queue_create = "create_qos_queue"
qos_queue_delete = "delete_qos_queue"
qos_queue_get = "get_qos_queue"
qos_queue_list = "get_qos_queues"


class DefaultQueueCreateNotAdmin(nexception.InUse):
    message = _("Need to be admin in order to create queue called default")


class DefaultQueueAlreadyExists(nexception.InUse):
    message = _("Default queue already exists.")


class QueueInvalidDscp(nexception.InvalidInput):
    message = _("Invalid value for dscp %(data)s must be integer value"
                " between 0 and 63.")


class QueueInvalidMarking(nexception.InvalidInput):
    message = _("The qos marking cannot be set to 'trusted' "
                "when the DSCP field is set")


class QueueMinGreaterMax(nexception.InvalidInput):
    message = _("Invalid bandwidth rate, min greater than max.")


class QueueInvalidBandwidth(nexception.InvalidInput):
    message = _("Invalid bandwidth rate, %(data)s must be a non negative"
                " integer.")


class QueueNotFound(nexception.NotFound):
    message = _("Queue %(id)s does not exist")


class QueueInUseByPort(nexception.InUse):
    message = _("Unable to delete queue attached to port.")


class QueuePortBindingNotFound(nexception.NotFound):
    message = _("Port is not associated with lqueue")


def convert_to_unsigned_int_or_none(val):
    if val is None:
        return
    try:
        val = int(val)
        if val < 0:
            raise ValueError()
    except (ValueError, TypeError):
        msg = _("'%s' must be a non negative integer.") % val
        raise nexception.InvalidInput(error_message=msg)
    return val


def convert_to_unsigned_int_or_none_max_63(val):
    val = convert_to_unsigned_int_or_none(val)
    if val > 63:
        raise QueueInvalidDscp(data=val)
    return val

# As per NSX API, if a queue is trusted, DSCP must be omitted; if a queue is
# untrusted, DSCP must be specified. Whichever default values we choose for
# the tuple (qos_marking, dscp), there will be at least one combination of a
# request with conflicting values: for instance given the default values below,
# requests with qos_marking = 'trusted' and the default dscp value will fail.
# In order to avoid API users to explicitly specify a setting for clearing
# the DSCP field when a trusted queue is created, the code serving this API
# will adopt the following behaviour when qos_marking is set to 'trusted':
# - if the DSCP attribute is set to the default value (0), silently drop
#   its value
# - if the DSCP attribute is set to anything than 0 (but still a valid DSCP
#   value) return a 400 error as qos_marking and DSCP setting conflict.
# TODO(salv-orlando): Evaluate whether it will be possible from a backward
# compatibility perspective to change the default value for DSCP in order to
# avoid this peculiar behaviour

RESOURCE_ATTRIBUTE_MAP = {
    'qos_queues': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'default': {'allow_post': True, 'allow_put': False,
                    'convert_to': attr.convert_to_boolean,
                    'is_visible': True, 'default': False},
        'name': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:string': attr.NAME_MAX_LEN},
                 'is_visible': True, 'default': ''},
        'min': {'allow_post': True, 'allow_put': False,
                'is_visible': True, 'default': '0',
                'convert_to': convert_to_unsigned_int_or_none},
        'max': {'allow_post': True, 'allow_put': False,
                'is_visible': True, 'default': None,
                'convert_to': convert_to_unsigned_int_or_none},
        'qos_marking': {'allow_post': True, 'allow_put': False,
                        'validate': {'type:values': ['untrusted', 'trusted']},
                        'default': 'untrusted', 'is_visible': True},
        'dscp': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '0',
                 'convert_to': convert_to_unsigned_int_or_none_max_63},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {'type:string': attr.TENANT_ID_MAX_LEN},
                      'is_visible': True},
    },
}


QUEUE = 'queue_id'
RXTX_FACTOR = 'rxtx_factor'
EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        RXTX_FACTOR: {'allow_post': True,
                      # FIXME(arosen): the plugin currently does not
                      # implement updating rxtx factor on port.
                      'allow_put': True,
                      'is_visible': False,
                      'default': 1,
                      'enforce_policy': True,
                      'convert_to': attr.convert_to_positive_float_or_none},

        QUEUE: {'allow_post': False,
                'allow_put': False,
                'is_visible': True,
                'default': False,
                'enforce_policy': True}},
    'networks': {QUEUE: {'allow_post': True,
                         'allow_put': True,
                         'is_visible': True,
                         'default': False,
                         'enforce_policy': True}}

}


class Qos(extensions.ExtensionDescriptor):
    """Port Queue extension."""

    @classmethod
    def get_name(cls):
        return "QoS Queue"

    @classmethod
    def get_alias(cls):
        return "qos-queue"

    @classmethod
    def get_description(cls):
        return "NSX QoS extension."

    @classmethod
    def get_updated(cls):
        return "2014-01-01T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        resource_name = 'qos_queue'
        collection_name = resource_name.replace('_', '-') + "s"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
        controller = base.create_resource(collection_name,
                                          resource_name,
                                          plugin, params, allow_bulk=False)

        ex = extensions.ResourceExtension(collection_name,
                                          controller)
        exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return dict(EXTENDED_ATTRIBUTES_2_0.items() +
                        RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}


class QueuePluginBase(object):
    @abc.abstractmethod
    def create_qos_queue(self, context, queue):
        pass

    @abc.abstractmethod
    def delete_qos_queue(self, context, id):
        pass

    @abc.abstractmethod
    def get_qos_queue(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def get_qos_queues(self, context, filters=None, fields=None, sorts=None,
                       limit=None, marker=None, page_reverse=False):
        pass
