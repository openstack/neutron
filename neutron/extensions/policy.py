from abc import abstractmethod

from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as qexception
from neutron.api import extensions
from neutron import manager
from oslo.config import cfg


# Policy Exceptions
class PolicyNotFound(qexception.NotFound):
    message = _("Policy %(id)s could not be found")

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'policys': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': attr.UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': ''},
        'fq_name': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'entries': {'allow_post': True, 'allow_put': True,
                    'is_visible': True, 'default': ''},
        'nets_using': {'allow_post': False, 'allow_put': False,
                       'is_visible': True, 'default': ''},
    },
}


class Policy(object):

    @classmethod
    def get_name(cls):
        return "Network Policy"

    @classmethod
    def get_alias(cls):
        return "policy"

    @classmethod
    def get_description(cls):
        return ("Configuration object for Network Policies")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/TODO"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['policy']:
            collection_name = resource_name + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())

            member_actions = {}

            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params,
                                              member_actions=member_actions)

            ex = extensions.ResourceExtension(collection_name,
                                              controller,
                                              member_actions=member_actions)
            exts.append(ex)

        return exts

#end class Policy


class PolicyPluginBase(object):

    @abstractmethod
    def create_policy(self, context, policy):
        pass

    @abstractmethod
    def update_policy(self, context, id, policy):
        pass

    @abstractmethod
    def get_policy(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_policy(self, context, id):
        pass

    @abstractmethod
    def get_policys(self, context, filters=None, fields=None):
        pass
#end class PolicyPluginBase
