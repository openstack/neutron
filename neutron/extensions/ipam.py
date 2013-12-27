from abc import abstractmethod

from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import exceptions as qexception
from neutron.api import extensions
from neutron import manager
from oslo.config import cfg


# Ipam Exceptions
class IpamNotFound(qexception.NotFound):
    message = _("IPAM %(id)s could not be found")

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'ipams': {
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
        'mgmt': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': None},
        'nets_using': {'allow_post': False, 'allow_put': False,
                       'is_visible': True, 'default': ''}
    },
}

# TODO should this be tied to ipam extension?
EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'contrail:fq_name': {'allow_post': False,
                             'allow_put': False,
                             'is_visible': True},
        'contrail:instance_count': {'allow_post': False,
                                    'allow_put': False,
                                    'is_visible': True},
        'contrail:policys': {'allow_post': True,
                             'allow_put': True,
                             'default': '',
                             'is_visible': True},
        'contrail:subnet_ipam': {'allow_post': False,
                                 'allow_put': False,
                                 'default': '',
                                 'is_visible': True},
    },
    'subnets': {
        'contrail:instance_count': {'allow_post': False,
                                    'allow_put': False,
                                    'is_visible': True},
        'contrail:ipam_fq_name': {'allow_post': True,
                                  'allow_put': True,
                                  'default': '',
                                  'is_visible': True},
    }
}


class Ipam(object):

    @classmethod
    def get_name(cls):
        return "Network IP Address Management"

    @classmethod
    def get_alias(cls):
        return "ipam"

    @classmethod
    def get_description(cls):
        return ("Configuration object for holding common to a set of"
                " IP address blocks")

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
        for resource_name in ['ipam']:
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

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
#end class Ipam


class IpamPluginBase(object):

    @abstractmethod
    def create_ipam(self, context, ipam):
        pass

    @abstractmethod
    def update_ipam(self, context, id, ipam):
        pass

    @abstractmethod
    def get_ipam(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_ipam(self, context, id):
        pass

    @abstractmethod
    def get_ipams(self, context, filters=None, fields=None):
        pass
#end class IpamPluginBase
