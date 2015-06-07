# Copyright (c) 2012 OpenStack Foundation.
# All rights reserved.
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

from neutron.api import extensions
from neutron.api.v2 import attributes

# The type of vnic that this port should be attached to
VNIC_TYPE = 'binding:vnic_type'
# The service will return the vif type for the specific port.
VIF_TYPE = 'binding:vif_type'
# The service may return a dictionary containing additional
# information needed by the interface driver. The set of items
# returned may depend on the value of VIF_TYPE.
VIF_DETAILS = 'binding:vif_details'
# In some cases different implementations may be run on different hosts.
# The host on which the port will be allocated.
HOST_ID = 'binding:host_id'
# The profile will be a dictionary that enables the application running
# on the specific host to pass and receive vif port specific information to
# the plugin.
PROFILE = 'binding:profile'

# The keys below are used in the VIF_DETAILS attribute to convey
# information to the VIF driver.

# TODO(rkukura): Replace CAP_PORT_FILTER, which nova no longer
# understands, with the new set of VIF security details to be used in
# the VIF_DETAILS attribute.
#
#  - port_filter : Boolean value indicating Neutron provides port filtering
#                  features such as security group and anti MAC/IP spoofing
#  - ovs_hybrid_plug: Boolean used to inform Nova that the hybrid plugging
#                     strategy for OVS should be used
CAP_PORT_FILTER = 'port_filter'
OVS_HYBRID_PLUG = 'ovs_hybrid_plug'
VIF_DETAILS_VLAN = 'vlan'

VIF_TYPE_UNBOUND = 'unbound'
VIF_TYPE_BINDING_FAILED = 'binding_failed'
VIF_TYPE_DISTRIBUTED = 'distributed'
VIF_TYPE_IOVISOR = 'iovisor'
VIF_TYPE_OVS = 'ovs'
VIF_TYPE_IVS = 'ivs'
VIF_TYPE_DVS = 'dvs'
VIF_TYPE_BRIDGE = 'bridge'
VIF_TYPE_802_QBG = '802.1qbg'
VIF_TYPE_802_QBH = '802.1qbh'
VIF_TYPE_HYPERV = 'hyperv'
VIF_TYPE_MIDONET = 'midonet'
VIF_TYPE_IB_HOSTDEV = 'ib_hostdev'
VIF_TYPE_HW_VEB = 'hw_veb'
VIF_TYPE_VROUTER = 'vrouter'
VIF_TYPE_OTHER = 'other'
VIF_TYPES = [VIF_TYPE_UNBOUND, VIF_TYPE_BINDING_FAILED, VIF_TYPE_OVS,
             VIF_TYPE_IVS, VIF_TYPE_BRIDGE, VIF_TYPE_802_QBG,
             VIF_TYPE_802_QBH, VIF_TYPE_HYPERV, VIF_TYPE_MIDONET,
             VIF_TYPE_IB_HOSTDEV, VIF_TYPE_HW_VEB,
             VIF_TYPE_DVS, VIF_TYPE_OTHER, VIF_TYPE_DISTRIBUTED,
             VIF_TYPE_VROUTER]

VNIC_NORMAL = 'normal'
VNIC_DIRECT = 'direct'
VNIC_MACVTAP = 'macvtap'
VNIC_TYPES = [VNIC_NORMAL, VNIC_DIRECT, VNIC_MACVTAP]

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        VIF_TYPE: {'allow_post': False, 'allow_put': False,
                   'default': attributes.ATTR_NOT_SPECIFIED,
                   'enforce_policy': True,
                   'is_visible': True},
        VIF_DETAILS: {'allow_post': False, 'allow_put': False,
                      'default': attributes.ATTR_NOT_SPECIFIED,
                      'enforce_policy': True,
                      'is_visible': True},
        VNIC_TYPE: {'allow_post': True, 'allow_put': True,
                    'default': VNIC_NORMAL,
                    'is_visible': True,
                    'validate': {'type:values': VNIC_TYPES},
                    'enforce_policy': True},
        HOST_ID: {'allow_post': True, 'allow_put': True,
                  'default': attributes.ATTR_NOT_SPECIFIED,
                  'is_visible': True,
                  'enforce_policy': True},
        PROFILE: {'allow_post': True, 'allow_put': True,
                  'default': attributes.ATTR_NOT_SPECIFIED,
                  'enforce_policy': True,
                  'validate': {'type:dict_or_none': None},
                  'is_visible': True},
    }
}


class Portbindings(extensions.ExtensionDescriptor):
    """Extension class supporting port bindings.

    This class is used by neutron's extension framework to make
    metadata about the port bindings available to external applications.

    With admin rights one will be able to update and read the values.
    """

    @classmethod
    def get_name(cls):
        return "Port Binding"

    @classmethod
    def get_alias(cls):
        return "binding"

    @classmethod
    def get_description(cls):
        return "Expose port bindings of a virtual port to external application"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/binding/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2014-02-03T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
