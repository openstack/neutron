# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cisco Systems, Inc.
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
# @author: Aruna Kushwaha, Cisco Systems, Inc.
# @author: Rudrajit Tapadar, Cisco Systems, Inc.
# @author: Abhishek Raut, Cisco Systems, Inc.
# @author: Sergey Sudakovich, Cisco Systems, Inc.

import eventlet

from oslo.config import cfg as q_conf

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import exceptions as q_exc
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import l3_db
from neutron.db import l3_rpc_base
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import providernet
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.common import cisco_credentials_v2 as c_cred
from neutron.plugins.cisco.common import cisco_exceptions
from neutron.plugins.cisco.common import config as c_conf
from neutron.plugins.cisco.db import n1kv_db_v2
from neutron.plugins.cisco.db import network_db_v2
from neutron.plugins.cisco.extensions import n1kv_profile
from neutron.plugins.cisco.n1kv import n1kv_client


LOG = logging.getLogger(__name__)


class N1kvRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                       l3_rpc_base.L3RpcCallbackMixin,
                       sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    """Class to handle agent RPC calls."""

    # Set RPC API version to 1.1 by default.
    RPC_API_VERSION = '1.1'

    def __init__(self, notifier):
        self.notifier = notifier

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this rpc manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin):

    """Agent side of the N1kv rpc API.

    API version history:
        1.0 - Initial version.
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)
        self.topic_vxlan_update = topics.get_topic_name(topic,
                                                        c_const.TUNNEL,
                                                        topics.UPDATE)

    def network_delete(self, context, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, network_type, segmentation_id,
                    physical_network):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       network_type=network_type,
                                       segmentation_id=segmentation_id,
                                       physical_network=physical_network),
                         topic=self.topic_port_update)

    def vxlan_update(self, context, vxlan_ip, vxlan_id):
        self.fanout_cast(context,
                         self.make_msg('vxlan_update',
                                       vxlan_ip=vxlan_ip,
                                       vxlan_id=vxlan_id),
                         topic=self.topic_vxlan_update)


class N1kvNeutronPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                          l3_db.L3_NAT_db_mixin,
                          n1kv_db_v2.NetworkProfile_db_mixin,
                          n1kv_db_v2.PolicyProfile_db_mixin,
                          network_db_v2.Credential_db_mixin,
                          agentschedulers_db.AgentSchedulerDbMixin):

    """
    Implement the Neutron abstractions using Cisco Nexus1000V.

    Refer README file for the architecture, new features, and
    workflow

    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations.
    __native_bulk_support = False
    supported_extension_aliases = ["provider", "agent",
                                   "policy_profile_binding",
                                   "network_profile_binding",
                                   "n1kv_profile", "network_profile",
                                   "policy_profile", "router", "credential"]

    def __init__(self, configfile=None):
        """
        Initialize Nexus1000V Neutron plugin.

        1. Initialize Nexus1000v and Credential DB
        2. Establish communication with Cisco Nexus1000V
        """
        n1kv_db_v2.initialize()
        c_cred.Store.initialize()
        self._initialize_network_vlan_ranges()
        # If no api_extensions_path is provided set the following
        if not q_conf.CONF.api_extensions_path:
            q_conf.CONF.set_override(
                'api_extensions_path',
                'extensions:neutron/plugins/cisco/extensions')
        self._setup_vsm()
        self._setup_rpc()

    def _setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.callbacks = N1kvRpcCallbacks(self.notifier)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify
        self.conn.consume_in_thread()

    def _setup_vsm(self):
        """
        Setup Cisco Nexus 1000V related parameters and pull policy profiles.

        Retreive all the policy profiles from the VSM when the plugin is
        is instantiated for the first time and then continue to poll for
        policy profile updates.
        """
        LOG.debug(_('_setup_vsm'))
        self.agent_vsm = True
        # Retrieve all the policy profiles from VSM.
        self._populate_policy_profiles()
        # Continue to poll VSM for any create/delete of policy profiles.
        eventlet.spawn(self._poll_policy_profiles)

    def _poll_policy_profiles(self):
        """Start a green thread to pull policy profiles from VSM."""
        while True:
            self._poll_policies(event_type='port_profile')
            eventlet.sleep(int(c_conf.CISCO_N1K.poll_duration))

    def _populate_policy_profiles(self):
        """
        Populate all the policy profiles from VSM.

        The tenant id is not available when the policy profiles are polled
        from the VSM. Hence we associate the policy profiles with fake
        tenant-ids.
        """
        LOG.debug(_('_populate_policy_profiles'))
        n1kvclient = n1kv_client.Client()
        policy_profiles = n1kvclient.list_port_profiles()
        LOG.debug(_('_populate_policy_profiles %s'), policy_profiles)
        if policy_profiles:
            for profile in policy_profiles['body'][c_const.SET]:
                if c_const.ID and c_const.NAME in profile:
                    profile_id = profile[c_const.PROPERTIES][c_const.ID]
                    profile_name = profile[c_const.PROPERTIES][c_const.NAME]
                    self._add_policy_profile(profile_name, profile_id)
        else:
            LOG.warning(_('No policy profile populated from VSM'))
        self._remove_all_fake_policy_profiles()

    def _poll_policies(self, event_type=None, epoch=None, tenant_id=None):
        """
        Poll for Policy Profiles from Cisco Nexus1000V for any update/delete.
        """
        LOG.debug(_('_poll_policies'))
        n1kvclient = n1kv_client.Client()
        policy_profiles = n1kvclient.list_events(event_type, epoch)
        if policy_profiles:
            for profile in policy_profiles['body'][c_const.SET]:
                if c_const.NAME in profile:
                    # Extract commands from the events XML.
                    cmd = profile[c_const.PROPERTIES]['cmd']
                    cmds = cmd.split(';')
                    cmdwords = cmds[1].split()
                    profile_name = profile[c_const.PROPERTIES][c_const.NAME]
                    # Delete the policy profile from db if it's deleted on VSM
                    if 'no' in cmdwords[0]:
                        p = self._get_policy_profile_by_name(profile_name)
                        if p:
                            self._delete_policy_profile(p['id'])
                    # Add policy profile to neutron DB idempotently
                    elif c_const.ID in profile[c_const.PROPERTIES]:
                        profile_id = profile[c_const.PROPERTIES][c_const.ID]
                        self._add_policy_profile(
                            profile_name, profile_id, tenant_id)
            # Replace tenant-id for profile bindings with admin's tenant-id
            self._remove_all_fake_policy_profiles()

    def _initialize_network_vlan_ranges(self):
        self.network_vlan_ranges = {}
        network_profiles = n1kv_db_v2._get_network_profiles()
        for network_profile in network_profiles:
            if network_profile['segment_type'] == c_const.NETWORK_TYPE_VLAN:
                seg_min, seg_max = self._get_segment_range(
                    network_profile['segment_range'])
                self._add_network_vlan_range(network_profile[
                    'physical_network'], int(seg_min), int(seg_max))

    def _add_network_vlan_range(self, physical_network, vlan_min, vlan_max):
        self._add_network(physical_network)
        self.network_vlan_ranges[physical_network].append((vlan_min, vlan_max))

    def _add_network(self, physical_network):
        if physical_network not in self.network_vlan_ranges:
            self.network_vlan_ranges[physical_network] = []

    def _extend_network_dict_provider(self, context, network):
        """Add extended network parameters."""
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[providernet.NETWORK_TYPE] = binding.network_type
        if binding.network_type == c_const.NETWORK_TYPE_VXLAN:
            network[providernet.PHYSICAL_NETWORK] = None
            network[providernet.SEGMENTATION_ID] = binding.segmentation_id
            network[n1kv_profile.MULTICAST_IP] = binding.multicast_ip
        elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
            network[providernet.PHYSICAL_NETWORK] = binding.physical_network
            network[providernet.SEGMENTATION_ID] = binding.segmentation_id

    def _process_provider_create(self, context, attrs):
        network_type = attrs.get(providernet.NETWORK_TYPE)
        physical_network = attrs.get(providernet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(providernet.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return (None, None, None)

        if not network_type_set:
            msg = _("provider:network_type required")
            raise q_exc.InvalidInput(error_message=msg)
        elif network_type == c_const.NETWORK_TYPE_VLAN:
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
            if segmentation_id < 1 or segmentation_id > 4094:
                msg = _("provider:segmentation_id out of range "
                        "(1 through 4094)")
                raise q_exc.InvalidInput(error_message=msg)
        elif network_type == c_const.NETWORK_TYPE_VXLAN:
            if physical_network_set:
                msg = _("provider:physical_network specified for VXLAN "
                        "network")
                raise q_exc.InvalidInput(error_message=msg)
            else:
                physical_network = None
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
            if segmentation_id < 5000:
                msg = _("provider:segmentation_id out of range "
                        "(5000+)")
                raise q_exc.InvalidInput(error_message=msg)
        else:
            msg = _("provider:network_type %s not supported"), network_type
            raise q_exc.InvalidInput(error_message=msg)

        if network_type == c_const.NETWORK_TYPE_VLAN:
            if physical_network_set:
                if physical_network not in self.network_vlan_ranges:
                    msg = (_("unknown provider:physical_network %s"),
                           physical_network)
                    raise q_exc.InvalidInput(error_message=msg)
            elif 'default' in self.network_vlan_ranges:
                physical_network = 'default'
            else:
                msg = _("provider:physical_network required")
                raise q_exc.InvalidInput(error_message=msg)

        return (network_type, physical_network, segmentation_id)

    def _check_provider_update(self, context, attrs):
        """Handle Provider network updates."""
        network_type = attrs.get(providernet.NETWORK_TYPE)
        physical_network = attrs.get(providernet.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(providernet.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return

        # TBD : Need to handle provider network updates
        msg = _("plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def _extend_network_dict_profile(self, context, network):
        """Add the extended parameter network profile to the network."""
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _extend_port_dict_profile(self, context, port):
        """Add the extended parameter port profile to the port."""
        binding = n1kv_db_v2.get_port_binding(context.session,
                                              port['id'])
        port[n1kv_profile.PROFILE_ID] = binding.profile_id

    def _process_network_profile(self, context, attrs):
        """Validate network profile exists."""
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            raise cisco_exceptions.NetworkProfileIdNotFound(
                profile_id=profile_id)
        if not self.network_profile_exists(context, profile_id):
            raise cisco_exceptions.NetworkProfileIdNotFound(
                profile_id=profile_id)
        return profile_id

    def _process_policy_profile(self, context, attrs):
        """Validates whether policy profile exists."""
        profile_id = attrs.get(n1kv_profile.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            msg = _("n1kv:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)
        if not self._policy_profile_exists(profile_id):
            msg = _("n1kv:profile_id does not exist")
            raise q_exc.InvalidInput(error_message=msg)

        return profile_id

    def _send_create_logical_network_request(self, network_profile):
        """
        Send create logical network request to VSM.

        :param network_profile: network profile dictionary
        """
        LOG.debug(_('_send_create_logical_network'))
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_logical_network(network_profile)

    def _send_delete_logical_network_request(self, network_profile):
        """
        Send delete logical network request to VSM.

        :param network_profile: network profile dictionary
        """
        LOG.debug('_send_delete_logical_network')
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_logical_network(network_profile)

    def _send_create_network_profile_request(self, context, profile):
        """
        Send create network profile request to VSM.

        :param context: neutron api request context
        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_create_network_profile_request: %s'), profile['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_network_segment_pool(profile)

    def _send_delete_network_profile_request(self, profile):
        """
        Send delete network profile request to VSM.

        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_delete_network_profile_request: %s'),
                  profile['name'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_network_segment_pool(profile['name'])

    def _send_create_network_request(self, context, network):
        """
        Send create network request to VSM.

        Create a bridge domain for network of type VXLAN.
        :param context: neutron api request context
        :param network: network dictionary
        """
        LOG.debug(_('_send_create_network_request: %s'), network['id'])
        profile = self.get_network_profile(context,
                                           network[n1kv_profile.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_VXLAN:
            n1kvclient.create_bridge_domain(network)
        n1kvclient.create_network_segment(network, profile)

    def _send_update_network_request(self, db_session, network):
        """
        Send update network request to VSM.

        :param network: network dictionary
        """
        LOG.debug(_('_send_update_network_request: %s'), network['id'])
        profile = n1kv_db_v2.get_network_profile(
            db_session, network[n1kv_profile.PROFILE_ID])
        body = {'name': network['name'],
                'id': network['id'],
                'networkDefinition': profile['name'],
                'vlan': network[providernet.SEGMENTATION_ID]}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment(network['name'], body)

    def _send_delete_network_request(self, network):
        """
        Send delete network request to VSM.

        Delete bridge domain if network is of type VXLAN.
        :param network: network dictionary
        """
        LOG.debug(_('_send_delete_network_request: %s'), network['id'])
        n1kvclient = n1kv_client.Client()
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_VXLAN:
            name = network['name'] + '_bd'
            n1kvclient.delete_bridge_domain(name)
        n1kvclient.delete_network_segment(network['name'])

    def _send_create_subnet_request(self, context, subnet):
        """
        Send create subnet request to VSM.

        :param context: neutron api request context
        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_create_subnet_request: %s'), subnet['id'])
        network = self.get_network(context, subnet['network_id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_ip_pool(subnet)
        body = {'ipPoolName': subnet['name']}
        n1kvclient.update_network_segment(network['name'], body=body)

    def _send_delete_subnet_request(self, context, subnet):
        """
        Send delete subnet request to VSM.

        :param context: neutron api request context
        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_delete_subnet_request: %s'), subnet['name'])
        network = self.get_network(context, subnet['network_id'])
        body = {'ipPoolName': subnet['name'], 'deleteSubnet': True}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment(network['name'], body=body)
        n1kvclient.delete_ip_pool(subnet['name'])

    def _send_create_port_request(self, context, port):
        """
        Send create port request to VSM.

        Create a VM network for a network and policy profile combination.
        If the VM network already exists, bind this port to the existing
        VM network and increment its port count.
        :param context: neutron api request context
        :param port: port dictionary
        """
        LOG.debug(_('_send_create_port_request: %s'), port)
        try:
            vm_network = n1kv_db_v2.get_vm_network(
                context.session,
                port[n1kv_profile.PROFILE_ID],
                port['network_id'])
        except cisco_exceptions.VMNetworkNotFound:
            policy_profile = n1kv_db_v2.get_policy_profile(
                context.session, port[n1kv_profile.PROFILE_ID])
            network = self.get_network(context, port['network_id'])
            vm_network_name = (c_const.VM_NETWORK_NAME_PREFIX +
                               str(port[n1kv_profile.PROFILE_ID]) +
                               "_" + str(port['network_id']))
            port_count = 1
            n1kv_db_v2.add_vm_network(context.session,
                                      vm_network_name,
                                      port[n1kv_profile.PROFILE_ID],
                                      port['network_id'],
                                      port_count)
            n1kvclient = n1kv_client.Client()
            n1kvclient.create_vm_network(port,
                                         vm_network_name,
                                         policy_profile,
                                         network['name'])
            n1kvclient.create_n1kv_port(port, vm_network_name)
        else:
            vm_network_name = vm_network['name']
            n1kvclient = n1kv_client.Client()
            n1kvclient.create_n1kv_port(port, vm_network_name)
            vm_network['port_count'] += 1
            n1kv_db_v2.update_vm_network_port_count(
                context.session, vm_network_name, vm_network['port_count'])

    def _send_update_port_request(self, port_id, mac_address, vm_network_name):
        """
        Send update port request to VSM.

        :param port_id: UUID representing port to update
        :param mac_address: string representing the mac address
        :param vm_network_name: VM network name to which the port is bound
        """
        LOG.debug(_('_send_update_port_request: %s'), port_id)
        body = {'portId': port_id,
                'macAddress': mac_address}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_n1kv_port(vm_network_name, port_id, body)

    def _send_delete_port_request(self, context, id):
        """
        Send delete port request to VSM.

        Decrement the port count of the VM network after deleting the port.
        If the port count reaches zero, delete the VM network.
        :param context: neutron api request context
        :param id: UUID of the port to be deleted
        """
        LOG.debug(_('_send_delete_port_request: %s'), id)
        port = self.get_port(context, id)
        vm_network = n1kv_db_v2.get_vm_network(context.session,
                                               port[n1kv_profile.PROFILE_ID],
                                               port['network_id'])
        vm_network['port_count'] -= 1
        n1kv_db_v2.update_vm_network_port_count(
            context.session, vm_network['name'], vm_network['port_count'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_n1kv_port(vm_network['name'], id)
        if vm_network['port_count'] == 0:
            n1kv_db_v2.delete_vm_network(context.session,
                                         port[n1kv_profile.PROFILE_ID],
                                         port['network_id'])
            n1kvclient.delete_vm_network(vm_network['name'])

    def _get_segmentation_id(self, context, id):
        """
        Retreive segmentation ID for a given network.

        :param context: neutron api request context
        :param id: UUID of the network
        :returns: segmentation ID for the network
        """
        session = context.session
        binding = n1kv_db_v2.get_network_binding(session, id)
        return binding.segmentation_id

    def create_network(self, context, network):
        """
        Create network based on network profile.

        :param context: neutron api request context
        :param network: network dictionary
        :returns: network object
        """
        (network_type, physical_network,
         segmentation_id) = self._process_provider_create(context,
                                                          network['network'])
        self._add_dummy_profile_only_if_testing(network)
        profile_id = self._process_network_profile(context, network['network'])
        LOG.debug(_('create network: profile_id=%s'), profile_id)
        session = context.session
        with session.begin(subtransactions=True):
            if not network_type:
                # tenant network
                (physical_network, network_type, segmentation_id,
                    multicast_ip) = n1kv_db_v2.alloc_network(session,
                                                             profile_id)
                LOG.debug(_('Physical_network %(phy_net)s, '
                            'seg_type %(net_type)s, '
                            'seg_id %(seg_id)s, '
                            'multicast_ip %(multicast_ip)s'),
                          {'phy_net': physical_network,
                           'net_type': network_type,
                           'seg_id': segmentation_id,
                           'multicast_ip': multicast_ip})
                if not segmentation_id:
                    raise q_exc.TenantNetworksDisabled()
            else:
                # provider network
                if network_type == c_const.NETWORK_TYPE_VLAN:
                    network_profile = self.get_network_profile(context,
                                                               profile_id)
                    seg_min, seg_max = self._get_segment_range(
                        network_profile['segment_range'])
                    if not seg_min <= segmentation_id <= seg_max:
                        raise cisco_exceptions.VlanIDOutsidePool
                    n1kv_db_v2.reserve_specific_vlan(session,
                                                     physical_network,
                                                     segmentation_id)
                    multicast_ip = "0.0.0.0"
            net = super(N1kvNeutronPluginV2, self).create_network(context,
                                                                  network)
            n1kv_db_v2.add_network_binding(session,
                                           net['id'],
                                           network_type,
                                           physical_network,
                                           segmentation_id,
                                           multicast_ip,
                                           profile_id)
            self._process_l3_create(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)

        try:
            self._send_create_network_request(context, net)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            super(N1kvNeutronPluginV2, self).delete_network(context, net['id'])
        else:
            # note - exception will rollback entire transaction
            LOG.debug(_("Created network: %s"), net['id'])
            return net

    def update_network(self, context, id, network):
        """
        Update network parameters.

        :param context: neutron api request context
        :param id: UUID representing the network to update
        :returns: updated network object
        """
        self._check_provider_update(context, network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            net = super(N1kvNeutronPluginV2, self).update_network(context, id,
                                                                  network)
            self._process_l3_update(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
        self._send_update_network_request(context.session, net)
        LOG.debug(_("Updated network: %s"), net['id'])
        return net

    def delete_network(self, context, id):
        """
        Delete a network.

        :param context: neutron api request context
        :param id: UUID representing the network to delete
        """
        session = context.session
        with session.begin(subtransactions=True):
            binding = n1kv_db_v2.get_network_binding(session, id)
            network = self.get_network(context, id)
            super(N1kvNeutronPluginV2, self).delete_network(context, id)
            if binding.network_type == c_const.NETWORK_TYPE_VXLAN:
                n1kv_db_v2.release_vxlan(session, binding.segmentation_id,
                                         self.vxlan_id_ranges)
            elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
                n1kv_db_v2.release_vlan(session, binding.physical_network,
                                        binding.segmentation_id,
                                        self.network_vlan_ranges)
                # the network_binding record is deleted via cascade from
                # the network record, so explicit removal is not necessary
        if self.agent_vsm:
            self._send_delete_network_request(network)
        LOG.debug(_("Deleted network: %s"), id)

    def get_network(self, context, id, fields=None):
        """
        Retreive a Network.

        :param context: neutron api request context
        :param id: UUID representing the network to fetch
        :returns: requested network dictionary
        """
        LOG.debug(_("Get network: %s"), id)
        net = super(N1kvNeutronPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_profile(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        """
        Retreive a list of networks.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        network object. Values in this dictiontary are an
                        iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a network
                        dictionary. Only these fields will be returned.
        :returns: list of network dictionaries.
        """
        LOG.debug(_("Get networks"))
        nets = super(N1kvNeutronPluginV2, self).get_networks(context, filters,
                                                             None)
        for net in nets:
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)

        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        """
        Create neutron port.

        Create a port. Use a default policy profile for ports created for dhcp
        and router interface. Default policy profile name is configured in the
        /etc/neutron/cisco_plugins.ini file.

        :param context: neutron api request context
        :param port: port dictionary
        :returns: port object
        """
        self._add_dummy_profile_only_if_testing(port)

        if ('device_id' in port['port'] and port['port']['device_owner'] in
            ['network:dhcp', 'network:router_interface']):
            p_profile_name = c_conf.CISCO_N1K.default_policy_profile
            p_profile = self._get_policy_profile_by_name(p_profile_name)
            if p_profile:
                port['port']['n1kv:profile_id'] = p_profile['id']

        profile_id_set = False
        if n1kv_profile.PROFILE_ID in port['port']:
            profile_id = port['port'].get(n1kv_profile.PROFILE_ID)
            profile_id_set = attributes.is_attr_set(profile_id)

        if profile_id_set:
            profile_id = self._process_policy_profile(context,
                                                      port['port'])
            LOG.debug(_('create port: profile_id=%s'), profile_id)
            session = context.session
            with session.begin(subtransactions=True):
                pt = super(N1kvNeutronPluginV2, self).create_port(context,
                                                                  port)
                n1kv_db_v2.add_port_binding(session, pt['id'], profile_id)
                self._extend_port_dict_profile(context, pt)
            try:
                self._send_create_port_request(context, pt)
            except(cisco_exceptions.VSMError,
                   cisco_exceptions.VSMConnectionFailed):
                super(N1kvNeutronPluginV2, self).delete_port(context, pt['id'])
            else:
                LOG.debug(_("Created port: %s"), pt)
                return pt

    def _add_dummy_profile_only_if_testing(self, obj):
        """
        Method to be patched by the test_n1kv_plugin module to
        inject n1kv:profile_id into the network/port object, since the plugin
        tests for its existence. This method does not affect
        the plugin code in any way.
        """
        pass

    def update_port(self, context, id, port):
        """
        Update port parameters.

        :param context: neutron api request context
        :param id: UUID representing the port to update
        :returns: updated port object
        """
        LOG.debug(_("Update port: %s"), id)
        if self.agent_vsm:
            super(N1kvNeutronPluginV2, self).get_port(context, id)
        port = super(N1kvNeutronPluginV2, self).update_port(context, id, port)
        self._extend_port_dict_profile(context, port)
        return port

    def delete_port(self, context, id):
        """
        Delete a port.

        :param context: neutron api request context
        :param id: UUID representing the port to delete
        :returns: deleted port object
        """
        self._send_delete_port_request(context, id)
        return super(N1kvNeutronPluginV2, self).delete_port(context, id)

    def get_port(self, context, id, fields=None):
        """
        Retrieve a port.
        :param context: neutron api request context
        :param id: UUID representing the port to retrieve
        :param fields: a list of strings that are valid keys in a port
                       dictionary. Only these fields will be returned.
        :returns: port dictionary
        """
        LOG.debug(_("Get port: %s"), id)
        port = super(N1kvNeutronPluginV2, self).get_port(context, id, fields)
        self._extend_port_dict_profile(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        """
        Retrieve a list of ports.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        port object. Values in this dictiontary are an
                        iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a port
                        dictionary. Only these fields will be returned.
        :returns: list of port dictionaries
        """
        LOG.debug(_("Get ports"))
        ports = super(N1kvNeutronPluginV2, self).get_ports(context, filters,
                                                           fields)
        for port in ports:
            self._extend_port_dict_profile(context, port)

        return [self._fields(port, fields) for port in ports]

    def create_subnet(self, context, subnet):
        """
        Create subnet for a given network.

        :param context: neutron api request context
        :param subnet: subnet dictionary
        :returns: subnet object
        """
        LOG.debug(_('Create subnet'))
        sub = super(N1kvNeutronPluginV2, self).create_subnet(context, subnet)
        try:
            self._send_create_subnet_request(context, sub)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            super(N1kvNeutronPluginV2, self).delete_subnet(context, sub['id'])
        else:
            LOG.debug(_("Created subnet: %s"), sub['id'])
            return sub

    def update_subnet(self, context, id, subnet):
        """
        Update a subnet.

        :param context: neutron api request context
        :param id: UUID representing subnet to update
        :returns: updated subnet object
        """
        LOG.debug(_('Update subnet'))
        sub = super(N1kvNeutronPluginV2, self).update_subnet(context,
                                                             id,
                                                             subnet)
        return sub

    def delete_subnet(self, context, id):
        """
        Delete a subnet.

        :param context: neutron api request context
        :param id: UUID representing subnet to delete
        :returns: deleted subnet object
        """
        LOG.debug(_('Delete subnet: %s'), id)
        subnet = self.get_subnet(context, id)
        self._send_delete_subnet_request(context, subnet)
        return super(N1kvNeutronPluginV2, self).delete_subnet(context, id)

    def get_subnet(self, context, id, fields=None):
        """
        Retrieve a subnet.

        :param context: neutron api request context
        :param id: UUID representing subnet to retrieve
        :params fields: a list of strings that are valid keys in a subnet
                        dictionary. Only these fields will be returned.
        :returns: subnet object
        """
        LOG.debug(_("Get subnet: %s"), id)
        subnet = super(N1kvNeutronPluginV2, self).get_subnet(context, id,
                                                             fields)
        return self._fields(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None):
        """
        Retrieve a list of subnets.

        :param context: neutron api request context
        :param filters: a dictionary with keys that are valid keys for a
                        subnet object. Values in this dictiontary are an
                        iterable containing values that will be used for an
                        exact match comparison for that value. Each result
                        returned by this function will have matched one of the
                        values for each key in filters
        :params fields: a list of strings that are valid keys in a subnet
                        dictionary. Only these fields will be returned.
        :returns: list of dictionaries of subnets
        """
        LOG.debug(_("Get subnets"))
        subnets = super(N1kvNeutronPluginV2, self).get_subnets(context,
                                                               filters,
                                                               fields)
        return [self._fields(subnet, fields) for subnet in subnets]

    def create_network_profile(self, context, network_profile):
        """
        Create a network profile.

        Create a network profile, which represents a pool of networks
        belonging to one type (VLAN or VXLAN). On creation of network
        profile, we retrieve the admin tenant-id which we use to replace
        the previously stored fake tenant-id in tenant-profile bindings.
        :param context: neutron api request context
        :param network_profile: network profile dictionary
        :returns: network profile object
        """
        self._replace_fake_tenant_id_with_real(context)
        _network_profile = super(
            N1kvNeutronPluginV2, self).create_network_profile(context,
                                                              network_profile)
        seg_min, seg_max = self._get_segment_range(
            _network_profile['segment_range'])
        if _network_profile['segment_type'] == c_const.NETWORK_TYPE_VLAN:
            self._add_network_vlan_range(_network_profile['physical_network'],
                                         int(seg_min),
                                         int(seg_max))
            n1kv_db_v2.sync_vlan_allocations(context.session,
                                             self.network_vlan_ranges)
        elif _network_profile['segment_type'] == c_const.NETWORK_TYPE_VXLAN:
            self.vxlan_id_ranges = []
            self.vxlan_id_ranges.append((int(seg_min), int(seg_max)))
            n1kv_db_v2.sync_vxlan_allocations(context.session,
                                              self.vxlan_id_ranges)
        try:
            self._send_create_logical_network_request(_network_profile)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            super(N1kvNeutronPluginV2, self).delete_network_profile(
                context, _network_profile['id'])
        try:
            self._send_create_network_profile_request(context,
                                                      _network_profile)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            self._send_delete_logical_network_request(_network_profile)
            super(N1kvNeutronPluginV2, self).delete_network_profile(
                context, _network_profile['id'])
        else:
            return _network_profile

    def delete_network_profile(self, context, id):
        """
        Delete a network profile.

        :param context: neutron api request context
        :param id: UUID of the network profile to delete
        :returns: deleted network profile object
        """
        _network_profile = super(
            N1kvNeutronPluginV2, self).delete_network_profile(context, id)
        seg_min, seg_max = self._get_segment_range(
            _network_profile['segment_range'])
        if _network_profile['segment_type'] == c_const.NETWORK_TYPE_VLAN:
            self._add_network_vlan_range(_network_profile['physical_network'],
                                         int(seg_min),
                                         int(seg_max))
            n1kv_db_v2.delete_vlan_allocations(context.session,
                                               self.network_vlan_ranges)
        elif _network_profile['segment_type'] == c_const.NETWORK_TYPE_VXLAN:
            self.delete_vxlan_ranges = []
            self.delete_vxlan_ranges.append((int(seg_min), int(seg_max)))
            n1kv_db_v2.delete_vxlan_allocations(context.session,
                                                self.delete_vxlan_ranges)
        self._send_delete_network_profile_request(_network_profile)
