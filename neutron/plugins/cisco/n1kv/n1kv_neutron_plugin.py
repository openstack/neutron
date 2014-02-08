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

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.common import utils
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_rpc_base
from neutron.db import portbindings_db
from neutron.extensions import portbindings
from neutron.extensions import providernet
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common import uuidutils as uuidutils
from neutron.plugins.cisco.common import cisco_constants as c_const
from neutron.plugins.cisco.common import cisco_credentials_v2 as c_cred
from neutron.plugins.cisco.common import cisco_exceptions
from neutron.plugins.cisco.common import config as c_conf
from neutron.plugins.cisco.db import n1kv_db_v2
from neutron.plugins.cisco.db import network_db_v2
from neutron.plugins.cisco.extensions import n1kv
from neutron.plugins.cisco.n1kv import n1kv_client
from neutron.plugins.common import constants as svc_constants


LOG = logging.getLogger(__name__)


class N1kvRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                       l3_rpc_base.L3RpcCallbackMixin):

    """Class to handle agent RPC calls."""

    # Set RPC API version to 1.1 by default.
    RPC_API_VERSION = '1.1'

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this rpc manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])


class N1kvNeutronPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                          external_net_db.External_net_db_mixin,
                          extraroute_db.ExtraRoute_db_mixin,
                          portbindings_db.PortBindingMixin,
                          n1kv_db_v2.NetworkProfile_db_mixin,
                          n1kv_db_v2.PolicyProfile_db_mixin,
                          network_db_v2.Credential_db_mixin,
                          l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                          agentschedulers_db.DhcpAgentSchedulerDbMixin):

    """
    Implement the Neutron abstractions using Cisco Nexus1000V.

    Refer README file for the architecture, new features, and
    workflow

    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations.
    __native_bulk_support = False
    supported_extension_aliases = ["provider", "agent",
                                   "n1kv", "network_profile",
                                   "policy_profile", "external-net", "router",
                                   "binding", "credential",
                                   "l3_agent_scheduler",
                                   "dhcp_agent_scheduler"]

    def __init__(self, configfile=None):
        """
        Initialize Nexus1000V Neutron plugin.

        1. Initialize VIF type to OVS
        2. Initialize Nexus1000v and Credential DB
        3. Establish communication with Cisco Nexus1000V
        """
        super(N1kvNeutronPluginV2, self).__init__()
        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
            portbindings.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        c_cred.Store.initialize()
        self._setup_vsm()
        self._setup_rpc()
        self.network_scheduler = importutils.import_object(
            q_conf.CONF.network_scheduler_driver
        )
        self.router_scheduler = importutils.import_object(
            q_conf.CONF.router_scheduler_driver
        )

    def _setup_rpc(self):
        # RPC support
        self.service_topics = {svc_constants.CORE: topics.PLUGIN,
                               svc_constants.L3_ROUTER_NAT: topics.L3PLUGIN}
        self.conn = rpc.create_connection(new=True)
        self.dispatcher = N1kvRpcCallbacks().create_rpc_dispatcher()
        for svc_topic in self.service_topics.values():
            self.conn.create_consumer(svc_topic, self.dispatcher, fanout=False)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def _setup_vsm(self):
        """
        Setup Cisco Nexus 1000V related parameters and pull policy profiles.

        Retrieve all the policy profiles from the VSM when the plugin is
        is instantiated for the first time and then continue to poll for
        policy profile updates.
        """
        LOG.debug(_('_setup_vsm'))
        self.agent_vsm = True
        # Poll VSM for create/delete of policy profile.
        eventlet.spawn(self._poll_policy_profiles)

    def _poll_policy_profiles(self):
        """Start a green thread to pull policy profiles from VSM."""
        while True:
            self._populate_policy_profiles()
            eventlet.sleep(int(c_conf.CISCO_N1K.poll_duration))

    def _populate_policy_profiles(self):
        """
        Populate all the policy profiles from VSM.

        The tenant id is not available when the policy profiles are polled
        from the VSM. Hence we associate the policy profiles with fake
        tenant-ids.
        """
        LOG.debug(_('_populate_policy_profiles'))
        try:
            n1kvclient = n1kv_client.Client()
            policy_profiles = n1kvclient.list_port_profiles()
            vsm_profiles = {}
            plugin_profiles = {}
            # Fetch policy profiles from VSM
            if policy_profiles:
                for profile in policy_profiles['body'][c_const.SET]:
                    profile_name = (profile[c_const.PROPERTIES].
                                    get(c_const.NAME, None))
                    profile_id = (profile[c_const.PROPERTIES].
                                  get(c_const.ID, None))
                    if profile_id and profile_name:
                        vsm_profiles[profile_id] = profile_name
                # Fetch policy profiles previously populated
                for profile in n1kv_db_v2.get_policy_profiles():
                    plugin_profiles[profile.id] = profile.name
                vsm_profiles_set = set(vsm_profiles)
                plugin_profiles_set = set(plugin_profiles)
                # Update database if the profile sets differ.
                if vsm_profiles_set ^ plugin_profiles_set:
                # Add profiles in database if new profiles were created in VSM
                    for pid in vsm_profiles_set - plugin_profiles_set:
                        self._add_policy_profile(vsm_profiles[pid], pid)
                # Delete profiles from database if profiles were deleted in VSM
                    for pid in plugin_profiles_set - vsm_profiles_set:
                        self._delete_policy_profile(pid)
            self._remove_all_fake_policy_profiles()
        except (cisco_exceptions.VSMError,
                cisco_exceptions.VSMConnectionFailed):
            LOG.warning(_('No policy profile populated from VSM'))

    def _extend_network_dict_provider(self, context, network):
        """Add extended network parameters."""
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[providernet.NETWORK_TYPE] = binding.network_type
        if binding.network_type == c_const.NETWORK_TYPE_OVERLAY:
            network[providernet.PHYSICAL_NETWORK] = None
            network[providernet.SEGMENTATION_ID] = binding.segmentation_id
            network[n1kv.MULTICAST_IP] = binding.multicast_ip
        elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
            network[providernet.PHYSICAL_NETWORK] = binding.physical_network
            network[providernet.SEGMENTATION_ID] = binding.segmentation_id
        elif binding.network_type == c_const.NETWORK_TYPE_TRUNK:
            network[providernet.PHYSICAL_NETWORK] = binding.physical_network
            network[providernet.SEGMENTATION_ID] = None
            network[n1kv.MULTICAST_IP] = None
        elif binding.network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
            network[providernet.PHYSICAL_NETWORK] = None
            network[providernet.SEGMENTATION_ID] = None
            network[n1kv.MULTICAST_IP] = None

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
            raise n_exc.InvalidInput(error_message=msg)
        elif network_type == c_const.NETWORK_TYPE_VLAN:
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise n_exc.InvalidInput(error_message=msg)
            if segmentation_id < 1 or segmentation_id > 4094:
                msg = _("provider:segmentation_id out of range "
                        "(1 through 4094)")
                raise n_exc.InvalidInput(error_message=msg)
        elif network_type == c_const.NETWORK_TYPE_OVERLAY:
            if physical_network_set:
                msg = _("provider:physical_network specified for Overlay "
                        "network")
                raise n_exc.InvalidInput(error_message=msg)
            else:
                physical_network = None
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise n_exc.InvalidInput(error_message=msg)
            if segmentation_id < 5000:
                msg = _("provider:segmentation_id out of range "
                        "(5000+)")
                raise n_exc.InvalidInput(error_message=msg)
        else:
            msg = _("provider:network_type %s not supported"), network_type
            raise n_exc.InvalidInput(error_message=msg)

        if network_type == c_const.NETWORK_TYPE_VLAN:
            if physical_network_set:
                network_profiles = n1kv_db_v2.get_network_profiles()
                for network_profile in network_profiles:
                    if physical_network == network_profile[
                        'physical_network']:
                        break
                else:
                    msg = (_("Unknown provider:physical_network %s"),
                           physical_network)
                    raise n_exc.InvalidInput(error_message=msg)
            else:
                msg = _("provider:physical_network required")
                raise n_exc.InvalidInput(error_message=msg)

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
        msg = _("Plugin does not support updating provider attributes")
        raise n_exc.InvalidInput(error_message=msg)

    def _get_cluster(self, segment1, segment2, clusters):
        """
        Returns a cluster to apply the segment mapping

        :param segment1: UUID of segment to be mapped
        :param segment2: UUID of segment to be mapped
        :param clusters: List of clusters
        """
        for cluster in sorted(clusters, key=lambda k: k['size']):
            for mapping in cluster[c_const.MAPPINGS]:
                for segment in mapping[c_const.SEGMENTS]:
                    if segment1 in segment or segment2 in segment:
                        break
                else:
                    cluster['size'] += 2
                    return cluster['encapProfileName']
                break
        return

    def _extend_mapping_dict(self, context, mapping_dict, segment):
        """
        Extend a mapping dictionary with dot1q tag and bridge-domain name.

        :param context: neutron api request context
        :param mapping_dict: dictionary to populate values
        :param segment: id of the segment being populated
        """
        net = self.get_network(context, segment)
        if net[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_VLAN:
            mapping_dict['dot1q'] = str(net[providernet.SEGMENTATION_ID])
        else:
            mapping_dict['bridgeDomain'] = (net['name'] +
                                            c_const.BRIDGE_DOMAIN_SUFFIX)

    def _send_add_multi_segment_request(self, context, net_id, segment_pairs):
        """
        Send Add multi-segment network request to VSM.

        :param context: neutron api request context
        :param net_id: UUID of the multi-segment network
        :param segment_pairs: List of segments in UUID pairs
                              that need to be bridged
        """

        if not segment_pairs:
            return

        session = context.session
        n1kvclient = n1kv_client.Client()
        clusters = n1kvclient.get_clusters()
        online_clusters = []
        encap_dict = {}
        for cluster in clusters['body'][c_const.SET]:
            cluster = cluster[c_const.PROPERTIES]
            if cluster[c_const.STATE] == c_const.ONLINE:
                cluster['size'] = 0
                for mapping in cluster[c_const.MAPPINGS]:
                    cluster['size'] += (
                        len(mapping[c_const.SEGMENTS]))
                online_clusters.append(cluster)
        for (segment1, segment2) in segment_pairs:
            encap_profile = self._get_cluster(segment1, segment2,
                                              online_clusters)
            if encap_profile is not None:
                if encap_profile in encap_dict:
                    profile_dict = encap_dict[encap_profile]
                else:
                    profile_dict = {'name': encap_profile,
                                    'addMappings': [],
                                    'delMappings': []}
                    encap_dict[encap_profile] = profile_dict
                mapping_dict = {}
                self._extend_mapping_dict(context,
                                          mapping_dict, segment1)
                self._extend_mapping_dict(context,
                                          mapping_dict, segment2)
                profile_dict['addMappings'].append(mapping_dict)
                n1kv_db_v2.add_multi_segment_encap_profile_name(session,
                                                                net_id,
                                                                (segment1,
                                                                 segment2),
                                                                encap_profile)
            else:
                raise cisco_exceptions.NoClusterFound

        for profile in encap_dict:
            n1kvclient.update_encapsulation_profile(context, profile,
                                                    encap_dict[profile])

    def _send_del_multi_segment_request(self, context, net_id, segment_pairs):
        """
        Send Delete multi-segment network request to VSM.

        :param context: neutron api request context
        :param net_id: UUID of the multi-segment network
        :param segment_pairs: List of segments in UUID pairs
                              whose bridging needs to be removed
        """
        if not segment_pairs:
            return
        session = context.session
        encap_dict = {}
        n1kvclient = n1kv_client.Client()
        for (segment1, segment2) in segment_pairs:
            binding = (
                n1kv_db_v2.get_multi_segment_network_binding(session, net_id,
                                                             (segment1,
                                                              segment2)))
            encap_profile = binding['encap_profile_name']
            if encap_profile in encap_dict:
                profile_dict = encap_dict[encap_profile]
            else:
                profile_dict = {'name': encap_profile,
                                'addMappings': [],
                                'delMappings': []}
                encap_dict[encap_profile] = profile_dict
            mapping_dict = {}
            self._extend_mapping_dict(context,
                                      mapping_dict, segment1)
            self._extend_mapping_dict(context,
                                      mapping_dict, segment2)
            profile_dict['delMappings'].append(mapping_dict)

        for profile in encap_dict:
            n1kvclient.update_encapsulation_profile(context, profile,
                                                    encap_dict[profile])

    def _get_encap_segments(self, context, segment_pairs):
        """
        Get the list of segments in encapsulation profile format.

        :param context: neutron api request context
        :param segment_pairs: List of segments that need to be bridged
        """
        member_list = []
        for pair in segment_pairs:
            (segment, dot1qtag) = pair
            member_dict = {}
            net = self.get_network(context, segment)
            member_dict['bridgeDomain'] = (net['name'] +
                                           c_const.BRIDGE_DOMAIN_SUFFIX)
            member_dict['dot1q'] = dot1qtag
            member_list.append(member_dict)
        return member_list

    def _populate_member_segments(self, context, network, segment_pairs, oper):
        """
        Populate trunk network dict with member segments.

        :param context: neutron api request context
        :param network: Dictionary containing the trunk network information
        :param segment_pairs: List of segments in UUID pairs
                              that needs to be trunked
        :param oper: Operation to be performed
        """
        LOG.debug(_('_populate_member_segments %s'), segment_pairs)
        trunk_list = []
        for (segment, dot1qtag) in segment_pairs:
            net = self.get_network(context, segment)
            member_dict = {'segment': net['name'],
                           'dot1qtag': dot1qtag}
            trunk_list.append(member_dict)
        if oper == n1kv.SEGMENT_ADD:
            network['add_segment_list'] = trunk_list
        elif oper == n1kv.SEGMENT_DEL:
            network['del_segment_list'] = trunk_list

    def _parse_multi_segments(self, context, attrs, param):
        """
        Parse the multi-segment network attributes.

        :param context: neutron api request context
        :param attrs: Attributes of the network
        :param param: Additional parameter indicating an add
                      or del operation
        :returns: List of segment UUIDs in set pairs
        """
        pair_list = []
        valid_seg_types = [c_const.NETWORK_TYPE_VLAN,
                           c_const.NETWORK_TYPE_OVERLAY]
        segments = attrs.get(param)
        if not attributes.is_attr_set(segments):
            return pair_list
        for pair in segments.split(','):
            segment1, sep, segment2 = pair.partition(':')
            if (uuidutils.is_uuid_like(segment1) and
                    uuidutils.is_uuid_like(segment2)):
                binding1 = n1kv_db_v2.get_network_binding(context.session,
                                                          segment1)
                binding2 = n1kv_db_v2.get_network_binding(context.session,
                                                          segment2)
                if (binding1.network_type not in valid_seg_types or
                        binding2.network_type not in valid_seg_types or
                        binding1.network_type == binding2.network_type):
                    msg = _("Invalid pairing supplied")
                    raise n_exc.InvalidInput(error_message=msg)
                else:
                    pair_list.append((segment1, segment2))
            else:
                LOG.debug(_('Invalid UUID supplied in %s'), pair)
                msg = _("Invalid UUID supplied")
                raise n_exc.InvalidInput(error_message=msg)
        return pair_list

    def _parse_trunk_segments(self, context, attrs, param, physical_network,
                              sub_type):
        """
        Parse the trunk network attributes.

        :param context: neutron api request context
        :param attrs: Attributes of the network
        :param param: Additional parameter indicating an add
                      or del operation
        :param physical_network: Physical network of the trunk segment
        :param sub_type: Sub-type of the trunk segment
        :returns: List of segment UUIDs and dot1qtag (for vxlan) in set pairs
        """
        pair_list = []
        segments = attrs.get(param)
        if not attributes.is_attr_set(segments):
            return pair_list
        for pair in segments.split(','):
            segment, sep, dot1qtag = pair.partition(':')
            if sub_type == c_const.NETWORK_TYPE_VLAN:
                dot1qtag = ''
            if uuidutils.is_uuid_like(segment):
                binding = n1kv_db_v2.get_network_binding(context.session,
                                                         segment)
                if binding.network_type == c_const.NETWORK_TYPE_TRUNK:
                    msg = _("Cannot add a trunk segment '%s' as a member of "
                            "another trunk segment") % segment
                    raise n_exc.InvalidInput(error_message=msg)
                elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
                    if sub_type == c_const.NETWORK_TYPE_OVERLAY:
                        msg = _("Cannot add vlan segment '%s' as a member of "
                                "a vxlan trunk segment") % segment
                        raise n_exc.InvalidInput(error_message=msg)
                    if not physical_network:
                        physical_network = binding.physical_network
                    elif physical_network != binding.physical_network:
                        msg = _("Network UUID '%s' belongs to a different "
                                "physical network") % segment
                        raise n_exc.InvalidInput(error_message=msg)
                elif binding.network_type == c_const.NETWORK_TYPE_OVERLAY:
                    if sub_type == c_const.NETWORK_TYPE_VLAN:
                        msg = _("Cannot add vxlan segment '%s' as a member of "
                                "a vlan trunk segment") % segment
                        raise n_exc.InvalidInput(error_message=msg)
                    try:
                        if not utils.is_valid_vlan_tag(int(dot1qtag)):
                            msg = _("Vlan tag '%s' is out of range") % dot1qtag
                            raise n_exc.InvalidInput(error_message=msg)
                    except ValueError:
                        msg = _("Vlan tag '%s' is not an integer "
                                "value") % dot1qtag
                        raise n_exc.InvalidInput(error_message=msg)
                pair_list.append((segment, dot1qtag))
            else:
                LOG.debug(_('%s is not a valid uuid'), segment)
                msg = _("'%s' is not a valid UUID") % segment
                raise n_exc.InvalidInput(error_message=msg)
        return pair_list

    def _extend_network_dict_member_segments(self, context, network):
        """Add the extended parameter member segments to the network."""
        members = []
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        if binding.network_type == c_const.NETWORK_TYPE_TRUNK:
            members = n1kv_db_v2.get_trunk_members(context.session,
                                                   network['id'])
        elif binding.network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
            members = n1kv_db_v2.get_multi_segment_members(context.session,
                                                           network['id'])
        network[n1kv.MEMBER_SEGMENTS] = members

    def _extend_network_dict_profile(self, context, network):
        """Add the extended parameter network profile to the network."""
        binding = n1kv_db_v2.get_network_binding(context.session,
                                                 network['id'])
        network[n1kv.PROFILE_ID] = binding.profile_id

    def _extend_port_dict_profile(self, context, port):
        """Add the extended parameter port profile to the port."""
        binding = n1kv_db_v2.get_port_binding(context.session,
                                              port['id'])
        port[n1kv.PROFILE_ID] = binding.profile_id

    def _process_network_profile(self, context, network):
        """Validate network profile exists."""
        profile_id = network.get(n1kv.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            profile_name = c_conf.CISCO_N1K.default_network_profile
            net_p = self._get_network_profile_by_name(context.session,
                                                      profile_name)
            profile_id = net_p['id']
            network['n1kv:profile_id'] = profile_id
        return profile_id

    def _process_policy_profile(self, context, attrs):
        """Validates whether policy profile exists."""
        profile_id = attrs.get(n1kv.PROFILE_ID)
        profile_id_set = attributes.is_attr_set(profile_id)
        if not profile_id_set:
            msg = _("n1kv:profile_id does not exist")
            raise n_exc.InvalidInput(error_message=msg)
        if not self._policy_profile_exists(profile_id):
            msg = _("n1kv:profile_id does not exist")
            raise n_exc.InvalidInput(error_message=msg)

        return profile_id

    def _send_create_logical_network_request(self, network_profile, tenant_id):
        """
        Send create logical network request to VSM.

        :param network_profile: network profile dictionary
        :param tenant_id: UUID representing the tenant
        """
        LOG.debug(_('_send_create_logical_network'))
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_logical_network(network_profile, tenant_id)

    def _send_delete_logical_network_request(self, network_profile):
        """
        Send delete logical network request to VSM.

        :param network_profile: network profile dictionary
        """
        LOG.debug('_send_delete_logical_network')
        n1kvclient = n1kv_client.Client()
        logical_network_name = (network_profile['id'] +
                                c_const.LOGICAL_NETWORK_SUFFIX)
        n1kvclient.delete_logical_network(logical_network_name)

    def _send_create_network_profile_request(self, context, profile):
        """
        Send create network profile request to VSM.

        :param context: neutron api request context
        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_create_network_profile_request: %s'), profile['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_network_segment_pool(profile, context.tenant_id)

    def _send_update_network_profile_request(self, profile):
        """
        Send update network profile request to VSM.

        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_update_network_profile_request: %s'), profile['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment_pool(profile)

    def _send_delete_network_profile_request(self, profile):
        """
        Send delete network profile request to VSM.

        :param profile: network profile dictionary
        """
        LOG.debug(_('_send_delete_network_profile_request: %s'),
                  profile['name'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_network_segment_pool(profile['id'])

    def _send_create_network_request(self, context, network, segment_pairs):
        """
        Send create network request to VSM.

        Create a bridge domain for network of type Overlay.
        :param context: neutron api request context
        :param network: network dictionary
        :param segment_pairs: List of segments in UUID pairs
                              that need to be bridged
        """
        LOG.debug(_('_send_create_network_request: %s'), network['id'])
        profile = self.get_network_profile(context,
                                           network[n1kv.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_OVERLAY:
            n1kvclient.create_bridge_domain(network, profile['sub_type'])
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_TRUNK:
            self._populate_member_segments(context, network, segment_pairs,
                                           n1kv.SEGMENT_ADD)
            network['del_segment_list'] = []
            if profile['sub_type'] == c_const.NETWORK_TYPE_OVERLAY:
                encap_dict = {'name': (network['name'] +
                                       c_const.ENCAPSULATION_PROFILE_SUFFIX),
                              'add_segment_list': (
                                  self._get_encap_segments(context,
                                                           segment_pairs)),
                              'del_segment_list': []}
                n1kvclient.create_encapsulation_profile(encap_dict)
        n1kvclient.create_network_segment(network, profile)

    def _send_update_network_request(self, context, network, add_segments,
                                     del_segments):
        """
        Send update network request to VSM.

        :param context: neutron api request context
        :param network: network dictionary
        :param add_segments: List of segments bindings
                             that need to be deleted
        :param del_segments: List of segments bindings
                             that need to be deleted
        """
        LOG.debug(_('_send_update_network_request: %s'), network['id'])
        db_session = context.session
        profile = n1kv_db_v2.get_network_profile(
            db_session, network[n1kv.PROFILE_ID])
        n1kvclient = n1kv_client.Client()
        body = {'description': network['name'],
                'id': network['id'],
                'networkSegmentPool': profile['id'],
                'vlan': network[providernet.SEGMENTATION_ID],
                'mode': 'access',
                'segmentType': profile['segment_type'],
                'addSegments': [],
                'delSegments': []}
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_TRUNK:
            self._populate_member_segments(context, network, add_segments,
                                           n1kv.SEGMENT_ADD)
            self._populate_member_segments(context, network, del_segments,
                                           n1kv.SEGMENT_DEL)
            body['mode'] = c_const.NETWORK_TYPE_TRUNK
            body['segmentType'] = profile['sub_type']
            body['addSegments'] = network['add_segment_list']
            body['delSegments'] = network['del_segment_list']
            LOG.debug(_('add_segments=%s'), body['addSegments'])
            LOG.debug(_('del_segments=%s'), body['delSegments'])
            if profile['sub_type'] == c_const.NETWORK_TYPE_OVERLAY:
                encap_profile = (network['id'] +
                                 c_const.ENCAPSULATION_PROFILE_SUFFIX)
                encap_dict = {'name': encap_profile,
                              'addMappings': (
                                  self._get_encap_segments(context,
                                                           add_segments)),
                              'delMappings': (
                                  self._get_encap_segments(context,
                                                           del_segments))}
                n1kvclient.update_encapsulation_profile(context, encap_profile,
                                                        encap_dict)
        n1kvclient.update_network_segment(network['id'], body)

    def _send_delete_network_request(self, context, network):
        """
        Send delete network request to VSM.

        Delete bridge domain if network is of type Overlay.
        Delete encapsulation profile if network is of type OVERLAY Trunk.
        :param context: neutron api request context
        :param network: network dictionary
        """
        LOG.debug(_('_send_delete_network_request: %s'), network['id'])
        n1kvclient = n1kv_client.Client()
        session = context.session
        if network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_OVERLAY:
            name = network['id'] + c_const.BRIDGE_DOMAIN_SUFFIX
            n1kvclient.delete_bridge_domain(name)
        elif network[providernet.NETWORK_TYPE] == c_const.NETWORK_TYPE_TRUNK:
            profile = self.get_network_profile(
                context, network[n1kv.PROFILE_ID])
            if profile['sub_type'] == c_const.NETWORK_TYPE_OVERLAY:
                profile_name = (network['id'] +
                                c_const.ENCAPSULATION_PROFILE_SUFFIX)
                n1kvclient.delete_encapsulation_profile(profile_name)
        elif (network[providernet.NETWORK_TYPE] ==
                c_const.NETWORK_TYPE_MULTI_SEGMENT):
            encap_dict = n1kv_db_v2.get_multi_segment_encap_dict(session,
                                                                 network['id'])
            for profile in encap_dict:
                profile_dict = {'name': profile,
                                'addSegments': [],
                                'delSegments': []}
                for segment_pair in encap_dict[profile]:
                    mapping_dict = {}
                    (segment1, segment2) = segment_pair
                    self._extend_mapping_dict(context,
                                              mapping_dict, segment1)
                    self._extend_mapping_dict(context,
                                              mapping_dict, segment2)
                    profile_dict['delSegments'].append(mapping_dict)
                n1kvclient.update_encapsulation_profile(context, profile,
                                                        profile_dict)
        n1kvclient.delete_network_segment(network['id'])

    def _send_create_subnet_request(self, context, subnet):
        """
        Send create subnet request to VSM.

        :param context: neutron api request context
        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_create_subnet_request: %s'), subnet['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.create_ip_pool(subnet)

    def _send_update_subnet_request(self, subnet):
        """
        Send update subnet request to VSM.

        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_update_subnet_request: %s'), subnet['name'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_ip_pool(subnet)

    def _send_delete_subnet_request(self, context, subnet):
        """
        Send delete subnet request to VSM.

        :param context: neutron api request context
        :param subnet: subnet dictionary
        """
        LOG.debug(_('_send_delete_subnet_request: %s'), subnet['name'])
        body = {'ipPool': subnet['id'], 'deleteSubnet': True}
        n1kvclient = n1kv_client.Client()
        n1kvclient.update_network_segment(subnet['network_id'], body=body)
        n1kvclient.delete_ip_pool(subnet['id'])

    def _send_create_port_request(self,
                                  context,
                                  port,
                                  port_count,
                                  policy_profile,
                                  vm_network_name):
        """
        Send create port request to VSM.

        Create a VM network for a network and policy profile combination.
        If the VM network already exists, bind this port to the existing
        VM network on the VSM.
        :param context: neutron api request context
        :param port: port dictionary
        :param port_count: integer representing the number of ports in one
                           VM Network
        :param policy_profile: object of type policy profile
        :param vm_network_name: string representing the name of the VM
                                network
        """
        LOG.debug(_('_send_create_port_request: %s'), port)
        n1kvclient = n1kv_client.Client()
        if port_count == 1:
            n1kvclient.create_vm_network(port,
                                         vm_network_name,
                                         policy_profile)
        else:
            n1kvclient.create_n1kv_port(port, vm_network_name)

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

    def _send_delete_port_request(self, context, port, vm_network):
        """
        Send delete port request to VSM.

        Delete the port on the VSM. If it is the last port on the VM Network,
        delete the VM Network.
        :param context: neutron api request context
        :param port: port object which is to be deleted
        :param vm_network: VM network object with which the port is associated
        """
        LOG.debug(_('_send_delete_port_request: %s'), port['id'])
        n1kvclient = n1kv_client.Client()
        n1kvclient.delete_n1kv_port(vm_network['name'], port['id'])
        if vm_network['port_count'] == 0:
            n1kvclient.delete_vm_network(vm_network['name'])

    def _get_segmentation_id(self, context, id):
        """
        Retrieve segmentation ID for a given network.

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
        profile_id = self._process_network_profile(context, network['network'])
        segment_pairs = None
        LOG.debug(_('Create network: profile_id=%s'), profile_id)
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
                if network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
                    segment_pairs = (
                        self._parse_multi_segments(context, network['network'],
                                                   n1kv.SEGMENT_ADD))
                    LOG.debug(_('Seg list %s '), segment_pairs)
                elif network_type == c_const.NETWORK_TYPE_TRUNK:
                    network_profile = self.get_network_profile(context,
                                                               profile_id)
                    segment_pairs = (
                        self._parse_trunk_segments(context, network['network'],
                                                   n1kv.SEGMENT_ADD,
                                                   physical_network,
                                                   network_profile['sub_type']
                                                   ))
                    LOG.debug(_('Seg list %s '), segment_pairs)
                else:
                    if not segmentation_id:
                        raise n_exc.TenantNetworksDisabled()
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
                                           profile_id,
                                           segment_pairs)
            self._process_l3_create(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
        try:
            if network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
                self._send_add_multi_segment_request(context, net['id'],
                                                     segment_pairs)
            else:
                self._send_create_network_request(context, net, segment_pairs)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                self._delete_network_db(context, net['id'])
        else:
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
        add_segments = []
        del_segments = []

        session = context.session
        with session.begin(subtransactions=True):
            net = super(N1kvNeutronPluginV2, self).update_network(context, id,
                                                                  network)
            self._process_l3_update(context, net, network['network'])
            binding = n1kv_db_v2.get_network_binding(session, id)
            if binding.network_type == c_const.NETWORK_TYPE_MULTI_SEGMENT:
                add_segments = (
                    self._parse_multi_segments(context, network['network'],
                                               n1kv.SEGMENT_ADD))
                n1kv_db_v2.add_multi_segment_binding(session,
                                                     net['id'], add_segments)
                del_segments = (
                    self._parse_multi_segments(context, network['network'],
                                               n1kv.SEGMENT_DEL))
                self._send_add_multi_segment_request(context, net['id'],
                                                     add_segments)
                self._send_del_multi_segment_request(context, net['id'],
                                                     del_segments)
                n1kv_db_v2.del_multi_segment_binding(session,
                                                     net['id'], del_segments)
            elif binding.network_type == c_const.NETWORK_TYPE_TRUNK:
                network_profile = self.get_network_profile(context,
                                                           binding.profile_id)
                add_segments = (
                    self._parse_trunk_segments(context, network['network'],
                                               n1kv.SEGMENT_ADD,
                                               binding.physical_network,
                                               network_profile['sub_type']))
                n1kv_db_v2.add_trunk_segment_binding(session,
                                                     net['id'], add_segments)
                del_segments = (
                    self._parse_trunk_segments(context, network['network'],
                                               n1kv.SEGMENT_DEL,
                                               binding.physical_network,
                                               network_profile['sub_type']))
                n1kv_db_v2.del_trunk_segment_binding(session,
                                                     net['id'], del_segments)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_profile(context, net)
            if binding.network_type != c_const.NETWORK_TYPE_MULTI_SEGMENT:
                self._send_update_network_request(context, net, add_segments,
                                                  del_segments)
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
            network = self.get_network(context, id)
            if n1kv_db_v2.is_trunk_member(session, id):
                msg = _("Cannot delete network '%s' "
                        "that is member of a trunk segment") % network['name']
                raise n_exc.InvalidInput(error_message=msg)
            if n1kv_db_v2.is_multi_segment_member(session, id):
                msg = _("Cannot delete network '%s' that is a member of a "
                        "multi-segment network") % network['name']
                raise n_exc.InvalidInput(error_message=msg)
            self._delete_network_db(context, id)
            # the network_binding record is deleted via cascade from
            # the network record, so explicit removal is not necessary
        self._send_delete_network_request(context, network)
        LOG.debug("Deleted network: %s", id)

    def _delete_network_db(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            binding = n1kv_db_v2.get_network_binding(session, id)
            if binding.network_type == c_const.NETWORK_TYPE_OVERLAY:
                n1kv_db_v2.release_vxlan(session, binding.segmentation_id)
            elif binding.network_type == c_const.NETWORK_TYPE_VLAN:
                n1kv_db_v2.release_vlan(session, binding.physical_network,
                                        binding.segmentation_id)
            super(N1kvNeutronPluginV2, self).delete_network(context, id)

    def get_network(self, context, id, fields=None):
        """
        Retrieve a Network.

        :param context: neutron api request context
        :param id: UUID representing the network to fetch
        :returns: requested network dictionary
        """
        LOG.debug(_("Get network: %s"), id)
        net = super(N1kvNeutronPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_profile(context, net)
        self._extend_network_dict_member_segments(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        """
        Retrieve a list of networks.

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
        p_profile = None
        port_count = None
        vm_network = None
        vm_network_name = None
        profile_id_set = False

        # Set the network policy profile id for auto generated L3/DHCP ports
        if ('device_id' in port['port'] and port['port']['device_owner'] in
            [constants.DEVICE_OWNER_DHCP, constants.DEVICE_OWNER_ROUTER_INTF,
             constants.DEVICE_OWNER_ROUTER_GW,
             constants.DEVICE_OWNER_FLOATINGIP]):
            p_profile_name = c_conf.CISCO_N1K.network_node_policy_profile
            p_profile = self._get_policy_profile_by_name(p_profile_name)
            if p_profile:
                port['port']['n1kv:profile_id'] = p_profile['id']

        if n1kv.PROFILE_ID in port['port']:
            profile_id = port['port'].get(n1kv.PROFILE_ID)
            profile_id_set = attributes.is_attr_set(profile_id)

        # Set the default policy profile id for ports if no id is set
        if not profile_id_set:
            p_profile_name = c_conf.CISCO_N1K.default_policy_profile
            p_profile = self._get_policy_profile_by_name(p_profile_name)
            if p_profile:
                port['port']['n1kv:profile_id'] = p_profile['id']
                profile_id_set = True

        profile_id = self._process_policy_profile(context,
                                                  port['port'])
        LOG.debug(_('Create port: profile_id=%s'), profile_id)
        session = context.session
        with session.begin(subtransactions=True):
            pt = super(N1kvNeutronPluginV2, self).create_port(context,
                                                              port)
            n1kv_db_v2.add_port_binding(session, pt['id'], profile_id)
            self._extend_port_dict_profile(context, pt)
            try:
                vm_network = n1kv_db_v2.get_vm_network(
                    context.session,
                    profile_id,
                    pt['network_id'])
            except cisco_exceptions.VMNetworkNotFound:
                # Create a VM Network if no VM network exists.
                vm_network_name = "%s%s_%s" % (c_const.VM_NETWORK_NAME_PREFIX,
                                               profile_id,
                                               pt['network_id'])
                port_count = 1
                vm_network = n1kv_db_v2.add_vm_network(context.session,
                                                       vm_network_name,
                                                       profile_id,
                                                       pt['network_id'],
                                                       port_count)
            else:
                # Update port count of the VM network.
                vm_network_name = vm_network['name']
                port_count = vm_network['port_count'] + 1
                n1kv_db_v2.update_vm_network_port_count(context.session,
                                                        vm_network_name,
                                                        port_count)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         pt)
            # Extract policy profile for VM network create in VSM.
            if not p_profile:
                p_profile = n1kv_db_v2.get_policy_profile(session, profile_id)
        try:
            self._send_create_port_request(context,
                                           pt,
                                           port_count,
                                           p_profile,
                                           vm_network_name)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                self._delete_port_db(context, pt, vm_network)
        else:
            LOG.debug(_("Created port: %s"), pt)
            return pt

    def update_port(self, context, id, port):
        """
        Update port parameters.

        :param context: neutron api request context
        :param id: UUID representing the port to update
        :returns: updated port object
        """
        LOG.debug(_("Update port: %s"), id)
        with context.session.begin(subtransactions=True):
            updated_port = super(N1kvNeutronPluginV2,
                                 self).update_port(context, id, port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         updated_port)
            self._extend_port_dict_profile(context, updated_port)
        return updated_port

    def delete_port(self, context, id, l3_port_check=True):
        """
        Delete a port.

        :param context: neutron api request context
        :param id: UUID representing the port to delete
        """
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        with context.session.begin(subtransactions=True):
            port = self.get_port(context, id)
            vm_network = n1kv_db_v2.get_vm_network(context.session,
                                                   port[n1kv.PROFILE_ID],
                                                   port['network_id'])
            router_ids = self.disassociate_floatingips(
                context, id, do_notify=False)
            self._delete_port_db(context, port, vm_network)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)
        self._send_delete_port_request(context, port, vm_network)

    def _delete_port_db(self, context, port, vm_network):
        with context.session.begin(subtransactions=True):
            vm_network['port_count'] -= 1
            n1kv_db_v2.update_vm_network_port_count(context.session,
                                                    vm_network['name'],
                                                    vm_network['port_count'])
            if vm_network['port_count'] == 0:
                n1kv_db_v2.delete_vm_network(context.session,
                                             port[n1kv.PROFILE_ID],
                                             port['network_id'])
            super(N1kvNeutronPluginV2, self).delete_port(context, port['id'])

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
        port = super(N1kvNeutronPluginV2, self).get_port(context, id, None)
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
                                                           None)
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
            with excutils.save_and_reraise_exception():
                super(N1kvNeutronPluginV2,
                      self).delete_subnet(context, sub['id'])
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
        self._send_update_subnet_request(sub)
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
                                                             None)
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
                                                               None)
        return [self._fields(subnet, fields) for subnet in subnets]

    def create_network_profile(self, context, network_profile):
        """
        Create a network profile.

        Create a network profile, which represents a pool of networks
        belonging to one type (VLAN or Overlay). On creation of network
        profile, we retrieve the admin tenant-id which we use to replace
        the previously stored fake tenant-id in tenant-profile bindings.
        :param context: neutron api request context
        :param network_profile: network profile dictionary
        :returns: network profile object
        """
        self._replace_fake_tenant_id_with_real(context)
        with context.session.begin(subtransactions=True):
            net_p = super(N1kvNeutronPluginV2,
                          self).create_network_profile(context,
                                                       network_profile)
        try:
            self._send_create_logical_network_request(net_p,
                                                      context.tenant_id)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                super(N1kvNeutronPluginV2,
                      self).delete_network_profile(context, net_p['id'])
        try:
            self._send_create_network_profile_request(context, net_p)
        except(cisco_exceptions.VSMError,
               cisco_exceptions.VSMConnectionFailed):
            with excutils.save_and_reraise_exception():
                super(N1kvNeutronPluginV2,
                      self).delete_network_profile(context, net_p['id'])
                self._send_delete_logical_network_request(net_p)
        return net_p

    def delete_network_profile(self, context, id):
        """
        Delete a network profile.

        :param context: neutron api request context
        :param id: UUID of the network profile to delete
        :returns: deleted network profile object
        """
        with context.session.begin(subtransactions=True):
            net_p = super(N1kvNeutronPluginV2,
                          self).delete_network_profile(context, id)
        self._send_delete_network_profile_request(net_p)
        self._send_delete_logical_network_request(net_p)

    def update_network_profile(self, context, net_profile_id, network_profile):
        """
        Update a network profile.

        :param context: neutron api request context
        :param net_profile_id: UUID of the network profile to update
        :param network_profile: dictionary containing network profile object
        """
        session = context.session
        with session.begin(subtransactions=True):
            net_p = (super(N1kvNeutronPluginV2, self).
                     update_network_profile(context,
                                            net_profile_id,
                                            network_profile))
        self._send_update_network_profile_request(net_p)
        return net_p

    def create_router(self, context, router):
        """
        Handle creation of router.

        Schedule router to L3 agent as part of the create handling.
        :param context: neutron api request context
        :param router: router dictionary
        :returns: router object
        """
        session = context.session
        with session.begin(subtransactions=True):
            rtr = (super(N1kvNeutronPluginV2, self).
                   create_router(context, router))
            LOG.debug(_("Scheduling router %s"), rtr['id'])
            self.schedule_router(context, rtr['id'])
        return rtr
