# Copyright (c) 2014 Cisco Systems
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
#


"""
ML2 Mechanism Driver for Cisco DFA platforms.
"""

import eventlet
from oslo.config import cfg

from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.dfa import cfg_profile_db_v2
from neutron.plugins.ml2.drivers.cisco.dfa import cisco_dfa_rest
from neutron.plugins.ml2.drivers.cisco.dfa import config
from neutron.plugins.ml2.drivers.cisco.dfa import constants as dfa_const
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_exceptions as dexc
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_instance_api
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_mech_driver_rpc as drpc
from neutron.plugins.ml2.drivers.cisco.dfa import project_events
from neutron.plugins.ml2.drivers.cisco.dfa import projects_cache_db_v2


LOG = logging.getLogger(__name__)


class SubnetObj(object):
    """Represents a subnet object.

    The information in the object will be used when creating a subnet on
    the DCNM.
    """
    def __init__(self, subnet):
        self.allocation_pools = subnet['allocation_pools']
        self.host_routes = subnet['host_routes']
        self.cidr = subnet['cidr']
        self.id = subnet['id']
        self.name = subnet['name']
        self.enable_dhcp = subnet['enable_dhcp']
        self.network_id = subnet['network_id']
        self.tenant_id = subnet['tenant_id']
        self.dns_nameservers = subnet['dns_nameservers']
        self.gateway_ip = subnet['gateway_ip']
        self.ip_version = subnet['ip_version']
        self.shared = subnet['shared']


class NetworkObj(object):
    """Represents a network object.

    The information in this object will be used when creating a network on
    the DCNM.
    """
    def __init__(self, net, segid, cfgp=None):
        self.provider__segmentation_id = segid
        self.tenant_id = net['tenant_id']
        self.name = net['name']
        self.config_profile = cfgp
        self.id = net['id']


class CiscoDfaMechanismDriver(api.MechanismDriver):
    """Cisco DFA ML2 Mechanism Driver."""

    def initialize(self):
        # Initialize the config
        self._dfa_cfg = config.CiscoDFAConfig().dfa_cfg

        # Initialize DCNM client.
        self._dcnm_client = cisco_dfa_rest.DFARESTClient()

        # Initialize project creation/deletion events object.
        # This will be used to get notification from keystone when
        # a tenant (i.e. project) is created or deleted.
        self._keys = project_events.EventsHandler('keystone',
                                                  self._dcnm_client)

        # Spawn a task, to process notification queue for keystone events.
        eventlet.spawn(self._process_keystone_events)

        # Initialize nova client wrapper. It will be used to get more
        # information for an instance.
        self._inst_api = dfa_instance_api.DFAInstanceAPI(cfg)

        # Initialize mechanism driver RPC.
        self._setup_mechdrv_rpc()

        # Initialize project info object.
        self.projects_cache_db_v2 = projects_cache_db_v2.ProjectsInfoCache()

        self._ctask_sleep_interval = 60

    def _get_agent_topic(self):
        """Read the mech_driver_agent section from the config file."""
        mech_drvr_rpc = self._dfa_cfg.get('mech_driver_rpc')
        if mech_drvr_rpc is None:
            return
        self._agent_topic = ''
        self._mech_drv_topic = ''
        for val in mech_drvr_rpc:
            if len(val) > 0:
                if val.split(':')[0] != dfa_const.CISCO_DFA_MECH_DRVR_NAME:
                    continue
                try:
                    self._mech_drv_topic = val.split(':')[1]
                    self._agent_topic = val.split(':')[2]
                except IndexError:
                    emsg = _('No topics is defined for %s mechanism driver')
                    LOG.error(emsg % dfa_const.CISCO_DFA_MECH_DRVR_NAME)
                    return

    def _setup_mechdrv_rpc(self):
        """Setup RPC for this mechanism driver."""
        self._get_agent_topic()
        if not self._agent_topic or not self._mech_drv_topic:
            LOG.debug('Mechanism Driver notifer is not initialized')
            return
        self.dfa_notifier = drpc.MechDriversAgentNotifierApi(topics.AGENT,
                                                             self._agent_topic)
        self.endpoints = [drpc.RpcCallbacks(self.dfa_notifier)]
        self.topic = self._mech_drv_topic
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    def _process_keystone_events(self):
        """Task to process notification from keystone.

        The handler processes events such as creation and deletion of projects
        sent by keystone.
        """
        self._keys.event_handler()

    def create_network_postcommit(self, context):
        # Check if the tenant is valid.
        projid = context.current.get('tenant_id')
        if not self._keys.is_valid_project(projid):
            return

        # Check if network id exists in the config profile DB. If not,
        # exception should be raised.
        net_id = context.current.get('id')
        res = cfg_profile_db_v2.get_network_profile_binding(
            context._plugin_context.session, net_id)
        if not res:
            cfgp_id = context.current.get(dfa_const.CONFIG_PROFILE_ID)
            msg = (_("Failed to create network. Config Profile id %s"
                     " does not exist.") % cfgp_id)
            raise n_exc.BadRequest(resource='network', msg=msg)

        # Get the project name. If project name does not exist, an exception
        # will be raised.
        self.projects_cache_db_v2.get_project_name(projid)

    def delete_network_postcommit(self, context):
        projid = context.current.get('tenant_id')
        if not self._keys.is_valid_project(projid):
            return

        segid = context.current.get('provider:segmentation_id')
        tenant_name = context._plugin_context.tenant_name
        net = NetworkObj(context.current, segid)
        try:
            self._dcnm_client.delete_network(tenant_name, net)
        except dexc.DFAClientRequestFailed as ex:
            emsg = _('Failed to create network %(net)s. Error:%(err)s.')
            LOG.error(emsg % {'net': net.name, 'err': ex})
            raise ml2_exc.MechanismDriverError

    def create_subnet_postcommit(self, context):
        projid = context.current.get('tenant_id')
        if not self._keys.is_valid_project(projid):
            return

        subnet = context.current
        if subnet['name'] == 'private-subnet':
            emsg = _("%s is default subnet and no need to create it in DCNM.")
            LOG.info(emsg % subnet['name'])
            return

        session = context._plugin_context.session
        netid = context.current['network_id']
        network_entry = cfg_profile_db_v2.get_network_entry(session, netid)
        tenant_name = context._plugin_context.tenant_name
        segid = self.projects_cache_db_v2.get_network_segid(netid)
        cfgp_name = cfg_profile_db_v2.get_config_profile_name(session, netid)
        snet = SubnetObj(context.current)
        net = NetworkObj(network_entry, int(segid), cfgp_name)
        try:
            self._dcnm_client.create_network(tenant_name, net, snet)
        except dexc.DFAClientRequestFailed as ex:
            emsg = _('Failed to create network %(net)s. Error:%(err)s.')
            LOG.error(emsg % {'net': net.name, 'err': ex})
            raise ml2_exc.MechanismDriverError

    def update_port_postcommit(self, context):
        projid = context.current.get('tenant_id')
        if not self._keys.is_valid_project(projid):
            return

        session = context._plugin_context.session
        self.device_id = context.current.get('device_id').replace('-', '')
        tenant_id = context.current.get('tenant_id')
        netid = context.current.get('network_id')
        self.inst_name = self._inst_api.get_instance_for_uuid(self.device_id,
                                                              tenant_id)
        self.fwd_mode = cfg_profile_db_v2.get_config_profile_fwd_mode(session,
                                                                      netid)
        self.segid = self.projects_cache_db_v2.get_network_segid(netid)
        self.mac = context.current.get('mac_address')
        self.ip = (context.current.get('fixed_ips')[0]['ip_address']
                   if context.current.get('fixed_ips') else None)

        vm_info = {
            'status': 'up',
            'ip': self.ip,
            'mac': self.mac,
            'segid': self.segid,
            'inst_name': self.inst_name,
            'inst_uuid': self.device_id,
            'host': context.current.get(portbindings.HOST_ID),
            'port_id': context.current.get('id'),
            'network_id': context.current.get('network_id'),
            'oui_type': 'cisco',
        }
        if self.inst_name:
            self.dfa_notifier.send_vm_info(context._plugin_context, vm_info)
        LOG.debug("update_port_postcommit : %s" % vm_info)

    def delete_port_postcommit(self, context):
        session = context._plugin_context.session
        self.device_id = context.current.get('device_id').replace('-', '')
        tenant_id = context.current.get('tenant_id')
        netid = context.current.get('network_id')
        self.inst_name = self._inst_api.get_instance_for_uuid(self.device_id,
                                                              tenant_id)
        self.fwd_mode = cfg_profile_db_v2.get_config_profile_fwd_mode(session,
                                                                      netid)
        self.segid = self.projects_cache_db_v2.get_network_segid(netid)
        self.mac = context.current.get('mac_address')
        self.ip = (context.current.get('fixed_ips')[0]['ip_address']
                   if context.current.get('fixed_ips') else None)

        vm_info = {
            'status': 'down',
            'ip': self.ip,
            'mac': self.mac,
            'segid': self.segid,
            'inst_name': self.inst_name,
            'inst_uuid': self.device_id,
            'host': context.current.get(portbindings.HOST_ID),
            'port_id': context.current.get('id'),
            'network_id': context.current.get('network_id'),
            'oui_type': 'cisco',
        }
        if self.inst_name:
            self.dfa_notifier.send_vm_info(context._plugin_context, vm_info)
        LOG.debug("delete_port_postcommit : %s" % vm_info)
