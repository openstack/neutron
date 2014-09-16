# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

import random

from keystoneclient import exceptions as k_exceptions
from keystoneclient.v2_0 import client as k_client
from oslo.config import cfg
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload

from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron import context as neutron_context
from neutron.db import agents_db
from neutron import manager
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import timeutils
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.common import cisco_constants as c_constants
from neutron.plugins.cisco.db.l3 import l3_models
from neutron.plugins.cisco.l3 import service_vm_lib
from neutron.plugins.common import constants as svc_constants

LOG = logging.getLogger(__name__)


DEVICE_HANDLING_OPTS = [
    cfg.StrOpt('l3_admin_tenant', default='L3AdminTenant',
               help=_('Name of the L3 admin tenant.')),
    cfg.StrOpt('management_network', default='osn_mgmt_nw',
               help=_('Name of management network for device configuration. '
                      'Default value is osn_mgmt_nw')),
    cfg.StrOpt('default_security_group', default='mgmt_sec_grp',
               help=_('Default security group applied on management port. '
                      'Default value is mgmt_sec_grp.')),
    cfg.IntOpt('cfg_agent_down_time', default=60,
               help=_('Seconds of no status update until a cfg agent '
                      'is considered down.')),
    cfg.BoolOpt('ensure_nova_running', default=True,
                help=_('Ensure that Nova is running before attempting to '
                       'create any VM.'))
]

CSR1KV_OPTS = [
    cfg.StrOpt('csr1kv_image', default='csr1kv_openstack_img',
               help=_('Name of Glance image for CSR1kv.')),
    cfg.StrOpt('csr1kv_flavor', default=621,
               help=_('UUID of Nova flavor for CSR1kv.')),
    cfg.StrOpt('csr1kv_plugging_driver',
               default=('neutron.plugins.cisco.l3.plugging_drivers.'
                        'n1kv_trunking_driver.N1kvTrunkingPlugDriver'),
               help=_('Plugging driver for CSR1kv.')),
    cfg.StrOpt('csr1kv_device_driver',
               default=('neutron.plugins.cisco.l3.hosting_device_drivers.'
                        'csr1kv_hd_driver.CSR1kvHostingDeviceDriver'),
               help=_('Hosting device driver for CSR1kv.')),
    cfg.StrOpt('csr1kv_cfgagent_router_driver',
               default=('neutron.plugins.cisco.cfg_agent.device_drivers.'
                        'csr1kv.csr1kv_routing_driver.CSR1kvRoutingDriver'),
               help=_('Config agent driver for CSR1kv.')),
    cfg.IntOpt('csr1kv_booting_time', default=420,
               help=_('Booting time in seconds before a CSR1kv '
                      'becomes operational.')),
    cfg.StrOpt('csr1kv_username', default='stack',
               help=_('Username to use for CSR1kv configurations.')),
    cfg.StrOpt('csr1kv_password', default='cisco',
               help=_('Password to use for CSR1kv configurations.'))
]

cfg.CONF.register_opts(DEVICE_HANDLING_OPTS, "general")
cfg.CONF.register_opts(CSR1KV_OPTS, "hosting_devices")


class DeviceHandlingMixin(object):
    """A class implementing some functionality to handle devices."""

    # The all-mighty tenant owning all hosting devices
    _l3_tenant_uuid = None
    # The management network for hosting devices
    _mgmt_nw_uuid = None
    _mgmt_sec_grp_id = None

    # Loaded driver modules for CSR1kv
    _hosting_device_driver = None
    _plugging_driver = None

    # Service VM manager object that interacts with Nova
    _svc_vm_mgr = None

    # Flag indicating is needed Nova services are reported as up.
    _nova_running = False

    @classmethod
    def l3_tenant_id(cls):
        """Returns id of tenant owning hosting device resources."""
        if cls._l3_tenant_uuid is None:
            auth_url = cfg.CONF.keystone_authtoken.identity_uri + "/v2.0"
            user = cfg.CONF.keystone_authtoken.admin_user
            pw = cfg.CONF.keystone_authtoken.admin_password
            tenant = cfg.CONF.keystone_authtoken.admin_tenant_name
            keystone = k_client.Client(username=user, password=pw,
                                       tenant_name=tenant,
                                       auth_url=auth_url)
            try:
                tenant = keystone.tenants.find(
                    name=cfg.CONF.general.l3_admin_tenant)
                cls._l3_tenant_uuid = tenant.id
            except k_exceptions.NotFound:
                LOG.error(_('No tenant with a name or ID of %s exists.'),
                          cfg.CONF.general.l3_admin_tenant)
            except k_exceptions.NoUniqueMatch:
                LOG.error(_('Multiple tenants matches found for %s'),
                          cfg.CONF.general.l3_admin_tenant)
        return cls._l3_tenant_uuid

    @classmethod
    def mgmt_nw_id(cls):
        """Returns id of the management network."""
        if cls._mgmt_nw_uuid is None:
            tenant_id = cls.l3_tenant_id()
            if not tenant_id:
                return
            net = manager.NeutronManager.get_plugin().get_networks(
                neutron_context.get_admin_context(),
                {'tenant_id': [tenant_id],
                 'name': [cfg.CONF.general.management_network]},
                ['id', 'subnets'])
            if len(net) == 1:
                num_subnets = len(net[0]['subnets'])
                if num_subnets == 0:
                    LOG.error(_('The virtual management network has no '
                                'subnet. Please assign one.'))
                    return
                elif num_subnets > 1:
                    LOG.info(_('The virtual management network has %d '
                               'subnets. The first one will be used.'),
                             num_subnets)
                cls._mgmt_nw_uuid = net[0].get('id')
            elif len(net) > 1:
                # Management network must have a unique name.
                LOG.error(_('The virtual management network does not have '
                            'unique name. Please ensure that it is.'))
            else:
                # Management network has not been created.
                LOG.error(_('There is no virtual management network. Please '
                            'create one.'))
        return cls._mgmt_nw_uuid

    @classmethod
    def mgmt_sec_grp_id(cls):
        """Returns id of security group used by the management network."""
        if not utils.is_extension_supported(
                manager.NeutronManager.get_plugin(), "security-group"):
            return
        if cls._mgmt_sec_grp_id is None:
            # Get the id for the _mgmt_security_group_id
            tenant_id = cls.l3_tenant_id()
            res = manager.NeutronManager.get_plugin().get_security_groups(
                neutron_context.get_admin_context(),
                {'tenant_id': [tenant_id],
                 'name': [cfg.CONF.general.default_security_group]},
                ['id'])
            if len(res) == 1:
                cls._mgmt_sec_grp_id = res[0].get('id')
            elif len(res) > 1:
                # the mgmt sec group must be unique.
                LOG.error(_('The security group for the virtual management '
                            'network does not have unique name. Please ensure '
                            'that it is.'))
            else:
                # CSR Mgmt security group is not present.
                LOG.error(_('There is no security group for the virtual '
                            'management network. Please create one.'))
        return cls._mgmt_sec_grp_id

    @classmethod
    def get_hosting_device_driver(self):
        """Returns device driver."""
        if self._hosting_device_driver:
            return self._hosting_device_driver
        else:
            try:
                self._hosting_device_driver = importutils.import_object(
                    cfg.CONF.hosting_devices.csr1kv_device_driver)
            except (ImportError, TypeError, n_exc.NeutronException):
                LOG.exception(_('Error loading hosting device driver'))
            return self._hosting_device_driver

    @classmethod
    def get_hosting_device_plugging_driver(self):
        """Returns  plugging driver."""
        if self._plugging_driver:
            return self._plugging_driver
        else:
            try:
                self._plugging_driver = importutils.import_object(
                    cfg.CONF.hosting_devices.csr1kv_plugging_driver)
            except (ImportError, TypeError, n_exc.NeutronException):
                LOG.exception(_('Error loading plugging driver'))
            return self._plugging_driver

    def get_hosting_devices_qry(self, context, hosting_device_ids,
                                load_agent=True):
        """Returns hosting devices with <hosting_device_ids>."""
        query = context.session.query(l3_models.HostingDevice)
        if load_agent:
            query = query.options(joinedload('cfg_agent'))
        if len(hosting_device_ids) > 1:
            query = query.filter(l3_models.HostingDevice.id.in_(
                hosting_device_ids))
        else:
            query = query.filter(l3_models.HostingDevice.id ==
                                 hosting_device_ids[0])
        return query

    def handle_non_responding_hosting_devices(self, context, host,
                                              hosting_device_ids):
        with context.session.begin(subtransactions=True):
            e_context = context.elevated()
            hosting_devices = self.get_hosting_devices_qry(
                e_context, hosting_device_ids).all()
            # 'hosting_info' is dictionary with ids of removed hosting
            # devices and the affected logical resources for each
            # removed hosting device:
            #    {'hd_id1': {'routers': [id1, id2, ...],
            #                'fw': [id1, ...],
            #                 ...},
            #     'hd_id2': {'routers': [id3, id4, ...]},
            #                'fw': [id1, ...],
            #                ...},
            #     ...}
            hosting_info = dict((id, {}) for id in hosting_device_ids)
            try:
                #TODO(bobmel): Modify so service plugins register themselves
                self._handle_non_responding_hosting_devices(
                    context, hosting_devices, hosting_info)
            except AttributeError:
                pass
            for hd in hosting_devices:
                if not self._process_non_responsive_hosting_device(e_context,
                                                                   hd):
                    # exclude this device since we did not remove it
                    del hosting_info[hd['id']]
            self.l3_cfg_rpc_notifier.hosting_devices_removed(
                context, hosting_info, False, host)

    def get_device_info_for_agent(self, hosting_device):
        """Returns information about <hosting_device> needed by config agent.

            Convenience function that service plugins can use to populate
            their resources with information about the device hosting their
            logical resource.
        """
        credentials = {'username': cfg.CONF.hosting_devices.csr1kv_username,
                       'password': cfg.CONF.hosting_devices.csr1kv_password}
        mgmt_ip = (hosting_device.management_port['fixed_ips'][0]['ip_address']
                   if hosting_device.management_port else None)
        return {'id': hosting_device.id,
                'credentials': credentials,
                'management_ip_address': mgmt_ip,
                'protocol_port': hosting_device.protocol_port,
                'created_at': str(hosting_device.created_at),
                'booting_time': cfg.CONF.hosting_devices.csr1kv_booting_time,
                'cfg_agent_id': hosting_device.cfg_agent_id}

    @classmethod
    def is_agent_down(cls, heart_beat_time,
                      timeout=cfg.CONF.general.cfg_agent_down_time):
        return timeutils.is_older_than(heart_beat_time, timeout)

    def get_cfg_agents_for_hosting_devices(self, context, hosting_device_ids,
                                           admin_state_up=None, active=None,
                                           schedule=False):
        if not hosting_device_ids:
            return []
        query = self.get_hosting_devices_qry(context, hosting_device_ids)
        if admin_state_up is not None:
            query = query.filter(
                agents_db.Agent.admin_state_up == admin_state_up)
        if schedule:
            agents = []
            for hosting_device in query:
                if hosting_device.cfg_agent is None:
                    agent = self._select_cfgagent(context, hosting_device)
                    if agent is not None:
                        agents.append(agent)
                else:
                    agents.append(hosting_device.cfg_agent)
        else:
            agents = [hosting_device.cfg_agent for hosting_device in query
                      if hosting_device.cfg_agent is not None]
        if active is not None:
            agents = [agent for agent in agents if not
                      self.is_agent_down(agent['heartbeat_timestamp'])]
        return agents

    def auto_schedule_hosting_devices(self, context, agent_host):
        """Schedules unassociated hosting devices to Cisco cfg agent.

        Schedules hosting devices to agent running on <agent_host>.
        """
        with context.session.begin(subtransactions=True):
            # Check if there is a valid Cisco cfg agent on the host
            query = context.session.query(agents_db.Agent)
            query = query.filter_by(agent_type=c_constants.AGENT_TYPE_CFG,
                                    host=agent_host, admin_state_up=True)
            try:
                cfg_agent = query.one()
            except (exc.MultipleResultsFound, exc.NoResultFound):
                LOG.debug('No enabled Cisco cfg agent on host %s',
                          agent_host)
                return False
            if self.is_agent_down(
                    cfg_agent.heartbeat_timestamp):
                LOG.warn(_('Cisco cfg agent %s is not alive'), cfg_agent.id)
            query = context.session.query(l3_models.HostingDevice)
            query = query.filter_by(cfg_agent_id=None)
            for hd in query:
                hd.cfg_agent = cfg_agent
                context.session.add(hd)
            return True

    def _setup_device_handling(self):
        auth_url = cfg.CONF.keystone_authtoken.identity_uri + "/v2.0"
        u_name = cfg.CONF.keystone_authtoken.admin_user
        pw = cfg.CONF.keystone_authtoken.admin_password
        tenant = cfg.CONF.general.l3_admin_tenant
        self._svc_vm_mgr = service_vm_lib.ServiceVMManager(
            user=u_name, passwd=pw, l3_admin_tenant=tenant, auth_url=auth_url)

    def _process_non_responsive_hosting_device(self, context, hosting_device):
        """Host type specific processing of non responsive hosting devices.

        :param hosting_device: db object for hosting device
        :return: True if hosting_device has been deleted, otherwise False
        """

        self._delete_service_vm_hosting_device(context, hosting_device)
        return True

    def _create_csr1kv_vm_hosting_device(self, context):
        """Creates a CSR1kv VM instance."""
        # Note(bobmel): Nova does not handle VM dispatching well before all
        # its services have started. This creates problems for the Neutron
        # devstack script that creates a Neutron router, which in turn
        # triggers service VM dispatching.
        # Only perform pool maintenance if needed Nova services have started
        if (cfg.CONF.general.ensure_nova_running and not self._nova_running):
            if self._svc_vm_mgr.nova_services_up():
                self.__class__._nova_running = True
            else:
                LOG.info(_('Not all Nova services are up and running. '
                           'Skipping this CSR1kv vm create request.'))
                return
        plugging_drv = self.get_hosting_device_plugging_driver()
        hosting_device_drv = self.get_hosting_device_driver()
        if plugging_drv is None or hosting_device_drv is None:
            return
        # These resources are owned by the L3AdminTenant
        complementary_id = uuidutils.generate_uuid()
        dev_data = {'complementary_id': complementary_id,
                    'device_id': 'CSR1kv',
                    'admin_state_up': True,
                    'protocol_port': 22,
                    'created_at': timeutils.utcnow()}
        res = plugging_drv.create_hosting_device_resources(
            context, complementary_id, self.l3_tenant_id(),
            self.mgmt_nw_id(), self.mgmt_sec_grp_id(), 1)
        if res.get('mgmt_port') is None:
            # Required ports could not be created
            return
        vm_instance = self._svc_vm_mgr.dispatch_service_vm(
            context, 'CSR1kv_nrouter', cfg.CONF.hosting_devices.csr1kv_image,
            cfg.CONF.hosting_devices.csr1kv_flavor, hosting_device_drv,
            res['mgmt_port'], res.get('ports'))
        with context.session.begin(subtransactions=True):
            if vm_instance is not None:
                dev_data.update(
                    {'id': vm_instance['id'],
                     'management_port_id': res['mgmt_port']['id']})
                hosting_device = self._create_hosting_device(
                    context, {'hosting_device': dev_data})
            else:
                # Fundamental error like could not contact Nova
                # Cleanup anything we created
                plugging_drv.delete_hosting_device_resources(
                    context, self.l3_tenant_id(), **res)
                return
        LOG.info(_('Created a CSR1kv hosting device VM'))
        return hosting_device

    def _delete_service_vm_hosting_device(self, context, hosting_device):
        """Deletes a <hosting_device> service VM.

        This will indirectly make all of its hosted resources unscheduled.
        """
        if hosting_device is None:
            return
        plugging_drv = self.get_hosting_device_plugging_driver()
        if plugging_drv is None:
            return
        res = plugging_drv.get_hosting_device_resources(
            context, hosting_device['id'], hosting_device['complementary_id'],
            self.l3_tenant_id(), self.mgmt_nw_id())
        if not self._svc_vm_mgr.delete_service_vm(context,
                                                  hosting_device['id']):
            LOG.error(_('Failed to delete hosting device %s service VM. '
                        'Will un-register it anyway.'),
                      hosting_device['id'])
        plugging_drv.delete_hosting_device_resources(
            context, self.l3_tenant_id(), **res)
        with context.session.begin(subtransactions=True):
            context.session.delete(hosting_device)

    def _create_hosting_device(self, context, hosting_device):
        LOG.debug('create_hosting_device() called')
        hd = hosting_device['hosting_device']
        tenant_id = self._get_tenant_id_for_create(context, hd)
        with context.session.begin(subtransactions=True):
            hd_db = l3_models.HostingDevice(
                id=hd.get('id') or uuidutils.generate_uuid(),
                complementary_id = hd.get('complementary_id'),
                tenant_id=tenant_id,
                device_id=hd.get('device_id'),
                admin_state_up=hd.get('admin_state_up', True),
                management_port_id=hd['management_port_id'],
                protocol_port=hd.get('protocol_port'),
                cfg_agent_id=hd.get('cfg_agent_id'),
                created_at=hd.get('created_at', timeutils.utcnow()),
                status=hd.get('status', svc_constants.ACTIVE))
            context.session.add(hd_db)
        return hd_db

    def _select_cfgagent(self, context, hosting_device):
        """Selects Cisco cfg agent that will configure <hosting_device>."""
        if not hosting_device:
            LOG.debug('Hosting device to schedule not specified')
            return
        elif hosting_device.cfg_agent:
            LOG.debug('Hosting device %(hd_id)s has already been '
                      'assigned to Cisco cfg agent %(agent_id)s',
                      {'hd_id': id,
                       'agent_id': hosting_device.cfg_agent.id})
            return
        with context.session.begin(subtransactions=True):
            active_cfg_agents = self._get_cfg_agents(context, active=True)
            if not active_cfg_agents:
                LOG.warn(_('There are no active Cisco cfg agents'))
                # No worries, once a Cisco cfg agent is started and
                # announces itself any "dangling" hosting devices
                # will be scheduled to it.
                return
            chosen_agent = random.choice(active_cfg_agents)
            hosting_device.cfg_agent = chosen_agent
            context.session.add(hosting_device)
            return chosen_agent

    def _get_cfg_agents(self, context, active=None, filters=None):
        query = context.session.query(agents_db.Agent)
        query = query.filter(
            agents_db.Agent.agent_type == c_constants.AGENT_TYPE_CFG)
        if active is not None:
            query = (query.filter(agents_db.Agent.admin_state_up == active))
        if filters:
            for key, value in filters.iteritems():
                column = getattr(agents_db.Agent, key, None)
                if column:
                    query = query.filter(column.in_(value))
        cfg_agents = query.all()
        if active is not None:
            cfg_agents = [cfg_agent for cfg_agent in cfg_agents
                          if not self.is_agent_down(
                              cfg_agent['heartbeat_timestamp'])]
        return cfg_agents
