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

import abc
import collections
import requests

from oslo.config import cfg
from oslo import messaging
import six

from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron import context as ctx
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants
from neutron.plugins.common import utils as plugin_utils
from neutron.services.vpn.common import topics
from neutron.services.vpn import device_drivers
from neutron.services.vpn.device_drivers import (
    cisco_csr_rest_client as csr_client)


ipsec_opts = [
    cfg.IntOpt('status_check_interval',
               default=60,
               help=_("Status check interval for Cisco CSR IPSec connections"))
]
cfg.CONF.register_opts(ipsec_opts, 'cisco_csr_ipsec')

LOG = logging.getLogger(__name__)

RollbackStep = collections.namedtuple('RollbackStep',
                                      ['action', 'resource_id', 'title'])


class CsrResourceCreateFailure(exceptions.NeutronException):
    message = _("Cisco CSR failed to create %(resource)s (%(which)s)")


class CsrAdminStateChangeFailure(exceptions.NeutronException):
    message = _("Cisco CSR failed to change %(tunnel)s admin state to "
                "%(state)s")


class CsrDriverMismatchError(exceptions.NeutronException):
    message = _("Required %(resource)s attribute %(attr)s mapping for Cisco "
                "CSR is missing in device driver")


class CsrUnknownMappingError(exceptions.NeutronException):
    message = _("Device driver does not have a mapping of '%(value)s for "
                "attribute %(attr)s of %(resource)s")


class CiscoCsrIPsecVpnDriverApi(n_rpc.RpcProxy):
    """RPC API for agent to plugin messaging."""

    def get_vpn_services_on_host(self, context, host):
        """Get list of vpnservices on this host.

        The vpnservices including related ipsec_site_connection,
        ikepolicy, ipsecpolicy, and Cisco info on this host.
        """
        return self.call(context,
                         self.make_msg('get_vpn_services_on_host',
                                       host=host))

    def update_status(self, context, status):
        """Update status for all VPN services and connections."""
        return self.cast(context,
                         self.make_msg('update_status',
                                       status=status))


@six.add_metaclass(abc.ABCMeta)
class CiscoCsrIPsecDriver(device_drivers.DeviceDriver):
    """Cisco CSR VPN Device Driver for IPSec.

    This class is designed for use with L3-agent now.
    However this driver will be used with another agent in future.
    so the use of "Router" is kept minimul now.
    Instead of router_id,  we are using process_id in this code.
    """

    # history
    #   1.0 Initial version
    RPC_API_VERSION = '1.0'

    # TODO(ihrachys): we can't use RpcCallback here due to inheritance
    # issues
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, agent, host):
        self.host = host
        self.conn = n_rpc.create_connection(new=True)
        context = ctx.get_admin_context_without_session()
        node_topic = '%s.%s' % (topics.CISCO_IPSEC_AGENT_TOPIC, self.host)

        self.service_state = {}

        self.endpoints = [self]
        self.conn.create_consumer(node_topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = (
            CiscoCsrIPsecVpnDriverApi(topics.CISCO_IPSEC_DRIVER_TOPIC, '1.0'))
        self.periodic_report = loopingcall.FixedIntervalLoopingCall(
            self.report_status, context)
        self.periodic_report.start(
            interval=agent.conf.cisco_csr_ipsec.status_check_interval)
        LOG.debug("Device driver initialized for %s", node_topic)

    def vpnservice_updated(self, context, **kwargs):
        """Handle VPNaaS service driver change notifications."""
        LOG.debug(_("Handling VPN service update notification '%s'"),
                  kwargs.get('reason', ''))
        self.sync(context, [])

    def create_vpn_service(self, service_data):
        """Create new entry to track VPN service and its connections."""
        csr = csr_client.CsrRestClient(service_data['router_info'])
        vpn_service_id = service_data['id']
        self.service_state[vpn_service_id] = CiscoCsrVpnService(
            service_data, csr)
        return self.service_state[vpn_service_id]

    def update_connection(self, context, vpn_service_id, conn_data):
        """Handle notification for a single IPSec connection."""
        vpn_service = self.service_state[vpn_service_id]
        conn_id = conn_data['id']
        conn_is_admin_up = conn_data[u'admin_state_up']

        if conn_id in vpn_service.conn_state:  # Existing connection...
            ipsec_conn = vpn_service.conn_state[conn_id]
            config_changed = ipsec_conn.check_for_changes(conn_data)
            if config_changed:
                LOG.debug(_("Update: Existing connection %s changed"), conn_id)
                ipsec_conn.delete_ipsec_site_connection(context, conn_id)
                ipsec_conn.create_ipsec_site_connection(context, conn_data)
                ipsec_conn.conn_info = conn_data

            if ipsec_conn.forced_down:
                if vpn_service.is_admin_up and conn_is_admin_up:
                    LOG.debug(_("Update: Connection %s no longer admin down"),
                              conn_id)
                    ipsec_conn.set_admin_state(is_up=True)
                    ipsec_conn.forced_down = False
            else:
                if not vpn_service.is_admin_up or not conn_is_admin_up:
                    LOG.debug(_("Update: Connection %s forced to admin down"),
                              conn_id)
                    ipsec_conn.set_admin_state(is_up=False)
                    ipsec_conn.forced_down = True
        else:  # New connection...
            ipsec_conn = vpn_service.create_connection(conn_data)
            ipsec_conn.create_ipsec_site_connection(context, conn_data)
            if not vpn_service.is_admin_up or not conn_is_admin_up:
                LOG.debug(_("Update: Created new connection %s in admin down "
                            "state"), conn_id)
                ipsec_conn.set_admin_state(is_up=False)
                ipsec_conn.forced_down = True
            else:
                LOG.debug(_("Update: Created new connection %s"), conn_id)

        ipsec_conn.is_dirty = False
        ipsec_conn.last_status = conn_data['status']
        ipsec_conn.is_admin_up = conn_is_admin_up
        return ipsec_conn

    def update_service(self, context, service_data):
        """Handle notification for a single VPN Service and its connections."""
        vpn_service_id = service_data['id']
        if vpn_service_id in self.service_state:
            LOG.debug(_("Update: Existing VPN service %s detected"),
                      vpn_service_id)
            vpn_service = self.service_state[vpn_service_id]
        else:
            LOG.debug(_("Update: New VPN service %s detected"), vpn_service_id)
            vpn_service = self.create_vpn_service(service_data)
            if not vpn_service:
                return

        vpn_service.is_dirty = False
        vpn_service.connections_removed = False
        vpn_service.last_status = service_data['status']
        vpn_service.is_admin_up = service_data[u'admin_state_up']
        for conn_data in service_data['ipsec_conns']:
            self.update_connection(context, vpn_service_id, conn_data)
        LOG.debug(_("Update: Completed update processing"))
        return vpn_service

    def update_all_services_and_connections(self, context):
        """Update services and connections based on plugin info.

        Perform any create and update operations and then update status.
        Mark every visited connection as no longer "dirty" so they will
        not be deleted at end of sync processing.
        """
        services_data = self.agent_rpc.get_vpn_services_on_host(context,
                                                                self.host)
        LOG.debug("Sync updating for %d VPN services", len(services_data))
        vpn_services = []
        for service_data in services_data:
            vpn_service = self.update_service(context, service_data)
            if vpn_service:
                vpn_services.append(vpn_service)
        return vpn_services

    def mark_existing_connections_as_dirty(self):
        """Mark all existing connections as "dirty" for sync."""
        service_count = 0
        connection_count = 0
        for service_state in self.service_state.values():
            service_state.is_dirty = True
            service_count += 1
            for conn_id in service_state.conn_state:
                service_state.conn_state[conn_id].is_dirty = True
                connection_count += 1
        LOG.debug(_("Mark: %(service)d VPN services and %(conn)d IPSec "
                    "connections marked dirty"), {'service': service_count,
                                                  'conn': connection_count})

    def remove_unknown_connections(self, context):
        """Remove connections that are not known by service driver."""
        service_count = 0
        connection_count = 0
        for vpn_service_id, vpn_service in self.service_state.items():
            dirty = [c_id for c_id, c in vpn_service.conn_state.items()
                     if c.is_dirty]
            vpn_service.connections_removed = len(dirty) > 0
            for conn_id in dirty:
                conn_state = vpn_service.conn_state[conn_id]
                conn_state.delete_ipsec_site_connection(context, conn_id)
                connection_count += 1
                del vpn_service.conn_state[conn_id]
            if vpn_service.is_dirty:
                service_count += 1
                del self.service_state[vpn_service_id]
            elif dirty:
                self.connections_removed = True
        LOG.debug(_("Sweep: Removed %(service)d dirty VPN service%(splural)s "
                    "and %(conn)d dirty IPSec connection%(cplural)s"),
                  {'service': service_count, 'conn': connection_count,
                   'splural': 's'[service_count == 1:],
                   'cplural': 's'[connection_count == 1:]})

    def build_report_for_connections_on(self, vpn_service):
        """Create the report fragment for IPSec connections on a service.

        Collect the current status from the Cisco CSR and use that to update
        the status and generate report fragment for each connection on the
        service. If there is no status information, or no change, then no
        report info will be created for the connection. The combined report
        data is returned.
        """
        LOG.debug(_("Report: Collecting status for IPSec connections on VPN "
                    "service %s"), vpn_service.service_id)
        tunnels = vpn_service.get_ipsec_connections_status()
        report = {}
        for connection in vpn_service.conn_state.values():
            if connection.forced_down:
                LOG.debug(_("Connection %s forced down"), connection.conn_id)
                current_status = constants.DOWN
            else:
                current_status = connection.find_current_status_in(tunnels)
                LOG.debug(_("Connection %(conn)s reported %(status)s"),
                          {'conn': connection.conn_id,
                           'status': current_status})
            frag = connection.update_status_and_build_report(current_status)
            if frag:
                LOG.debug(_("Report: Adding info for IPSec connection %s"),
                          connection.conn_id)
                report.update(frag)
        return report

    def build_report_for_service(self, vpn_service):
        """Create the report info for a VPN service and its IPSec connections.

        Get the report info for the connections on the service, and include
        it into the report info for the VPN service. If there is no report
        info for the connection, then no change has occurred and no report
        will be generated. If there is only one connection for the service,
        we'll set the service state to match the connection (with ERROR seen
        as DOWN).
        """
        conn_report = self.build_report_for_connections_on(vpn_service)
        if conn_report or vpn_service.connections_removed:
            pending_handled = plugin_utils.in_pending_status(
                vpn_service.last_status)
            vpn_service.update_last_status()
            LOG.debug(_("Report: Adding info for VPN service %s"),
                      vpn_service.service_id)
            return {u'id': vpn_service.service_id,
                    u'status': vpn_service.last_status,
                    u'updated_pending_status': pending_handled,
                    u'ipsec_site_connections': conn_report}
        else:
            return {}

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def report_status(self, context):
        """Report status of all VPN services and IPSec connections to plugin.

        This is called periodically by the agent, to push up changes in
        status. Use a lock to serialize access to (and changing of)
        running state.
        """
        return self.report_status_internal(context)

    def report_status_internal(self, context):
        """Generate report and send to plugin, if anything changed."""
        service_report = []
        LOG.debug(_("Report: Starting status report processing"))
        for vpn_service_id, vpn_service in self.service_state.items():
            LOG.debug(_("Report: Collecting status for VPN service %s"),
                      vpn_service_id)
            report = self.build_report_for_service(vpn_service)
            if report:
                service_report.append(report)
        if service_report:
            LOG.info(_("Sending status report update to plugin"))
            self.agent_rpc.update_status(context, service_report)
        LOG.debug(_("Report: Completed status report processing"))
        return service_report

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, routers):
        """Synchronize with plugin and report current status.

        Mark all "known" services/connections as dirty, update them based on
        information from the plugin, remove (sweep) any connections that are
        not updated (dirty), and report updates, if any, back to plugin.
        Called when update/delete a service or create/update/delete a
        connection (vpnservice_updated message), or router change
        (_process_routers).

        Use lock to serialize access (and changes) to running state for VPN
        service and IPsec connections.
        """
        self.mark_existing_connections_as_dirty()
        self.update_all_services_and_connections(context)
        self.remove_unknown_connections(context)
        self.report_status_internal(context)

    def create_router(self, process_id):
        """Actions taken when router created."""
        # Note: Since Cisco CSR is running out-of-band, nothing to do here
        pass

    def destroy_router(self, process_id):
        """Actions taken when router deleted."""
        # Note: Since Cisco CSR is running out-of-band, nothing to do here
        pass


class CiscoCsrVpnService(object):

    """Maintains state/status information for a service and its connections."""

    def __init__(self, service_data, csr):
        self.service_id = service_data['id']
        self.conn_state = {}
        self.csr = csr
        self.is_admin_up = True
        # TODO(pcm) FUTURE - handle sharing of policies

    def create_connection(self, conn_data):
        conn_id = conn_data['id']
        self.conn_state[conn_id] = CiscoCsrIPSecConnection(conn_data, self.csr)
        return self.conn_state[conn_id]

    def get_connection(self, conn_id):
        return self.conn_state.get(conn_id)

    def conn_status(self, conn_id):
        conn_state = self.get_connection(conn_id)
        if conn_state:
            return conn_state.last_status

    def snapshot_conn_state(self, ipsec_conn):
        """Create/obtain connection state and save current status."""
        conn_state = self.conn_state.setdefault(
            ipsec_conn['id'], CiscoCsrIPSecConnection(ipsec_conn, self.csr))
        conn_state.last_status = ipsec_conn['status']
        conn_state.is_dirty = False
        return conn_state

    STATUS_MAP = {'ERROR': constants.ERROR,
                  'UP-ACTIVE': constants.ACTIVE,
                  'UP-IDLE': constants.ACTIVE,
                  'UP-NO-IKE': constants.ACTIVE,
                  'DOWN': constants.DOWN,
                  'DOWN-NEGOTIATING': constants.DOWN}

    def get_ipsec_connections_status(self):
        """Obtain current status of all tunnels on a Cisco CSR.

        Convert them to OpenStack status values.
        """
        tunnels = self.csr.read_tunnel_statuses()
        for tunnel in tunnels:
            LOG.debug("CSR Reports %(tunnel)s status '%(status)s'",
                      {'tunnel': tunnel[0], 'status': tunnel[1]})
        return dict(map(lambda x: (x[0], self.STATUS_MAP[x[1]]), tunnels))

    def find_matching_connection(self, tunnel_id):
        """Find IPSec connection using Cisco CSR tunnel specified, if any."""
        for connection in self.conn_state.values():
            if connection.tunnel == tunnel_id:
                return connection.conn_id

    def no_connections_up(self):
        return not any(c.last_status == 'ACTIVE'
                       for c in self.conn_state.values())

    def update_last_status(self):
        if not self.is_admin_up or self.no_connections_up():
            self.last_status = constants.DOWN
        else:
            self.last_status = constants.ACTIVE


class CiscoCsrIPSecConnection(object):

    """State and actions for IPSec site-to-site connections."""

    def __init__(self, conn_info, csr):
        self.conn_info = conn_info
        self.csr = csr
        self.steps = []
        self.forced_down = False
        self.changed = False

    @property
    def conn_id(self):
        return self.conn_info['id']

    @property
    def is_admin_up(self):
        return self.conn_info['admin_state_up']

    @is_admin_up.setter
    def is_admin_up(self, is_up):
        self.conn_info['admin_state_up'] = is_up

    @property
    def tunnel(self):
        return self.conn_info['cisco']['site_conn_id']

    def check_for_changes(self, curr_conn):
        return not all([self.conn_info[attr] == curr_conn[attr]
                        for attr in ('mtu', 'psk', 'peer_address',
                                     'peer_cidrs', 'ike_policy',
                                     'ipsec_policy', 'cisco')])

    def find_current_status_in(self, statuses):
        if self.tunnel in statuses:
            return statuses[self.tunnel]
        else:
            return constants.ERROR

    def update_status_and_build_report(self, current_status):
        if current_status != self.last_status:
            pending_handled = plugin_utils.in_pending_status(self.last_status)
            self.last_status = current_status
            return {self.conn_id: {'status': current_status,
                                   'updated_pending_status': pending_handled}}
        else:
            return {}

    DIALECT_MAP = {'ike_policy': {'name': 'IKE Policy',
                                  'v1': u'v1',
                                  # auth_algorithm -> hash
                                  'sha1': u'sha',
                                  # encryption_algorithm -> encryption
                                  '3des': u'3des',
                                  'aes-128': u'aes',
                                  'aes-192': u'aes192',
                                  'aes-256': u'aes256',
                                  # pfs -> dhGroup
                                  'group2': 2,
                                  'group5': 5,
                                  'group14': 14},
                   'ipsec_policy': {'name': 'IPSec Policy',
                                    # auth_algorithm -> esp-authentication
                                    'sha1': u'esp-sha-hmac',
                                    # transform_protocol -> ah
                                    'esp': None,
                                    'ah': u'ah-sha-hmac',
                                    'ah-esp': u'ah-sha-hmac',
                                    # encryption_algorithm -> esp-encryption
                                    '3des': u'esp-3des',
                                    'aes-128': u'esp-aes',
                                    'aes-192': u'esp-192-aes',
                                    'aes-256': u'esp-256-aes',
                                    # pfs -> pfs
                                    'group2': u'group2',
                                    'group5': u'group5',
                                    'group14': u'group14'}}

    def translate_dialect(self, resource, attribute, info):
        """Map VPNaaS attributes values to CSR values for a resource."""
        name = self.DIALECT_MAP[resource]['name']
        if attribute not in info:
            raise CsrDriverMismatchError(resource=name, attr=attribute)
        value = info[attribute].lower()
        if value in self.DIALECT_MAP[resource]:
            return self.DIALECT_MAP[resource][value]
        raise CsrUnknownMappingError(resource=name, attr=attribute,
                                     value=value)

    def create_psk_info(self, psk_id, conn_info):
        """Collect/create attributes needed for pre-shared key."""
        return {u'keyring-name': psk_id,
                u'pre-shared-key-list': [
                    {u'key': conn_info['psk'],
                     u'encrypted': False,
                     u'peer-address': conn_info['peer_address']}]}

    def create_ike_policy_info(self, ike_policy_id, conn_info):
        """Collect/create/map attributes needed for IKE policy."""
        for_ike = 'ike_policy'
        policy_info = conn_info[for_ike]
        version = self.translate_dialect(for_ike,
                                         'ike_version',
                                         policy_info)
        encrypt_algorithm = self.translate_dialect(for_ike,
                                                   'encryption_algorithm',
                                                   policy_info)
        auth_algorithm = self.translate_dialect(for_ike,
                                                'auth_algorithm',
                                                policy_info)
        group = self.translate_dialect(for_ike,
                                       'pfs',
                                       policy_info)
        lifetime = policy_info['lifetime_value']
        return {u'version': version,
                u'priority-id': ike_policy_id,
                u'encryption': encrypt_algorithm,
                u'hash': auth_algorithm,
                u'dhGroup': group,
                u'lifetime': lifetime}

    def create_ipsec_policy_info(self, ipsec_policy_id, info):
        """Collect/create attributes needed for IPSec policy.

        Note: OpenStack will provide a default encryption algorithm, if one is
        not provided, so a authentication only configuration of (ah, sha1),
        which maps to ah-sha-hmac transform protocol, cannot be selected.
        As a result, we'll always configure the encryption algorithm, and
        will select ah-sha-hmac for transform protocol.
        """

        for_ipsec = 'ipsec_policy'
        policy_info = info[for_ipsec]
        transform_protocol = self.translate_dialect(for_ipsec,
                                                    'transform_protocol',
                                                    policy_info)
        auth_algorithm = self.translate_dialect(for_ipsec,
                                                'auth_algorithm',
                                                policy_info)
        encrypt_algorithm = self.translate_dialect(for_ipsec,
                                                   'encryption_algorithm',
                                                   policy_info)
        group = self.translate_dialect(for_ipsec, 'pfs', policy_info)
        lifetime = policy_info['lifetime_value']
        settings = {u'policy-id': ipsec_policy_id,
                    u'protection-suite': {
                        u'esp-encryption': encrypt_algorithm,
                        u'esp-authentication': auth_algorithm},
                    u'lifetime-sec': lifetime,
                    u'pfs': group,
                    u'anti-replay-window-size': u'disable'}
        if transform_protocol:
            settings[u'protection-suite'][u'ah'] = transform_protocol
        return settings

    def create_site_connection_info(self, site_conn_id, ipsec_policy_id,
                                    conn_info):
        """Collect/create attributes needed for the IPSec connection."""
        mtu = conn_info['mtu']
        return {
            u'vpn-interface-name': site_conn_id,
            u'ipsec-policy-id': ipsec_policy_id,
            u'remote-device': {
                u'tunnel-ip-address': conn_info['peer_address']
            },
            u'mtu': mtu
        }

    def create_routes_info(self, site_conn_id, conn_info):
        """Collect/create attributes for static routes."""
        routes_info = []
        for peer_cidr in conn_info.get('peer_cidrs', []):
            route = {u'destination-network': peer_cidr,
                     u'outgoing-interface': site_conn_id}
            route_id = csr_client.make_route_id(peer_cidr, site_conn_id)
            routes_info.append((route_id, route))
        return routes_info

    def _check_create(self, resource, which):
        """Determine if REST create request was successful."""
        if self.csr.status == requests.codes.CREATED:
            LOG.debug("%(resource)s %(which)s is configured",
                      {'resource': resource, 'which': which})
            return
        LOG.error(_("Unable to create %(resource)s %(which)s: "
                    "%(status)d"),
                  {'resource': resource, 'which': which,
                   'status': self.csr.status})
        # ToDO(pcm): Set state to error
        raise CsrResourceCreateFailure(resource=resource, which=which)

    def do_create_action(self, action_suffix, info, resource_id, title):
        """Perform a single REST step for IPSec site connection create."""
        create_action = 'create_%s' % action_suffix
        try:
            getattr(self.csr, create_action)(info)
        except AttributeError:
            LOG.exception(_("Internal error - '%s' is not defined"),
                          create_action)
            raise CsrResourceCreateFailure(resource=title,
                                           which=resource_id)
        self._check_create(title, resource_id)
        self.steps.append(RollbackStep(action_suffix, resource_id, title))

    def _verify_deleted(self, status, resource, which):
        """Determine if REST delete request was successful."""
        if status in (requests.codes.NO_CONTENT, requests.codes.NOT_FOUND):
            LOG.debug("%(resource)s configuration %(which)s was removed",
                      {'resource': resource, 'which': which})
        else:
            LOG.warning(_("Unable to delete %(resource)s %(which)s: "
                          "%(status)d"), {'resource': resource,
                                          'which': which,
                                          'status': status})

    def do_rollback(self):
        """Undo create steps that were completed successfully."""
        for step in reversed(self.steps):
            delete_action = 'delete_%s' % step.action
            LOG.debug(_("Performing rollback action %(action)s for "
                        "resource %(resource)s"), {'action': delete_action,
                                                   'resource': step.title})
            try:
                getattr(self.csr, delete_action)(step.resource_id)
            except AttributeError:
                LOG.exception(_("Internal error - '%s' is not defined"),
                              delete_action)
                raise CsrResourceCreateFailure(resource=step.title,
                                               which=step.resource_id)
            self._verify_deleted(self.csr.status, step.title, step.resource_id)
        self.steps = []

    def create_ipsec_site_connection(self, context, conn_info):
        """Creates an IPSec site-to-site connection on CSR.

        Create the PSK, IKE policy, IPSec policy, connection, static route,
        and (future) DPD.
        """
        # Get all the IDs
        conn_id = conn_info['id']
        psk_id = conn_id
        site_conn_id = conn_info['cisco']['site_conn_id']
        ike_policy_id = conn_info['cisco']['ike_policy_id']
        ipsec_policy_id = conn_info['cisco']['ipsec_policy_id']

        LOG.debug(_('Creating IPSec connection %s'), conn_id)
        # Get all the attributes needed to create
        try:
            psk_info = self.create_psk_info(psk_id, conn_info)
            ike_policy_info = self.create_ike_policy_info(ike_policy_id,
                                                          conn_info)
            ipsec_policy_info = self.create_ipsec_policy_info(ipsec_policy_id,
                                                              conn_info)
            connection_info = self.create_site_connection_info(site_conn_id,
                                                               ipsec_policy_id,
                                                               conn_info)
            routes_info = self.create_routes_info(site_conn_id, conn_info)
        except (CsrUnknownMappingError, CsrDriverMismatchError) as e:
            LOG.exception(e)
            return

        try:
            self.do_create_action('pre_shared_key', psk_info,
                                  conn_id, 'Pre-Shared Key')
            self.do_create_action('ike_policy', ike_policy_info,
                                  ike_policy_id, 'IKE Policy')
            self.do_create_action('ipsec_policy', ipsec_policy_info,
                                  ipsec_policy_id, 'IPSec Policy')
            self.do_create_action('ipsec_connection', connection_info,
                                  site_conn_id, 'IPSec Connection')

            # TODO(pcm): FUTURE - Do DPD for v1 and handle if >1 connection
            # and different DPD settings
            for route_id, route_info in routes_info:
                self.do_create_action('static_route', route_info,
                                      route_id, 'Static Route')
        except CsrResourceCreateFailure:
            self.do_rollback()
            LOG.info(_("FAILED: Create of IPSec site-to-site connection %s"),
                     conn_id)
        else:
            LOG.info(_("SUCCESS: Created IPSec site-to-site connection %s"),
                     conn_id)

    def delete_ipsec_site_connection(self, context, conn_id):
        """Delete the site-to-site IPSec connection.

        This will be best effort and will continue, if there are any
        failures.
        """
        LOG.debug(_('Deleting IPSec connection %s'), conn_id)
        if not self.steps:
            LOG.warning(_('Unable to find connection %s'), conn_id)
        else:
            self.do_rollback()

        LOG.info(_("SUCCESS: Deleted IPSec site-to-site connection %s"),
                 conn_id)

    def set_admin_state(self, is_up):
        """Change the admin state for the IPSec connection."""
        self.csr.set_ipsec_connection_state(self.tunnel, admin_up=is_up)
        if self.csr.status != requests.codes.NO_CONTENT:
            state = "UP" if is_up else "DOWN"
            LOG.error(_("Unable to change %(tunnel)s admin state to "
                        "%(state)s"), {'tunnel': self.tunnel, 'state': state})
            raise CsrAdminStateChangeFailure(tunnel=self.tunnel, state=state)
