# All Rights Reserved.
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

import collections

from neutron_lib.agent import topics
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib import constants
from neutron_lib.plugins import directory
from neutron_lib import rpc as n_rpc
from neutron_lib.utils import net
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import versionutils

from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.db import securitygroups_rpc_base as sg_rpc_base

LOG = logging.getLogger(__name__)


class SecurityGroupServerRpcApi(object):
    """RPC client for security group methods in the plugin.

    This class implements the client side of an rpc interface.  This interface
    is used by agents to call security group related methods implemented on the
    plugin side.  The other side of this interface is defined in
    SecurityGroupServerRpcCallback.  For more information about changing rpc
    interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """
    def __init__(self, topic):
        target = oslo_messaging.Target(
            topic=topic, version='1.0',
            namespace=constants.RPC_NAMESPACE_SECGROUP)
        self.client = n_rpc.get_client(target)

    def security_group_rules_for_devices(self, context, devices):
        LOG.debug("Get security group rules "
                  "for devices via rpc %r", devices)
        cctxt = self.client.prepare(version='1.1')
        return cctxt.call(context, 'security_group_rules_for_devices',
                          devices=devices)

    def security_group_info_for_devices(self, context, devices):
        LOG.debug("Get security group information for devices via rpc %r",
                  devices)
        call_version = '1.3'
        cctxt = self.client.prepare(version=call_version)
        return cctxt.call(context, 'security_group_info_for_devices',
                          devices=devices,
                          call_version=call_version)


class SecurityGroupServerRpcCallback(object):
    """Callback for SecurityGroup agent RPC in plugin implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in SecurityGroupServerRpcApi. For more information on changing
    rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """

    # API version history:
    #   1.1 - Initial version
    #   1.2 - security_group_info_for_devices introduced as an optimization
    #   1.3 - security_group_info_for_devices returns member_ips with new
    #         structure.

    # NOTE: target must not be overridden in subclasses
    # to keep RPC API version consistent across plugins.
    target = oslo_messaging.Target(version='1.3',
                                   namespace=constants.RPC_NAMESPACE_SECGROUP)

    @property
    def plugin(self):
        return directory.get_plugin()

    def _get_devices_info(self, context, devices):
        return dict(
            (port['id'], port)
            for port in self.plugin.get_ports_from_devices(context, devices)
            if port and not net.is_port_trusted(port)
        )

    def security_group_rules_for_devices(self, context, **kwargs):
        """Callback method to return security group rules for each port.

        also convert remote_group_id rule
        to source_ip_prefix and dest_ip_prefix rule

        :params devices: list of devices
        :returns: port correspond to the devices with security group rules
        """
        devices_info = kwargs.get('devices')
        ports = self._get_devices_info(context, devices_info)
        return self.plugin.security_group_rules_for_ports(context, ports)

    def security_group_info_for_devices(self, context, **kwargs):
        """Return security group information for requested devices.

        :params devices: list of devices
        :returns:
        sg_info{
          'security_groups': {sg_id: [rule1, rule2]}
          'sg_member_ips': {sg_id: {'IPv4': set(), 'IPv6': set()}}
          'devices': {device_id: {device_info}}
        }

        Note that sets are serialized into lists by rpc code.
        """
        # The original client RPC version was 1.2 before this change.
        call_version = kwargs.pop("call_version", '1.2')
        _target_version = versionutils.convert_version_to_tuple(call_version)
        devices_info = kwargs.get('devices')
        ports = self._get_devices_info(context, devices_info)
        sg_info = self.plugin.security_group_info_for_ports(context, ports)
        if _target_version < (1, 3):
            LOG.warning("RPC security_group_info_for_devices call has "
                        "inconsistent version between server and agents. "
                        "The server supports RPC version is 1.3 while "
                        "the agent is %s.", call_version)
            return self.make_compatible_sg_member_ips(sg_info)
        return sg_info

    def make_compatible_sg_member_ips(self, sg_info):
        sg_member_ips = sg_info.get('sg_member_ips', {})
        sg_ids = sg_member_ips.keys()
        for sg_id in sg_ids:
            member_ips = sg_member_ips.get(sg_id, {})
            ipv4_ips = member_ips.get("IPv4", set())
            comp_ipv4_ips = set([ip for ip, _mac in ipv4_ips])
            ipv6_ips = member_ips.get("IPv6", set())
            comp_ipv6_ips = set([ip for ip, _mac in ipv6_ips])
            comp_ips = {"IPv4": comp_ipv4_ips,
                        "IPv6": comp_ipv6_ips}
            sg_member_ips[sg_id] = comp_ips
        sg_info['sg_member_ips'] = sg_member_ips
        return sg_info


class SecurityGroupAgentRpcApiMixin(object):
    """RPC client for security group methods to the agent.

    This class implements the client side of an rpc interface.  This interface
    is used by plugins to call security group methods implemented on the
    agent side.  The other side of this interface can be found in
    SecurityGroupAgentRpcCallbackMixin.  For more information about changing
    rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """

    # history
    #   1.1 Support Security Group RPC
    SG_RPC_VERSION = "1.1"

    def _get_security_group_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.SECURITY_GROUP,
                                     topics.UPDATE)

    def security_groups_rule_updated(self, context, security_groups):
        """Notify rule updated security groups."""
        if not security_groups:
            return
        cctxt = self.client.prepare(version=self.SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_rule_updated',
                   security_groups=security_groups)

    def security_groups_member_updated(self, context, security_groups):
        """Notify member updated security groups."""
        if not security_groups:
            return
        cctxt = self.client.prepare(version=self.SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_member_updated',
                   security_groups=security_groups)


class SecurityGroupAgentRpcCallbackMixin(object):
    """A mix-in that enable SecurityGroup support in agent implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in SecurityGroupAgentRpcApiMixin. For more information on
    changing rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.

    The sg_agent reference implementation is available in neutron/agent
    """
    # mix-in object should be have sg_agent
    sg_agent = None

    def _security_groups_agent_not_set(self):
        LOG.warning("Security group agent binding currently not set. "
                    "This should be set by the end of the init "
                    "process.")

    def security_groups_rule_updated(self, context, **kwargs):
        """Callback for security group rule update.

        :param security_groups: list of updated security_groups
        """
        security_groups = kwargs.get('security_groups', [])
        LOG.debug("Security group rule updated on remote: %s",
                  security_groups)
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_rule_updated(security_groups)

    def security_groups_member_updated(self, context, **kwargs):
        """Callback for security group member update.

        :param security_groups: list of updated security_groups
        """
        security_groups = kwargs.get('security_groups', [])
        LOG.debug("Security group member updated on remote: %s",
                  security_groups)
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_member_updated(security_groups)


class SecurityGroupServerAPIShim(sg_rpc_base.SecurityGroupInfoAPIMixin):
    """Agent-side replacement for SecurityGroupServerRpcApi using local data.

    This provides the same methods as SecurityGroupServerRpcApi but it reads
    from the updates delivered to the push notifications cache rather than
    calling the server.
    """
    def __init__(self, rcache):
        self.rcache = rcache
        registry.subscribe(self._clear_child_sg_rules, 'SecurityGroup',
                           events.AFTER_DELETE)
        registry.subscribe(self._add_child_sg_rules, 'SecurityGroup',
                           events.AFTER_UPDATE)
        # set this attr so agent can adjust the timeout of the client
        self.client = resources_rpc.ResourcesPullRpcApi().client

    def register_legacy_sg_notification_callbacks(self, sg_agent):
        self._sg_agent = sg_agent
        registry.subscribe(self._handle_sg_rule_delete,
                           'SecurityGroupRule', events.AFTER_DELETE)
        registry.subscribe(self._handle_sg_rule_update,
                           'SecurityGroupRule', events.AFTER_UPDATE)
        registry.subscribe(self._handle_sg_member_delete,
                           'Port', events.AFTER_DELETE)
        registry.subscribe(self._handle_sg_member_update,
                           'Port', events.AFTER_UPDATE)

    def security_group_info_for_devices(self, context, devices):
        ports = self._get_devices_info(context, devices)
        result = self.security_group_info_for_ports(context, ports)
        return result

    def security_group_rules_for_devices(self, context, devices):
        # this is the legacy method that should never be called since
        # security_group_info_for_devices will never throw an unsupported
        # error.
        raise NotImplementedError()

    def _add_child_sg_rules(self, rtype, event, trigger, context, updated,
                            **kwargs):
        # whenever we receive a full security group, add all child rules
        # because the server won't emit events for the individual rules on
        # creation.
        for rule in updated.rules:
            self.rcache.record_resource_update(context, 'SecurityGroupRule',
                                               rule)

    def _clear_child_sg_rules(self, rtype, event, trigger, context, existing,
                              **kwargs):
        if not existing:
            return
        # the server can delete an entire security group without notifying
        # about the security group rules. so we need to emulate a rule deletion
        # when a security group is removed.
        filters = {'security_group_id': (existing.id, )}
        for rule in self.rcache.get_resources('SecurityGroupRule', filters):
            self.rcache.record_resource_delete(context, 'SecurityGroupRule',
                                               rule.id)

    def _handle_sg_rule_delete(self, rtype, event, trigger, context, existing,
                               **kwargs):
        if not existing:
            return
        sg_id = existing.security_group_id
        self._sg_agent.security_groups_rule_updated([sg_id])

    def _handle_sg_rule_update(self, rtype, event, trigger, context, existing,
                               updated, **kwargs):
        sg_id = updated.security_group_id
        self._sg_agent.security_groups_rule_updated([sg_id])

    def _handle_sg_member_delete(self, rtype, event, trigger, context,
                                 existing, **kwargs):
        # received on port delete
        sgs = set(existing.security_group_ids) if existing else set()
        if sgs:
            self._sg_agent.security_groups_member_updated(sgs)

    def _handle_sg_member_update(self, rtype, event, trigger, context,
                                 existing, updated, changed_fields, **kwargs):
        # received on port update
        sgs = set(existing.security_group_ids) if existing else set()
        if not changed_fields.intersection({'security_group_ids', 'fixed_ips',
                                            'allowed_address_pairs'}):
            # none of the relevant fields to SG calculations changed
            return
        sgs.update(set(updated.security_group_ids))
        if sgs:
            self._sg_agent.security_groups_member_updated(sgs)

    def _get_devices_info(self, context, devices):
        # NOTE(kevinbenton): this format is required by the sg code, it is
        # defined in get_port_from_device and mimics
        # make_port_dict_with_security_groups in ML2 db
        result = {}
        for device in devices:
            ovo = self.rcache.get_resource_by_id('Port', device)
            if not ovo:
                continue
            port = ovo.to_dict()
            # the caller expects trusted ports to be excluded from the result
            if net.is_port_trusted(port):
                continue

            port['security_groups'] = list(ovo.security_group_ids)
            port['security_group_rules'] = []
            port['security_group_source_groups'] = []
            port['fixed_ips'] = [str(f['ip_address'])
                                 for f in port['fixed_ips']]
            # NOTE(kevinbenton): this id==device is only safe for OVS. a lookup
            # will be required for linux bridge and others that don't have the
            # full port UUID
            port['device'] = port['id']
            port['port_security_enabled'] = getattr(
                ovo.security, 'port_security_enabled', True)
            result[device] = port
        return result

    def _select_ips_for_remote_group(self, context, remote_group_ids):
        if not remote_group_ids:
            return {}
        ips_by_group = {rg: set() for rg in remote_group_ids}

        filters = {'security_group_ids': tuple(remote_group_ids)}
        for p in self.rcache.get_resources('Port', filters):
            allowed_ips = [(str(addr.ip_address), str(addr.mac_address))
                           for addr in p.allowed_address_pairs]
            port_ips = [(str(addr.ip_address), str(p.mac_address))
                        for addr in p.fixed_ips] + allowed_ips
            for sg_id in p.security_group_ids:
                if sg_id in ips_by_group:
                    ips_by_group[sg_id].update(set(port_ips))
        return ips_by_group

    def _select_rules_for_ports(self, context, ports):
        if not ports:
            return []
        results = []
        sg_ids = set((sg_id for p in ports.values()
                      for sg_id in p['security_group_ids']))
        rules_by_sgid = collections.defaultdict(list)
        for sg_id in sg_ids:
            filters = {'security_group_id': (sg_id, )}
            for r in self.rcache.get_resources('SecurityGroupRule', filters):
                rules_by_sgid[r.security_group_id].append(r)
        for p in ports.values():
            for sg_id in p['security_group_ids']:
                for rule in rules_by_sgid[sg_id]:
                    results.append((p['id'], rule.to_dict()))
        return results

    def _select_sg_ids_for_ports(self, context, ports):
        sg_ids = set((sg_id for p in ports.values()
                      for sg_id in p['security_group_ids']))
        return [(sg_id, ) for sg_id in sg_ids]

    def _is_security_group_stateful(self, context, sg_id):
        sg = self.rcache.get_resource_by_id(resources.SECURITYGROUP, sg_id)
        return sg.stateful
