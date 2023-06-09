# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

import netaddr
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.utils import helpers

from neutron._i18n import _
from neutron.db.models import address_group as ag_models
from neutron.db.models import allowed_address_pair as aap_models
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import securitygroup as ext_sg
from neutron.objects import securitygroup as sg_obj


DIRECTION_IP_PREFIX = {'ingress': 'source_ip_prefix',
                       'egress': 'dest_ip_prefix'}

DHCP_RULE_PORT = {4: (67, 68, const.IPv4), 6: (547, 546, const.IPv6)}


class SecurityGroupServerNotifierRpcMixin(sg_db.SecurityGroupDbMixin):
    """Mixin class to add agent-based security group implementation."""

    def register_sg_notifier(self):
        registry.subscribe(self._notify_sg_on_port_change, resources.PORT,
                           events.AFTER_CREATE)
        registry.subscribe(self._notify_sg_on_port_change, resources.PORT,
                           events.AFTER_UPDATE)
        registry.subscribe(self._notify_sg_on_port_change, resources.PORT,
                           events.AFTER_DELETE)

    def _notify_sg_on_port_change(self, resource, event, trigger, payload):
        """Trigger notification to other SG members on port changes."""

        context = payload.context
        port = payload.latest_state
        if event == events.AFTER_UPDATE:
            original_port = payload.states[0]
            self.check_and_notify_security_group_member_changed(
                context, original_port, port)
        else:
            self.notify_security_groups_member_updated(context, port)

    def create_security_group_rule(self, context, security_group_rule):
        rule = super(SecurityGroupServerNotifierRpcMixin,
                     self).create_security_group_rule(context,
                                                      security_group_rule)
        sgids = [rule['security_group_id']]
        self.notifier.security_groups_rule_updated(context, sgids)
        return rule

    def create_security_group_rule_bulk(self, context, security_group_rules):
        rules = super(SecurityGroupServerNotifierRpcMixin,
                      self).create_security_group_rule_bulk_native(
                          context, security_group_rules)
        sgids = set([r['security_group_id'] for r in rules])
        self.notifier.security_groups_rule_updated(context, list(sgids))
        return rules

    def delete_security_group_rule(self, context, sgrid):
        rule = self.get_security_group_rule(context, sgrid)
        super(SecurityGroupServerNotifierRpcMixin,
              self).delete_security_group_rule(context, sgrid)
        self.notifier.security_groups_rule_updated(context,
                                                   [rule['security_group_id']])

    def check_and_notify_security_group_member_changed(
            self, context, original_port, updated_port):
        sg_change = not helpers.compare_elements(
            original_port.get(ext_sg.SECURITYGROUPS),
            updated_port.get(ext_sg.SECURITYGROUPS))
        if sg_change:
            self.notify_security_groups_member_updated_bulk(
                context, [original_port, updated_port])
        elif original_port['fixed_ips'] != updated_port['fixed_ips']:
            self.notify_security_groups_member_updated(context, updated_port)

    def is_security_group_member_updated(self, context,
                                         original_port, updated_port):
        """Check security group member updated or not.

        This method returns a flag which indicates request notification
        is required and does not perform notification itself.
        It is because another changes for the port may require notification.
        """
        need_notify = False
        if (original_port['fixed_ips'] != updated_port['fixed_ips'] or
                original_port['mac_address'] != updated_port['mac_address'] or
                not helpers.compare_elements(
                    original_port.get(ext_sg.SECURITYGROUPS),
                    updated_port.get(ext_sg.SECURITYGROUPS))):
            need_notify = True
        return need_notify

    def notify_security_groups_member_updated_bulk(self, context, ports):
        """Notify update event of security group members for ports.

        The agent setups the iptables rule to allow
        ingress packet from the dhcp server (as a part of provider rules),
        so we need to notify an update of dhcp server ip
        address to the plugin agent.
        """
        sec_groups = set()
        for port in ports:
            # NOTE (Swami): ROUTER_INTERFACE_OWNERS check is required
            # since it includes the legacy router interface device owners
            # and DVR router interface device owners.
            if (port['device_owner'] not in
                    [const.DEVICE_OWNER_DHCP, const.ROUTER_INTERFACE_OWNERS]):
                sec_groups |= set(port.get(ext_sg.SECURITYGROUPS))

        if sec_groups:
            self.notifier.security_groups_member_updated(
                context, list(sec_groups))

    def notify_security_groups_member_updated(self, context, port):
        self.notify_security_groups_member_updated_bulk(context, [port])


class SecurityGroupInfoAPIMixin(object):
    """API for retrieving security group info for SG agent code."""

    def get_port_from_device(self, context, device):
        """Get port dict from device name on an agent.

        Subclass must provide this method or get_ports_from_devices.

        :param device: device name which identifies a port on the agent side.
        What is specified in "device" depends on a plugin agent implementation.
        For example, it is a port ID in OVS agent and netdev name in Linux
        Bridge agent.
        :return: port dict returned by DB plugin get_port(). In addition,
        it must contain the following fields in the port dict returned.
        - device
        - security_groups
        - security_group_rules,
        - security_group_source_groups
        - security_group_remote_address_groups
        - fixed_ips
        """
        raise NotImplementedError(_("%s must implement get_port_from_device "
                                    "or get_ports_from_devices.")
                                  % self.__class__.__name__)

    def get_ports_from_devices(self, context, devices):
        """Bulk method of get_port_from_device.

        Subclasses may override this to provide better performance for DB
        queries, backend calls, etc.
        """
        return [self.get_port_from_device(context, device)
                for device in devices]

    def security_group_info_for_ports(self, context, ports):
        sg_info = {'devices': ports,
                   'security_groups': {},
                   'sg_member_ips': {}}
        rules_in_db = self._select_rules_for_ports(context, ports)
        remote_security_group_info = {}
        remote_address_group_info = {}
        for (port_id, rule_in_db) in rules_in_db:
            remote_gid = rule_in_db.get('remote_group_id')
            remote_ag_id = rule_in_db.get('remote_address_group_id')
            security_group_id = rule_in_db.get('security_group_id')
            ethertype = rule_in_db['ethertype']
            if ('security_group_source_groups'
                    not in sg_info['devices'][port_id]):
                sg_info['devices'][port_id][
                    'security_group_source_groups'] = []
            if ('security_group_remote_address_groups'
                    not in sg_info['devices'][port_id]):
                sg_info['devices'][port_id][
                    'security_group_remote_address_groups'] = []

            if remote_gid:
                if (remote_gid
                        not in sg_info['devices'][port_id][
                            'security_group_source_groups']):
                    sg_info['devices'][port_id][
                        'security_group_source_groups'].append(remote_gid)
                if remote_gid not in remote_security_group_info:
                    remote_security_group_info[remote_gid] = {}
                if ethertype not in remote_security_group_info[remote_gid]:
                    # this set will be serialized into a list by rpc code
                    remote_security_group_info[remote_gid][ethertype] = set()
            elif remote_ag_id:
                if (remote_ag_id
                        not in sg_info['devices'][port_id][
                            'security_group_remote_address_groups']):
                    sg_info['devices'][port_id][
                        'security_group_remote_address_groups'].append(
                            remote_ag_id)
                if remote_ag_id not in remote_address_group_info:
                    remote_address_group_info[remote_ag_id] = {}
                if ethertype not in remote_address_group_info[remote_ag_id]:
                    # this set will be serialized into a list by rpc code
                    remote_address_group_info[remote_ag_id][ethertype] = set()
            direction = rule_in_db['direction']
            stateful = self._is_security_group_stateful(context,
                                                        security_group_id)
            rule_dict = {
                'direction': direction,
                'ethertype': ethertype,
                'stateful': stateful}

            for key in ('protocol', 'port_range_min', 'port_range_max',
                        'remote_ip_prefix', 'remote_group_id',
                        'remote_address_group_id'):
                if rule_in_db.get(key) is not None:
                    if key == 'remote_ip_prefix':
                        normalized_cidr = rule_in_db.get('normalized_cidr')
                        direction_ip_prefix = DIRECTION_IP_PREFIX[direction]
                        rule_dict[direction_ip_prefix] = (
                            normalized_cidr or rule_in_db[key])
                        continue
                    rule_dict[key] = rule_in_db[key]
            if security_group_id not in sg_info['security_groups']:
                sg_info['security_groups'][security_group_id] = []
            if rule_dict not in sg_info['security_groups'][security_group_id]:
                sg_info['security_groups'][security_group_id].append(
                    rule_dict)
        # Update the security groups info if they don't have any rules
        sg_ids = self._select_sg_ids_for_ports(context, ports)
        for (sg_id, ) in sg_ids:
            if sg_id not in sg_info['security_groups']:
                sg_info['security_groups'][sg_id] = []

        sg_info['sg_member_ips'] = remote_security_group_info
        # the provider rules do not belong to any security group, so these
        # rules still reside in sg_info['devices'] [port_id]
        self._apply_provider_rule(context, sg_info['devices'])

        self._get_security_group_member_ips(context, sg_info)
        # NOTE(hangyang) Remote address group IP info are also stored in
        # sg_info['sg_member_ips'] so that the two types of remote groups
        # can be processed by the same firewall functions.
        sg_info['sg_member_ips'].update(remote_address_group_info)
        return self._get_address_group_ips(context, sg_info,
                                           remote_address_group_info)

    def _get_security_group_member_ips(self, context, sg_info):
        ips = self._select_ips_for_remote_group(
            context, sg_info['sg_member_ips'].keys())
        for sg_id, member_ips in ips.items():
            for ip in member_ips:
                ethertype = 'IPv%d' % netaddr.IPNetwork(ip[0]).version
                if ethertype in sg_info['sg_member_ips'][sg_id]:
                    sg_info['sg_member_ips'][sg_id][ethertype].add(ip)
        return sg_info

    def _get_address_group_ips(self, context, sg_info,
                               remote_address_group_info):
        ips = self._select_ips_for_remote_address_group(
            context, remote_address_group_info.keys())
        for ag_id, ag_ips in ips.items():
            for ip in ag_ips:
                ethertype = 'IPv%d' % netaddr.IPNetwork(ip[0]).version
                if ethertype in remote_address_group_info[ag_id]:
                    sg_info['sg_member_ips'][ag_id][ethertype].add(ip)
        return sg_info

    def _select_remote_group_ids(self, ports):
        remote_group_ids = []
        for port in ports.values():
            for rule in port.get('security_group_rules'):
                remote_group_id = rule.get('remote_group_id')
                if remote_group_id:
                    remote_group_ids.append(remote_group_id)
        return remote_group_ids

    def _select_remote_address_group_ids(self, ports):
        remote_address_group_ids = []
        for port in ports.values():
            for rule in port.get('security_group_rules'):
                remote_address_group_id = rule.get('remote_address_group_id')
                if remote_address_group_id:
                    remote_address_group_ids.append(remote_address_group_id)
        return remote_address_group_ids

    def _convert_remote_id_to_ip_prefix(self, context, ports):
        remote_group_ids = self._select_remote_group_ids(ports)
        remote_address_group_ids = self._select_remote_address_group_ids(ports)
        ips = self._select_ips_for_remote_group(context, remote_group_ids)
        ips.update(self._select_ips_for_remote_address_group(
            context, remote_address_group_ids))
        for port in ports.values():
            updated_rule = []
            for rule in port.get('security_group_rules'):
                remote_group_id = rule.get('remote_group_id')
                remote_address_group_id = rule.get('remote_address_group_id')
                direction = rule.get('direction')
                direction_ip_prefix = DIRECTION_IP_PREFIX[direction]
                if not (remote_group_id or remote_address_group_id):
                    updated_rule.append(rule)
                    continue

                base_rule = rule
                if remote_group_id:
                    port['security_group_source_groups'].append(
                        remote_group_id)
                    ip_list = [ip[0] for ip in ips[remote_group_id]]
                else:
                    port['security_group_remote_address_groups'].append(
                        remote_address_group_id)
                    ip_list = [ip[0] for ip in ips[remote_address_group_id]]
                for ip in ip_list:
                    if ip in port.get('fixed_ips', []):
                        continue
                    ip_rule = base_rule.copy()
                    version = netaddr.IPNetwork(ip).version
                    ethertype = 'IPv%s' % version
                    if base_rule['ethertype'] != ethertype:
                        continue
                    ip_rule[direction_ip_prefix] = str(
                        netaddr.IPNetwork(ip).cidr)
                    updated_rule.append(ip_rule)
            port['security_group_rules'] = updated_rule
        return ports

    def _add_ingress_dhcp_rule(self, port):
        for ip_version in (4, 6):
            # only allow DHCP servers to talk to the appropriate IP address
            # to avoid getting leases that don't match the Neutron IPs
            prefix = '32' if ip_version == 4 else '128'
            dests = ['%s/%s' % (ip, prefix) for ip in port['fixed_ips']
                     if netaddr.IPNetwork(ip).version == ip_version]
            if ip_version == 4:
                # v4 dhcp servers can also talk to broadcast
                dests.append('255.255.255.255/32')
            elif ip_version == 6:
                # v6 dhcp responses can target link-local addresses
                dests.append('fe80::/64')
            source_port, dest_port, ethertype = DHCP_RULE_PORT[ip_version]
            for dest in dests:
                dhcp_rule = {'direction': 'ingress',
                             'ethertype': ethertype,
                             'protocol': 'udp',
                             'port_range_min': dest_port,
                             'port_range_max': dest_port,
                             'source_port_range_min': source_port,
                             'source_port_range_max': source_port,
                             'dest_ip_prefix': dest}
                port['security_group_rules'].append(dhcp_rule)

    def _add_ingress_ra_rule(self, port):
        has_v6 = [ip for ip in port['fixed_ips']
                  if netaddr.IPNetwork(ip).version == 6]
        if not has_v6:
            return
        ra_rule = {'direction': 'ingress',
                   'ethertype': const.IPv6,
                   'protocol': const.PROTO_NAME_IPV6_ICMP,
                   'source_port_range_min': const.ICMPV6_TYPE_RA}
        port['security_group_rules'].append(ra_rule)

    def _apply_provider_rule(self, context, ports):
        for port in ports.values():
            self._add_ingress_ra_rule(port)
            self._add_ingress_dhcp_rule(port)

    def security_group_rules_for_ports(self, context, ports):
        rules_in_db = self._select_rules_for_ports(context, ports)
        for (port_id, rule_in_db) in rules_in_db:
            port = ports[port_id]
            direction = rule_in_db['direction']
            rule_dict = {
                'security_group_id': rule_in_db['security_group_id'],
                'direction': direction,
                'ethertype': rule_in_db['ethertype'],
            }
            for key in ('protocol', 'port_range_min', 'port_range_max',
                        'remote_ip_prefix', 'remote_group_id',
                        'remote_address_group_id'):
                if rule_in_db.get(key) is not None:
                    if key == 'remote_ip_prefix':
                        normalized_cidr = rule_in_db.get('normalized_cidr')
                        direction_ip_prefix = DIRECTION_IP_PREFIX[direction]
                        rule_dict[direction_ip_prefix] = (
                            normalized_cidr or rule_in_db[key])
                        continue
                    rule_dict[key] = rule_in_db[key]
            port['security_group_rules'].append(rule_dict)
        self._apply_provider_rule(context, ports)
        return self._convert_remote_id_to_ip_prefix(context, ports)

    def _select_ips_for_remote_group(self, context, remote_group_ids):
        """Get all IP addresses (including allowed addr pairs) for each sg.

        Return dict of lists of IPs keyed by group_id.
        """
        raise NotImplementedError()

    def _select_ips_for_remote_address_group(self, context,
                                             remote_address_group_ids):
        """Get all IP addresses for each address group.

        Return dict of lists of IPs keyed by address_group_id.
        """
        raise NotImplementedError()

    def _select_rules_for_ports(self, context, ports):
        """Get all security group rules associated with a list of ports.

        Return list of tuples of (port_id, sg_rule)
        """
        raise NotImplementedError()

    def _select_sg_ids_for_ports(self, context, ports):
        """Return security group IDs for a list of ports.

        Return list of tuples with a single element of sg_id.
        """
        raise NotImplementedError()

    def _is_security_group_stateful(self, context, sg_id):
        """Return whether the security group is stateful or not.

        Return True if the security group associated with the given ID
        is stateful, else False.
        """
        return True


class SecurityGroupServerRpcMixin(SecurityGroupInfoAPIMixin,
                                  SecurityGroupServerNotifierRpcMixin):
    """Server-side RPC mixin using DB for SG notifications and responses."""

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def _select_sg_ids_for_ports(self, context, ports):
        if not ports:
            return []
        sg_binding_port = sg_models.SecurityGroupPortBinding.port_id
        sg_binding_sgid = sg_models.SecurityGroupPortBinding.security_group_id
        query = context.session.query(sg_binding_sgid)
        query = query.filter(sg_binding_port.in_(ports.keys()))
        return query.all()

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def _select_rules_for_ports(self, context, ports):
        if not ports:
            return []
        sg_binding_port = sg_models.SecurityGroupPortBinding.port_id
        sg_binding_sgid = sg_models.SecurityGroupPortBinding.security_group_id

        sgr_sgid = sg_models.SecurityGroupRule.security_group_id

        query = context.session.query(sg_binding_port,
                                      sg_models.SecurityGroupRule)
        query = query.join(sg_models.SecurityGroupRule,
                           sgr_sgid == sg_binding_sgid)
        query = query.filter(sg_binding_port.in_(ports.keys()))
        return query.all()

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def _select_ips_for_remote_group(self, context, remote_group_ids):
        ips_by_group = {}
        if not remote_group_ids:
            return ips_by_group
        for remote_group_id in remote_group_ids:
            ips_by_group[remote_group_id] = set()

        ip_port = models_v2.IPAllocation.port_id
        sg_binding_port = sg_models.SecurityGroupPortBinding.port_id
        sg_binding_sgid = sg_models.SecurityGroupPortBinding.security_group_id

        # Join the security group binding table directly to the IP allocation
        # table instead of via the Port table skip an unnecessary intermediary
        query = context.session.query(
            sg_binding_sgid,
            models_v2.IPAllocation.ip_address,
            aap_models.AllowedAddressPair.ip_address,
            aap_models.AllowedAddressPair.mac_address)
        query = query.join(models_v2.IPAllocation,
                           ip_port == sg_binding_port)
        # Outerjoin because address pairs may be null and we still want the
        # IP for the port.
        query = query.outerjoin(
            aap_models.AllowedAddressPair,
            sg_binding_port == aap_models.AllowedAddressPair.port_id)
        query = query.filter(sg_binding_sgid.in_(remote_group_ids))
        # Each allowed address pair IP record for a port beyond the 1st
        # will have a duplicate regular IP in the query response since
        # the relationship is 1-to-many. Dedup with a set
        for security_group_id, ip_address, allowed_addr_ip, mac in query:
            # Since port mac will not be used further, but in order to align
            # the data structure we directly set None to it to avoid bother
            # the ports table.
            ips_by_group[security_group_id].add((ip_address, None))
            if allowed_addr_ip:
                ips_by_group[security_group_id].add(
                    (allowed_addr_ip, mac))
        return ips_by_group

    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_READER
    def _select_ips_for_remote_address_group(self, context,
                                             remote_address_group_ids):
        ips_by_group = {}
        if not remote_address_group_ids:
            return ips_by_group
        for remote_ag_id in remote_address_group_ids:
            ips_by_group[remote_ag_id] = set()

        ag_assoc_ag_id = ag_models.AddressAssociation.address_group_id
        ag_assoc_addr = ag_models.AddressAssociation.address
        query = context.session.query(ag_assoc_ag_id, ag_assoc_addr)
        query = query.filter(ag_assoc_ag_id.in_(remote_address_group_ids))
        for ag_id, addr in query:
            # In order to align the data structure expected on firewall,
            # we set the mac address as None
            ips_by_group[ag_id].add((addr, None))
        return ips_by_group

    @db_api.retry_if_session_inactive()
    def _is_security_group_stateful(self, context, sg_id):
        return sg_obj.SecurityGroup.get_sg_by_id(context, sg_id).stateful
