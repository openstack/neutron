# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Big Switch Networks, Inc.
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
#
# @author: Sumit Naiksatam, sumitnaiksatam@gmail.com, Big Switch Networks, Inc.

from oslo.config import cfg

from neutron.common import exceptions as n_exception
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.db import api as qdbapi
from neutron.db.firewall import firewall_db
from neutron.extensions import firewall as fw_ext
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.plugins.common import constants as const


LOG = logging.getLogger(__name__)


class FirewallCallbacks(object):
    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin

    def create_rpc_dispatcher(self):
        return q_rpc.PluginRpcDispatcher([self])

    def set_firewall_status(self, context, firewall_id, status, **kwargs):
        """Agent uses this to set a firewall's status."""
        LOG.debug(_("set_firewall_status() called"))
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # ignore changing status if firewall expects to be deleted
            # That case means that while some pending operation has been
            # performed on the backend, neutron server received delete request
            # and changed firewall status to const.PENDING_DELETE
            if fw_db.status == const.PENDING_DELETE:
                LOG.debug(_("Firewall %(fw_id)s in PENDING_DELETE state, "
                            "not changing to %(status)s"),
                          {'fw_id': firewall_id, 'status': status})
                return False
            #TODO(xuhanp): Remove INACTIVE status and use DOWN to
            # be consistent with other network resources
            if status in (const.ACTIVE, const.INACTIVE, const.DOWN):
                fw_db.status = status
                return True
            else:
                fw_db.status = const.ERROR
                return False

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug(_("firewall_deleted() called"))
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # allow to delete firewalls in ERROR state
            if fw_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_firewall_object(context, firewall_id)
                return True
            else:
                fw_db.status = const.ERROR
                LOG.warn(_('Firewall %s unexpectedly deleted by agent.'),
                         firewall_id)
                return False

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        LOG.debug(_("get_firewalls_for_tenant() called"))
        fw_list = [
            self.plugin._make_firewall_dict_with_rules(context, fw['id'])
            for fw in self.plugin.get_firewalls(context)
        ]
        return fw_list

    def get_firewalls_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all firewalls for a tenant."""
        LOG.debug(_("get_firewalls_for_tenant_without_rules() called"))
        fw_list = [fw for fw in self.plugin.get_firewalls(context)]
        return fw_list

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        LOG.debug(_("get_tenants_with_firewalls() called"))
        ctx = neutron_context.get_admin_context()
        fw_list = self.plugin.get_firewalls(ctx)
        fw_tenant_list = list(set(fw['tenant_id'] for fw in fw_list))
        return fw_tenant_list


class FirewallAgentApi(proxy.RpcProxy):
    """Plugin side of plugin to agent RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, host):
        super(FirewallAgentApi, self).__init__(topic, self.API_VERSION)
        self.host = host

    def create_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('create_firewall', firewall=firewall,
                          host=self.host),
            topic=self.topic
        )

    def update_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('update_firewall', firewall=firewall,
                          host=self.host),
            topic=self.topic
        )

    def delete_firewall(self, context, firewall):
        return self.fanout_cast(
            context,
            self.make_msg('delete_firewall', firewall=firewall,
                          host=self.host),
            topic=self.topic
        )


class FirewallCountExceeded(n_exception.Conflict):

    """Reference implementation specific exception for firewall count.

    Only one firewall is supported per tenant. When a second
    firewall is tried to be created, this exception will be raised.
    """
    message = _("Exceeded allowed count of firewalls for tenant "
                "%(tenant_id)s. Only one firewall is supported per tenant.")


class FirewallPlugin(firewall_db.Firewall_db_mixin):

    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        qdbapi.register_models()

        self.callbacks = FirewallCallbacks(self)

        self.conn = rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN,
            self.callbacks.create_rpc_dispatcher(),
            fanout=False)
        self.conn.consume_in_thread()

        self.agent_rpc = FirewallAgentApi(
            topics.L3_AGENT,
            cfg.CONF.host
        )

    def _make_firewall_dict_with_rules(self, context, firewall_id):
        firewall = self.get_firewall(context, firewall_id)
        fw_policy_id = firewall['firewall_policy_id']
        if fw_policy_id:
            fw_policy = self.get_firewall_policy(context, fw_policy_id)
            fw_rules_list = [self.get_firewall_rule(
                context, rule_id) for rule_id in fw_policy['firewall_rules']]
            firewall['firewall_rule_list'] = fw_rules_list
        else:
            firewall['firewall_rule_list'] = []
        # FIXME(Sumit): If the size of the firewall object we are creating
        # here exceeds the largest message size supported by rabbit/qpid
        # then we will have a problem.
        return firewall

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        fw = super(FirewallPlugin, self).update_firewall(context, firewall_id,
                                                         status_update)
        if fw:
            fw_with_rules = (
                self._make_firewall_dict_with_rules(context,
                                                    firewall_id))
            self.agent_rpc.update_firewall(context, fw_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._rpc_update_firewall(context, firewall_id)

    def _ensure_update_firewall(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [const.PENDING_CREATE,
                               const.PENDING_UPDATE,
                               const.PENDING_DELETE]:
            raise fw_ext.FirewallInPendingState(firewall_id=firewall_id,
                                                pending_state=fwall['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy and 'firewall_list' in firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._ensure_update_firewall(context, firewall_id)

    def _ensure_update_or_delete_firewall_rule(self, context,
                                               firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if 'firewall_policy_id' in fw_rule and fw_rule['firewall_policy_id']:
            self._ensure_update_firewall_policy(context,
                                                fw_rule['firewall_policy_id'])

    def create_firewall(self, context, firewall):
        LOG.debug(_("create_firewall() called"))
        tenant_id = self._get_tenant_id_for_create(context,
                                                   firewall['firewall'])
        fw_count = self.get_firewalls_count(context,
                                            filters={'tenant_id': [tenant_id]})
        if fw_count:
            raise FirewallCountExceeded(tenant_id=tenant_id)
        firewall['firewall']['status'] = const.PENDING_CREATE
        fw = super(FirewallPlugin, self).create_firewall(context, firewall)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        self.agent_rpc.create_firewall(context, fw_with_rules)
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.debug(_("update_firewall() called"))
        self._ensure_update_firewall(context, id)
        firewall['firewall']['status'] = const.PENDING_UPDATE
        fw = super(FirewallPlugin, self).update_firewall(context, id, firewall)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        self.agent_rpc.update_firewall(context, fw_with_rules)
        return fw

    def delete_db_firewall_object(self, context, id):
        firewall = self.get_firewall(context, id)
        if firewall['status'] in [const.PENDING_DELETE]:
            super(FirewallPlugin, self).delete_firewall(context, id)

    def delete_firewall(self, context, id):
        LOG.debug(_("delete_firewall() called"))
        status_update = {"firewall": {"status": const.PENDING_DELETE}}
        fw = super(FirewallPlugin, self).update_firewall(context, id,
                                                         status_update)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        self.agent_rpc.delete_firewall(context, fw_with_rules)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug(_("update_firewall_policy() called"))
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).update_firewall_policy(context, id, firewall_policy)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug(_("update_firewall_rule() called"))
        self._ensure_update_or_delete_firewall_rule(context, id)
        fwr = super(FirewallPlugin,
                    self).update_firewall_rule(context, id, firewall_rule)
        firewall_policy_id = fwr['firewall_policy_id']
        if firewall_policy_id:
            self._rpc_update_firewall_policy(context, firewall_policy_id)
        return fwr

    def delete_firewall_rule(self, context, id):
        LOG.debug(_("delete_firewall_rule() called"))
        self._ensure_update_or_delete_firewall_rule(context, id)
        fwr = self.get_firewall_rule(context, id)
        firewall_policy_id = fwr['firewall_policy_id']
        super(FirewallPlugin, self).delete_firewall_rule(context, id)
        # At this point we have already deleted the rule in the DB,
        # however it's still not deleted on the backend firewall.
        # Until it gets deleted on the backend we will be setting
        # the firewall in PENDING_UPDATE state. The backend firewall
        # implementation is responsible for setting the appropriate
        # configuration (e.g. do not allow any traffic) until the rule
        # is deleted. Once the rule is deleted, the backend should put
        # the firewall back in ACTIVE state. While the firewall is in
        # PENDING_UPDATE state, the firewall behavior might differ based
        # on the backend implementation.
        if firewall_policy_id:
            self._rpc_update_firewall_policy(context, firewall_policy_id)

    def insert_rule(self, context, id, rule_info):
        LOG.debug(_("insert_rule() called"))
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).insert_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        return fwp

    def remove_rule(self, context, id, rule_info):
        LOG.debug(_("remove_rule() called"))
        self._ensure_update_firewall_policy(context, id)
        fwp = super(FirewallPlugin,
                    self).remove_rule(context, id, rule_info)
        self._rpc_update_firewall_policy(context, id)
        return fwp
