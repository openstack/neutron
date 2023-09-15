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

from collections import namedtuple
import random

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib import exceptions as n_exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.services.logapi import constants as log_const
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.services import logging as log_cfg
from neutron.objects import securitygroup as sg_obj
from neutron.services.logapi.common import db_api
from neutron.services.logapi.common import sg_callback
from neutron.services.logapi.drivers import base
from neutron.services.logapi.drivers import manager

LOG = logging.getLogger(__name__)

DRIVER = None

log_cfg.register_log_driver_opts()

MAX_INT_LABEL = 2**32
SUPPORTED_LOGGING_TYPES = [log_const.SECURITY_GROUP]


class LoggingNotSupported(n_exceptions.NeutronException):
    message = _("The current OVN version does not offer support "
                "for neutron network log functionality.")


class OVNDriver(base.DriverBase):

    def __init__(self):
        super().__init__(
            name="ovn",
            vif_types=[portbindings.VIF_TYPE_OVS,
                       portbindings.VIF_TYPE_VHOST_USER],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_logging_types=SUPPORTED_LOGGING_TYPES,
            requires_rpc=False)
        self._log_plugin_property = None
        self.meter_name = (
                cfg.CONF.network_log.local_output_log_base or "acl_log_meter")

    @staticmethod
    def network_logging_supported(ovn_nb):
        columns = list(ovn_nb._tables["Meter"].columns)
        return ("fair" in columns)

    @classmethod
    def create(cls, plugin_driver):
        cls.plugin_driver = plugin_driver
        return OVNDriver()

    @property
    def _log_plugin(self):
        if self._log_plugin_property is None:
            self._log_plugin_property = directory.get_plugin(
                plugin_constants.LOG_API)
        return self._log_plugin_property

    @staticmethod
    def _log_dict_to_obj(log_dict):
        cls = namedtuple('Log_obj', log_dict)
        cls.__new__.__defaults__ = tuple(log_dict.values())
        return cls()

    def _get_logs(self, context):
        log_objs = self._log_plugin.get_logs(context)
        return [self._log_dict_to_obj(lo) for lo in log_objs]

    @property
    def _ovn_client(self):
        return self.plugin_driver._ovn_client

    @property
    def ovn_nb(self):
        return self.plugin_driver.nb_ovn

    @staticmethod
    def _acl_actions_enabled(log_obj):
        if not log_obj.enabled:
            return set()
        if log_obj.event == log_const.ACCEPT_EVENT:
            return {ovn_const.ACL_ACTION_ALLOW_RELATED,
                    ovn_const.ACL_ACTION_ALLOW_STATELESS,
                    ovn_const.ACL_ACTION_ALLOW}
        if log_obj.event == log_const.DROP_EVENT:
            return {ovn_const.ACL_ACTION_DROP,
                    ovn_const.ACL_ACTION_REJECT}
        # Fall through case: log_const.ALL_EVENT
        return {ovn_const.ACL_ACTION_DROP,
                ovn_const.ACL_ACTION_REJECT,
                ovn_const.ACL_ACTION_ALLOW_RELATED,
                ovn_const.ACL_ACTION_ALLOW_STATELESS,
                ovn_const.ACL_ACTION_ALLOW}

    def _remove_acls_log(self, pgs, ovn_txn, log_name=None):
        acl_absents, acl_changes, acl_visits = 0, 0, 0
        for pg in pgs:
            for acl_uuid in pg["acls"]:
                acl_visits += 1
                acl = self.ovn_nb.lookup("ACL", acl_uuid, default=None)
                # Log message if ACL is not found, as deleted concurrently
                if acl is None:
                    LOG.debug("ACL %s not found, deleted concurrently",
                              acl_uuid)
                    acl_absents += 1
                    continue
                # skip acls used by a different network log
                if log_name:
                    if acl.name and acl.name[0] != log_name:
                        continue
                columns = {
                    'log': False,
                    'meter': [],
                    'name': [],
                    'severity': []
                }
                # TODO(egarciar): There wont be a need to check if label exists
                # once minimum version for OVN is >= 22.03
                if hasattr(acl, 'label'):
                    columns['label'] = 0
                    ovn_txn.add(self.ovn_nb.db_remove(
                        "ACL", acl_uuid, 'options', 'log-related',
                        if_exists=True))
                ovn_txn.add(self.ovn_nb.db_set(
                    "ACL", acl_uuid, *columns.items()))
                acl_changes += 1
        msg = "Cleared %d, Not found %d (out of %d visited) ACLs"
        if log_name:
            msg += " for network log {}".format(log_name)
        LOG.info(msg, acl_changes, acl_absents, acl_visits)

    def _set_acls_log(self, pgs, context, ovn_txn, actions_enabled, log_name):
        acl_changes, acl_visits = 0, 0
        for pg in pgs:
            meter_name = self.meter_name
            if pg["name"] != ovn_const.OVN_DROP_PORT_GROUP_NAME:
                sg = sg_obj.SecurityGroup.get_sg_by_id(
                    context,
                    pg["external_ids"][ovn_const.OVN_SG_EXT_ID_KEY])
                if not sg:
                    LOG.warning("Port Group %s is missing a corresponding "
                                "security group, skipping its network log "
                                "setting...", pg["name"])
                    continue
                if not sg.stateful:
                    meter_name = meter_name + ("_stateless")
            for acl_uuid in pg["acls"]:
                acl_visits += 1
                acl = self.ovn_nb.lookup("ACL", acl_uuid)
                # skip acls used by a different network log
                if acl.name and acl.name[0] != log_name:
                    continue
                columns = {
                    'log': acl.action in actions_enabled,
                    'meter': meter_name,
                    'name': log_name,
                    'severity': "info"
                }
                # TODO(egarciar): There wont be a need to check if label exists
                # once minimum version for OVN is >= 22.03
                if hasattr(acl, "label"):
                    # Label needs to be an unsigned 32 bit number and not 0.
                    columns["label"] = random.randrange(1, MAX_INT_LABEL)
                    columns["options"] = {'log-related': "true"}
                ovn_txn.add(self.ovn_nb.db_set(
                    "ACL", acl_uuid, *columns.items()))
                acl_changes += 1
        LOG.info("Set %d (out of %d visited) ACLs for network log %s",
                 acl_changes, acl_visits, log_name)

    def _update_log_objs(self, context, ovn_txn, log_objs):
        for log_obj in log_objs:
            pgs = self._pgs_from_log_obj(context, log_obj)
            actions_enabled = self._acl_actions_enabled(log_obj)
            self._set_acls_log(pgs, context, ovn_txn, actions_enabled,
                               utils.ovn_name(log_obj.id))

    def _pgs_all(self):
        return self.ovn_nb.db_list(
            "Port_Group",
            columns=["name", "external_ids", "acls"]).execute(check_error=True)

    def _pgs_from_log_obj(self, context, log_obj):
        """Map Neutron log_obj into affected port groups in OVN.

        :param context: current running context information
        :param log_obj: a log_object to be analyzed.

        """
        if not log_obj.resource_id and not log_obj.target_id:
            # No sg, no port, ALL: return all pgs
            if log_obj.event == log_const.ALL_EVENT:
                return self._pgs_all()
            try:
                pg_drop = self.ovn_nb.lookup("Port_Group",
                    ovn_const.OVN_DROP_PORT_GROUP_NAME)
                # No sg, no port, DROP: return DROP pg
                if log_obj.event == log_const.DROP_EVENT:
                    return [{"name": pg_drop.name,
                             "external_ids": pg_drop.external_ids,
                             "acls": [r.uuid for r in pg_drop.acls]}]
                # No sg, no port, ACCEPT: return all except DROP pg
                pgs = self._pgs_all()
                pgs.remove({"name": pg_drop.name,
                            "external_ids": pg_drop.external_ids,
                            "acls": [r.uuid for r in pg_drop.acls]})
                return pgs
            except idlutils.RowNotFound:
                pass
        pgs = []
        # include special pg_drop to log DROP and ALL actions
        if not log_obj.event or log_obj.event in (log_const.DROP_EVENT,
                                                  log_const.ALL_EVENT):
            try:
                pg = self.ovn_nb.lookup("Port_Group",
                                        ovn_const.OVN_DROP_PORT_GROUP_NAME)
                pgs.append({"name": pg.name,
                            "external_ids": pg.external_ids,
                            "acls": [r.uuid for r in pg.acls]})
            except idlutils.RowNotFound:
                pass
            if log_obj.event == log_const.DROP_EVENT:
                return pgs

        if log_obj.resource_id:
            try:
                pg = self.ovn_nb.lookup("Port_Group",
                                        utils.ovn_port_group_name(
                                            log_obj.resource_id))
                pgs.append({"name": pg.name,
                            "external_ids": pg.external_ids,
                            "acls": [r.uuid for r in pg.acls]})
            except idlutils.RowNotFound:
                pass
            # Note: when sg is provided, it is redundant to get sgs from port,
            # because model will ensure that sg is associated with neutron port
        elif log_obj.target_id:
            sg_ids = db_api._get_sgs_attached_to_port(context,
                                                      log_obj.target_id)
            for sg_id in sg_ids:
                try:
                    pg = self.ovn_nb.lookup("Port_Group",
                                            utils.ovn_port_group_name(sg_id))
                    pgs.append({"name": pg.name,
                                "external_ids": pg.external_ids,
                                "acls": [r.uuid for r in pg.acls]})
                except idlutils.RowNotFound:
                    pass
        return pgs

    def create_log(self, context, log_obj):
        """Create a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log objects being created
        """
        LOG.debug("Create_log %s", log_obj)

        pgs = self._pgs_from_log_obj(context, log_obj)
        actions_enabled = self._acl_actions_enabled(log_obj)
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._ovn_client.create_ovn_fair_meter(self.meter_name,
                                                   txn=ovn_txn)
            self._set_acls_log(pgs, context, ovn_txn, actions_enabled,
                               utils.ovn_name(log_obj.id))

    def create_log_precommit(self, context, log_obj):
        """Create a log_obj precommit.

        :param context: current running context information
        :param log_obj: a log object being created
        """
        LOG.debug("Create_log_precommit %s", log_obj)

        if not self.network_logging_supported(self.ovn_nb):
            raise LoggingNotSupported()

    def _unset_disabled_acls(self, context, log_obj, ovn_txn):
        """Check if we need to disable any ACLs after an update.

        Will return True if there were more logs, and False if there was
        nothing to check.

        :param context: current running context information
        :param log_obj: a log_object which was updated
        :returns: True if there were other logs enabled, otherwise False.
        """
        if log_obj.enabled:
            return False

        pgs = self._pgs_from_log_obj(context, log_obj)
        other_logs = [log for log in self._get_logs(context)
                      if log.id != log_obj.id and log.enabled]
        if not other_logs:
            return False

        if log_obj.event == log_const.ALL_EVENT:
            acls_to_check = pgs[0]["acls"].copy()
            if not acls_to_check:
                return True
            for log in other_logs:
                for acl in self._pgs_from_log_obj(context, log)[0]["acls"]:
                    if acl in acls_to_check:
                        acls_to_check.remove(acl)
                    if not acls_to_check:
                        return True
            acls_to_remove = [{"name": pgs[0]["name"], "acls": acls_to_check}]
            self._remove_acls_log(acls_to_remove, ovn_txn)
        else:
            all_events = set([log.event for log in other_logs
                if (not log.resource_id or
                    log.resource_id == log_obj.resource_id)])
            if (log_const.ALL_EVENT not in all_events and
                    log_obj.event not in all_events):
                self._remove_acls_log(pgs, ovn_txn)
        return True

    def update_log(self, context, log_obj):
        """Update a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log object being updated

        """
        LOG.debug("Update_log %s", log_obj)

        with self.ovn_nb.transaction(check_error=True) as ovn_txn:

            if not self._unset_disabled_acls(context, log_obj, ovn_txn):
                pgs = self._pgs_from_log_obj(context, log_obj)
                actions_enabled = self._acl_actions_enabled(log_obj)
                self._set_acls_log(pgs, context, ovn_txn, actions_enabled,
                                   utils.ovn_name(log_obj.id))

    def delete_log(self, context, log_obj):
        """Delete a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log_object being deleted

        """
        LOG.debug("Delete_log %s", log_obj)

        # If we are removing the last log_obj, let's clear log from all acls.
        # This is a simple way of ensuring that no acl logs are left behind!
        log_objs = self._get_logs(context)
        if not log_objs or (
                len(log_objs) == 1 and log_objs[0].id == log_obj.id):
            pgs = self._pgs_all()
            with self.ovn_nb.transaction(check_error=True) as ovn_txn:
                self._remove_acls_log(pgs, ovn_txn)
                ovn_txn.add(self.ovn_nb.meter_del(self.meter_name,
                                                  if_exists=True))
                ovn_txn.add(self.ovn_nb.meter_del(
                    self.meter_name + "_stateless", if_exists=True))
            LOG.info("All ACL logs cleared after deletion of log_obj %s",
                     log_obj.id)
            return

        # Remove log_obj and revisit all remaining ones, since the acls that
        # were serving the removed log_obj may be usable by the remaining
        # log_objs.
        pgs = self._pgs_from_log_obj(context, log_obj)
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._remove_acls_log(pgs, ovn_txn, utils.ovn_name(log_obj.id))

        # TODO(flaviof): We needed to break this second part into a separate
        # transaction because logic that determines the value of the 'freed up'
        # acl rows will not see the modified rows unless it was inside an an
        # idl command.
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._update_log_objs(context, ovn_txn, [lo for lo in log_objs
                                                     if lo.id != log_obj.id])

    def resource_update(self, context, log_objs):
        """Tell the agent when resources related to log_objects are
        being updated

        :param context: current running context information
        :param log_objs: a list of log_objects, whose related resources are
                         being updated.
        """
        LOG.debug("Resource_update %s", log_objs)

        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._update_log_objs(context, ovn_txn, log_objs)


def register(plugin_driver):
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = OVNDriver.create(plugin_driver)

    # Trigger decorator
    importutils.import_module(
        "neutron.services.logapi.common.sg_validate"
    )
    # Register resource callback handler
    manager.register(
        resources.SECURITY_GROUP_RULE, sg_callback.SecurityGroupRuleCallBack)

    LOG.info("OVN logging driver registered")
    return DRIVER
