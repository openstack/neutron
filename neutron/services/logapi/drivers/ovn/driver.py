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
from neutron.services.logapi.common import db_api
from neutron.services.logapi.common import sg_callback
from neutron.services.logapi.drivers import base
from neutron.services.logapi.drivers import manager

LOG = logging.getLogger(__name__)

DRIVER = None

log_cfg.register_log_driver_opts()

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
    def ovn_nb(self):
        return self.plugin_driver.nb_ovn

    def _create_ovn_fair_meter(self, ovn_txn):
        """Create row in Meter table with fair attribute set to True.

        Create a row in OVN's NB Meter table based on well-known name. This
        method uses the network_log configuration to specify the attributes
        of the meter. Current implementation needs only one 'fair' meter row
        which is then referred by multiple ACL rows.

        :param ovn_txn: ovn nortbound idl transaction.

        """
        meter = self.ovn_nb.db_find_rows(
            "Meter", ("name", "=", self.meter_name)).execute(check_error=True)
        if meter:
            meter = meter[0]
            try:
                meter_band = self.ovn_nb.lookup("Meter_Band",
                                                meter.bands[0].uuid)
                if all((meter.unit == "pktps",
                        meter.fair[0],
                        meter_band.rate == cfg.CONF.network_log.rate_limit,
                        meter_band.burst_size ==
                        cfg.CONF.network_log.burst_limit)):
                    # Meter (and its meter-band) unchanged: noop.
                    return
            except idlutils.RowNotFound:
                pass
            # Re-create meter (and its meter-band) with the new attributes.
            # This is supposed to happen only if configuration changed, so
            # doing updates is an overkill: better to leverage the ovsdbapp
            # library to avoid the complexity.
            ovn_txn.add(self.ovn_nb.meter_del(meter.uuid))
        # Create meter
        LOG.info("Creating network log fair meter %s", self.meter_name)
        ovn_txn.add(self.ovn_nb.meter_add(
            name=self.meter_name,
            unit="pktps",
            rate=cfg.CONF.network_log.rate_limit,
            fair=True,
            burst_size=cfg.CONF.network_log.burst_limit,
            may_exist=False,
            external_ids={ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                          log_const.LOGGING_PLUGIN}))

    @staticmethod
    def _acl_actions_enabled(log_obj):
        if not log_obj.enabled:
            return set()
        if log_obj.event == log_const.ACCEPT_EVENT:
            return {ovn_const.ACL_ACTION_ALLOW_RELATED,
                    ovn_const.ACL_ACTION_ALLOW}
        if log_obj.event == log_const.DROP_EVENT:
            return {ovn_const.ACL_ACTION_DROP,
                    ovn_const.ACL_ACTION_REJECT}
        # Fall through case: log_const.ALL_EVENT
        return {ovn_const.ACL_ACTION_DROP,
                ovn_const.ACL_ACTION_REJECT,
                ovn_const.ACL_ACTION_ALLOW_RELATED,
                ovn_const.ACL_ACTION_ALLOW}

    def _remove_acls_log(self, pgs, ovn_txn, log_name=None):
        acl_changes, acl_visits = 0, 0
        for pg in pgs:
            for acl_uuid in pg["acls"]:
                acl_visits += 1
                # skip acls used by a different network log
                if log_name:
                    acl = self.ovn_nb.lookup("ACL", acl_uuid)
                    if acl.name and acl.name[0] != log_name:
                        continue
                ovn_txn.add(self.ovn_nb.db_set(
                    "ACL", acl_uuid,
                    ("log", False),
                    ("meter", []),
                    ("name", []),
                    ("severity", [])
                ))
                acl_changes += 1
        msg = "Cleared %d (out of %d visited) ACLs"
        if log_name:
            msg += " for network log {}".format(log_name)
        LOG.info(msg, acl_changes, acl_visits)

    def _set_acls_log(self, pgs, ovn_txn, actions_enabled, log_name):
        acl_changes, acl_visits = 0, 0
        for pg in pgs:
            for acl_uuid in pg["acls"]:
                acl_visits += 1
                acl = self.ovn_nb.lookup("ACL", acl_uuid)
                # skip acls used by a different network log
                if acl.name and acl.name[0] != log_name:
                    continue
                ovn_txn.add(self.ovn_nb.db_set(
                    "ACL", acl_uuid,
                    ("log", acl.action in actions_enabled),
                    ("meter", self.meter_name),
                    ("name", log_name),
                    ("severity", "info")
                ))
                acl_changes += 1
        LOG.info("Set %d (out of %d visited) ACLs for network log %s",
                 acl_changes, acl_visits, log_name)

    def _update_log_objs(self, context, ovn_txn, log_objs):
        for log_obj in log_objs:
            pgs = self._pgs_from_log_obj(context, log_obj)
            actions_enabled = self._acl_actions_enabled(log_obj)
            self._set_acls_log(pgs, ovn_txn, actions_enabled,
                               utils.ovn_name(log_obj.id))

    def _pgs_all(self):
        return self.ovn_nb.db_list(
            "Port_Group", columns=["name", "acls"]).execute(check_error=True)

    def _pgs_from_log_obj(self, context, log_obj):
        """Map Neutron log_obj into affected port groups in OVN.

        :param context: current running context information
        :param log_obj: a log_object to be analyzed.

        """
        if not log_obj.resource_id and not log_obj.target_id:
            # No sg, no port: return all pgs
            return self._pgs_all()

        pgs = []
        # include special pg_drop to log DROP and ALL actions
        if not log_obj.event or log_obj.event in (log_const.DROP_EVENT,
                                                  log_const.ALL_EVENT):
            try:
                pg = self.ovn_nb.lookup("Port_Group",
                                        ovn_const.OVN_DROP_PORT_GROUP_NAME)
                pgs.append({"name": pg.name,
                            "acls": [r.uuid for r in pg.acls]})
            except idlutils.RowNotFound:
                pass

        if log_obj.resource_id:
            try:
                pg = self.ovn_nb.lookup("Port_Group",
                                        utils.ovn_port_group_name(
                                            log_obj.resource_id))
                pgs.append({"name": pg.name,
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
            self._create_ovn_fair_meter(ovn_txn)
            self._set_acls_log(pgs, ovn_txn, actions_enabled,
                               utils.ovn_name(log_obj.id))

    def create_log_precommit(self, context, log_obj):
        """Create a log_obj precommit.

        :param context: current running context information
        :param log_obj: a log object being created
        """
        LOG.debug("Create_log_precommit %s", log_obj)

        if not self.network_logging_supported(self.ovn_nb):
            raise LoggingNotSupported()

    def update_log(self, context, log_obj):
        """Update a log_obj invocation.

        :param context: current running context information
        :param log_obj: a log object being updated

        """
        LOG.debug("Update_log %s", log_obj)

        pgs = self._pgs_from_log_obj(context, log_obj)
        actions_enabled = self._acl_actions_enabled(log_obj)
        with self.ovn_nb.transaction(check_error=True) as ovn_txn:
            self._set_acls_log(pgs, ovn_txn, actions_enabled,
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
