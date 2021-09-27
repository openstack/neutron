# Copyright (C) 2014,2015 VA Linux Systems Japan K.K.
# Copyright (C) 2014,2015 YAMAMOTO Takashi <yamamoto at valinux co jp>
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

import functools
import random

import debtcollector
import eventlet
import netaddr
from neutron_lib import exceptions
import os_ken.app.ofctl.api as ofctl_api
from os_ken.app.ofctl import exception as ofctl_exc
import os_ken.exception as os_ken_exc
from os_ken.lib import ofctl_string
from os_ken.ofproto import ofproto_parser
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import timeutils
import tenacity

from neutron._i18n import _
from neutron.agent.common import ovs_lib

LOG = logging.getLogger(__name__)

BUNDLE_ID_WIDTH = 1 << 32
COOKIE_DEFAULT = object()


class ActiveBundleRunning(exceptions.NeutronException):
    message = _("Another active bundle 0x%(bundle_id)x is running")


class OpenFlowSwitchMixin(object):
    """Mixin to provide common convenient routines for an openflow switch.

    NOTE(yamamoto): super() points to ovs_lib.OVSBridge.
    See ovs_bridge.py how this class is actually used.
    """

    @staticmethod
    def _cidr_to_os_ken(ip):
        n = netaddr.IPNetwork(ip)
        if n.hostmask:
            return (str(n.ip), str(n.netmask))
        return str(n.ip)

    def __init__(self, *args, **kwargs):
        self._app = kwargs.pop('os_ken_app')
        self.active_bundles = set()
        super(OpenFlowSwitchMixin, self).__init__(*args, **kwargs)

    def _get_dp_by_dpid(self, dpid_int):
        """Get os-ken datapath object for the switch."""
        timeout_sec = cfg.CONF.OVS.of_connect_timeout
        start_time = timeutils.now()
        while True:
            dp = ofctl_api.get_datapath(self._app, dpid_int)
            if dp is not None:
                break
            # The switch has not established a connection to us; retry again
            # until timeout.
            if timeutils.now() > start_time + timeout_sec:
                m = _("Switch connection timeout")
                LOG.error(m)
                # NOTE(yamamoto): use RuntimeError for compat with ovs_lib
                raise RuntimeError(m)
        return dp

    @staticmethod
    @tenacity.retry(
        retry=tenacity.retry_if_exception_type(ofctl_exc.InvalidDatapath),
        wait=tenacity.wait_exponential(multiplier=0.02, max=1),
        stop=tenacity.stop_after_delay(5),
        reraise=True)
    def _send_msg_retry(app, msg, reply_cls, reply_multi):
        return ofctl_api.send_msg(app, msg, reply_cls, reply_multi)

    def _send_msg(self, msg, reply_cls=None, reply_multi=False,
                  active_bundle=None):
        timeout_sec = cfg.CONF.OVS.of_request_timeout
        timeout = eventlet.Timeout(seconds=timeout_sec)
        if active_bundle is not None:
            (dp, ofp, ofpp) = self._get_dp()
            msg = ofpp.ONFBundleAddMsg(dp, active_bundle['id'],
                                       active_bundle['bundle_flags'], msg, [])
        try:
            result = self._send_msg_retry(self._app, msg, reply_cls,
                                          reply_multi)
        except os_ken_exc.OSKenException as e:
            m = _("ofctl request %(request)s error %(error)s") % {
                "request": msg,
                "error": e,
            }
            LOG.error(m)
            # NOTE(yamamoto): use RuntimeError for compat with ovs_lib
            raise RuntimeError(m)
        except eventlet.Timeout as e:
            with excutils.save_and_reraise_exception() as ctx:
                if e is timeout:
                    ctx.reraise = False
                    m = _("ofctl request %(request)s timed out") % {
                        "request": msg,
                    }
                    LOG.error(m)
                    # NOTE(yamamoto): use RuntimeError for compat with ovs_lib
                    raise RuntimeError(m)
        finally:
            timeout.cancel()
        LOG.debug("ofctl request %(request)s result %(result)s",
                  {"request": msg, "result": result})
        return result

    @staticmethod
    def _match(_ofp, ofpp, match, **match_kwargs):
        if match is not None:
            return match
        return ofpp.OFPMatch(**match_kwargs)

    def uninstall_flows(self, table_id=None, strict=False, priority=0,
                        cookie=COOKIE_DEFAULT, cookie_mask=0,
                        match=None, active_bundle=None, **match_kwargs):
        (dp, ofp, ofpp) = self._get_dp()
        if table_id is None:
            table_id = ofp.OFPTT_ALL

        if cookie == ovs_lib.COOKIE_ANY:
            cookie = 0
            if cookie_mask != 0:
                raise Exception(_("cookie=COOKIE_ANY but cookie_mask set to "
                                  "%s") %
                                cookie_mask)
        elif cookie == COOKIE_DEFAULT:
            cookie = self._default_cookie
            cookie_mask = ovs_lib.UINT64_BITMASK

        match = self._match(ofp, ofpp, match, **match_kwargs)
        if strict:
            cmd = ofp.OFPFC_DELETE_STRICT
        else:
            cmd = ofp.OFPFC_DELETE
        msg = ofpp.OFPFlowMod(dp,
                              command=cmd,
                              cookie=cookie,
                              cookie_mask=cookie_mask,
                              table_id=table_id,
                              match=match,
                              priority=priority,
                              out_group=ofp.OFPG_ANY,
                              out_port=ofp.OFPP_ANY)
        self._send_msg(msg, active_bundle=active_bundle)

    def dump_flows(self, table_id=None):
        (dp, ofp, ofpp) = self._get_dp()
        if table_id is None:
            table_id = ofp.OFPTT_ALL
        msg = ofpp.OFPFlowStatsRequest(dp, table_id=table_id)
        replies = self._send_msg(msg,
                                 reply_cls=ofpp.OFPFlowStatsReply,
                                 reply_multi=True)
        flows = []
        for rep in replies:
            flows += rep.body
        return flows

    def _dump_and_clean(self, table_id=None):
        cookies = set([f.cookie for f in self.dump_flows(table_id)]) - \
                      self.reserved_cookies
        for c in cookies:
            LOG.warning("Deleting flow with cookie 0x%(cookie)x",
                        {'cookie': c})
            self.uninstall_flows(cookie=c, cookie_mask=ovs_lib.UINT64_BITMASK)

    def cleanup_flows(self):
        LOG.info("Reserved cookies for %s: %s", self.br_name,
                 self.reserved_cookies)

        for table_id in self.of_tables:
            self._dump_and_clean(table_id)

    def install_goto_next(self, table_id, active_bundle=None):
        self.install_goto(table_id=table_id, dest_table_id=table_id + 1,
                          active_bundle=active_bundle)

    def install_output(self, port, table_id=0, priority=0,
                       match=None, **match_kwargs):
        (_dp, ofp, ofpp) = self._get_dp()
        actions = [ofpp.OFPActionOutput(port, 0)]
        instructions = [ofpp.OFPInstructionActions(
                        ofp.OFPIT_APPLY_ACTIONS, actions)]
        self.install_instructions(table_id=table_id, priority=priority,
                                  instructions=instructions,
                                  match=match, **match_kwargs)

    def install_normal(self, table_id=0, priority=0,
                       match=None, **match_kwargs):
        (_dp, ofp, _ofpp) = self._get_dp()
        self.install_output(port=ofp.OFPP_NORMAL,
                            table_id=table_id, priority=priority,
                            match=match, **match_kwargs)

    def install_goto(self, dest_table_id, table_id=0, priority=0,
                     match=None, **match_kwargs):
        (_dp, _ofp, ofpp) = self._get_dp()
        instructions = [ofpp.OFPInstructionGotoTable(table_id=dest_table_id)]
        self.install_instructions(table_id=table_id, priority=priority,
                                  instructions=instructions,
                                  match=match, **match_kwargs)

    def install_drop(self, table_id=0, priority=0, match=None, **match_kwargs):
        self.install_instructions(table_id=table_id, priority=priority,
                                  instructions=[], match=match, **match_kwargs)

    def install_instructions(self, instructions,
                             table_id=0, priority=0,
                             match=None, active_bundle=None, **match_kwargs):
        (dp, ofp, ofpp) = self._get_dp()
        match = self._match(ofp, ofpp, match, **match_kwargs)
        if isinstance(instructions, str):
            debtcollector.deprecate("Use of string instruction is "
                "deprecated", removal_version='U')
            jsonlist = ofctl_string.ofp_instruction_from_str(
                ofp, instructions)
            instructions = ofproto_parser.ofp_instruction_from_jsondict(
                dp, jsonlist)
        msg = ofpp.OFPFlowMod(dp,
                              table_id=table_id,
                              cookie=self.default_cookie,
                              match=match,
                              priority=priority,
                              instructions=instructions)
        self._send_msg(msg, active_bundle=active_bundle)

    def install_apply_actions(self, actions,
                              table_id=0, priority=0,
                              match=None, **match_kwargs):
        (dp, ofp, ofpp) = self._get_dp()
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        self.install_instructions(table_id=table_id,
                                  priority=priority,
                                  match=match,
                                  instructions=instructions,
                                  **match_kwargs)

    def bundled(self, atomic=False, ordered=False):
        return BundledOpenFlowBridge(self, atomic, ordered)


class BundledOpenFlowBridge(object):
    def __init__(self, br, atomic, ordered):
        self.br = br
        self.active_bundle = None
        self.bundle_flags = 0
        if not atomic and not ordered:
            return
        (dp, ofp, ofpp) = self.br._get_dp()
        if atomic:
            self.bundle_flags |= ofp.ONF_BF_ATOMIC
        if ordered:
            self.bundle_flags |= ofp.ONF_BF_ORDERED

    def __getattr__(self, name):
        if name.startswith('install') or name.startswith('uninstall'):
            under = getattr(self.br, name)
            if self.active_bundle is None:
                return under
            return functools.partial(under, active_bundle=dict(
                id=self.active_bundle, bundle_flags=self.bundle_flags))
        raise AttributeError(_("Only install_* or uninstall_* methods "
                               "can be used"))

    def __enter__(self):
        if self.active_bundle is not None:
            raise ActiveBundleRunning(bundle_id=self.active_bundle)
        while True:
            self.active_bundle = random.randrange(BUNDLE_ID_WIDTH)
            if self.active_bundle not in self.br.active_bundles:
                self.br.active_bundles.add(self.active_bundle)
                break
        try:
            (dp, ofp, ofpp) = self.br._get_dp()
            msg = ofpp.ONFBundleCtrlMsg(dp, self.active_bundle,
                                        ofp.ONF_BCT_OPEN_REQUEST,
                                        self.bundle_flags, [])
            reply = self.br._send_msg(msg, reply_cls=ofpp.ONFBundleCtrlMsg)
            if reply.type != ofp.ONF_BCT_OPEN_REPLY:
                raise RuntimeError(
                    _("Unexpected reply type %d != ONF_BCT_OPEN_REPLY") %
                    reply.type)
            return self
        except Exception:
            self.br.active_bundles.remove(self.active_bundle)
            self.active_bundle = None
            raise

    def __exit__(self, type, value, traceback):
        (dp, ofp, ofpp) = self.br._get_dp()
        if type is None:
            ctrl_type = ofp.ONF_BCT_COMMIT_REQUEST
            expected_reply = ofp.ONF_BCT_COMMIT_REPLY
        else:
            ctrl_type = ofp.ONF_BCT_DISCARD_REQUEST
            expected_reply = ofp.ONF_BCT_DISCARD_REPLY
            LOG.warning(
                "Discarding bundle with ID 0x%(id)x due to an exception",
                {'id': self.active_bundle})

        try:
            msg = ofpp.ONFBundleCtrlMsg(dp, self.active_bundle,
                                        ctrl_type,
                                        self.bundle_flags, [])
            reply = self.br._send_msg(msg, reply_cls=ofpp.ONFBundleCtrlMsg)
            if reply.type != expected_reply:
                # The bundle ID may be in a bad state.  Let's leave it
                # in active_bundles so that we will never use it again.
                raise RuntimeError(_("Unexpected reply type %d") % reply.type)
            self.br.active_bundles.remove(self.active_bundle)
        finally:
            # It is possible the bundle is kept open, but this must be
            # cleared or all subsequent __enter__ will fail.
            self.active_bundle = None
