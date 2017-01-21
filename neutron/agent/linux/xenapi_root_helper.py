# Copyright (c) 2016 Citrix System.
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

"""xenapi root helper

For xenapi, we may need to run some commands in dom0 with additional privilege.
This xenapi root helper contains the class of XenAPIClient to support it:
XenAPIClient will keep a XenAPI session to dom0 and allow to run commands
in dom0 via calling XenAPI plugin. The XenAPI plugin is responsible to
determine whether a command is safe to execute.
"""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_rootwrap import cmd as oslo_rootwrap_cmd
from oslo_serialization import jsonutils

from neutron._i18n import _LE
from neutron.conf.agent import xenapi_conf


ROOT_HELPER_DAEMON_TOKEN = 'xenapi_root_helper'

RC_UNKNOWN_XENAPI_ERROR = 80
MSG_UNAUTHORIZED = "Unauthorized command"
MSG_NOT_FOUND = "Executable not found"
XENAPI_PLUGIN_FAILURE_ID = "XENAPI_PLUGIN_FAILURE"

LOG = logging.getLogger(__name__)
xenapi_conf.register_xenapi_opts(cfg.CONF)


class XenAPIClient(object):
    def __init__(self):
        self._session = None
        self._host = None
        self._XenAPI = None

    def _call_plugin(self, plugin, fn, args):
        host = self._this_host()
        return self.get_session().xenapi.host.call_plugin(
            host, plugin, fn, args)

    def _create_session(self, url, username, password):
        session = self._get_XenAPI().Session(url)
        session.login_with_password(username, password)
        return session

    def _get_return_code(self, failure_details):
        # The details will be as:
        # [XENAPI_PLUGIN_FAILURE_ID, methodname, except_class_name, message]
        # We can distinguish the error type by checking the message string.
        if (len(failure_details) == 4 and
            XENAPI_PLUGIN_FAILURE_ID == failure_details[0]):
            if (MSG_UNAUTHORIZED == failure_details[3]):
                return oslo_rootwrap_cmd.RC_UNAUTHORIZED
            elif (MSG_NOT_FOUND == failure_details[3]):
                return oslo_rootwrap_cmd.RC_NOEXECFOUND
        # otherwise we get unexpected exception.
        return RC_UNKNOWN_XENAPI_ERROR

    def _get_XenAPI(self):
        # Delay importing XenAPI as this module may not exist
        # for non-XenServer hypervisors.
        if self._XenAPI is None:
            import XenAPI
            self._XenAPI = XenAPI
        return self._XenAPI

    def _this_host(self):
        if not self._host:
            session = self.get_session()
            self._host = session.xenapi.session.get_this_host(session.handle)
        return self._host

    def execute(self, cmd, stdin=None):
        out = ""
        err = ""
        if cmd is None or len(cmd) == 0:
            err = "No command specified."
            return oslo_rootwrap_cmd.RC_NOCOMMAND, out, err
        try:
            result_raw = self._call_plugin(
                'netwrap', 'run_command',
                {'cmd': jsonutils.dumps(cmd),
                 'cmd_input': jsonutils.dumps(stdin)})
            result = jsonutils.loads(result_raw)
            returncode = result['returncode']
            out = result['out']
            err = result['err']
            return returncode, out, err
        except self._get_XenAPI().Failure as failure:
            LOG.exception(_LE('Failed to execute command: %s'), cmd)
            returncode = self._get_return_code(failure.details)
            return returncode, out, err

    def get_session(self):
        if self._session is None:
            url = cfg.CONF.xenapi.connection_url
            username = cfg.CONF.xenapi.connection_username
            password = cfg.CONF.xenapi.connection_password
            try:
                self._session = self._create_session(url, username, password)
            except Exception:
                # Shouldn't reach here, otherwise it's a fatal error.
                LOG.exception(_LE("Failed to initiate XenAPI session"))
                raise SystemExit(1)
        return self._session
