# Copyright (c) 2026 OpenStack Foundation
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

import errno
import grp
import os
import pwd

from oslo_log import log as logging

from neutron.agent.common import utils


LOG = logging.getLogger(__name__)

HA_STATE_FILENAME = 'state'


def get_ha_state_path(conf_dir):
    return os.path.join(conf_dir, HA_STATE_FILENAME)


def _resolve_uid_gid(user, group):
    try:
        uid = int(user)
    except (TypeError, ValueError):
        uid = pwd.getpwnam(user).pw_uid
    try:
        gid = int(group)
    except (TypeError, ValueError):
        gid = grp.getgrnam(group).gr_gid
    return uid, gid


def prepare_ha_state_path(state_path, user, group):
    """Fix ownership of the HA state path while running as root.

    ``neutron-keepalived-state-change`` is launched via rootwrap and must
    ensure the state file and its parent directory are owned by the L3 agent
    user before writing the state.

    :param state_path: full path to the HA state file
    :param user: target user name or uid
    :param group: target group name or gid
    """
    if os.geteuid() != 0:
        return

    uid, gid = _resolve_uid_gid(user, group)
    conf_dir = os.path.dirname(state_path)
    for path in (conf_dir, state_path):
        if not os.path.exists(path):
            continue
        stat = os.stat(path)
        if stat.st_uid == uid and stat.st_gid == gid:
            continue
        utils.execute(
            ['chown', '-R', '%s:%s' % (uid, gid), path],
            run_as_root=True, privsep_exec=True)
        LOG.info('Fixed ownership of HA state path %(path)s to '
                 'uid/gid %(uid)s/%(gid)s',
                 {'path': path, 'uid': uid, 'gid': gid})


def write_ha_state_file(state_path, state):
    """Write the HA router state, handling legacy root-owned state files.

    Deployments that ran ``neutron-keepalived-state-change`` as root may have
    left a root-owned ``state`` file in a directory owned by the L3 agent
    user.  In that case the agent user can unlink the file (directory write
    permission is sufficient) and recreate it.
    """
    for attempt in (1, 2):
        try:
            with open(state_path, 'w') as state_file:
                state_file.write(state)
            return
        except OSError as error:
            if error.errno != errno.EACCES or attempt == 2:
                raise
            try:
                os.remove(state_path)
            except OSError as remove_error:
                LOG.warning('Could not remove legacy root-owned HA state '
                            'file %(path)s: %(error)s',
                            {'path': state_path, 'error': remove_error})
                raise error from remove_error
            LOG.info('Removed legacy root-owned HA state file %s before '
                     'recreating it', state_path)
