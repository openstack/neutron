# Copyright (c) 2016 Red Hat, Inc.
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

from oslo_log import log as logging
from ovs import vlog

LOG = logging.getLogger(__name__)


def use_oslo_logger():
    """Replace the OVS IDL logger functions with our logger"""

    # NOTE(twilson) Replace functions directly instead of subclassing so that
    # debug messages contain the correct function/filename/line information
    vlog.Vlog.emer = LOG.critical
    vlog.Vlog.err = LOG.error
    vlog.Vlog.warn = LOG.warning
    vlog.Vlog.info = LOG.info
    vlog.Vlog.dbg = LOG.debug
