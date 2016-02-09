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

import logging as sys_logging

from oslo_reports import guru_meditation_report as gmr

from neutron import version

# During the call to gmr.TextGuruMeditation.setup_autorun(), Guru Meditation
# Report tries to start logging. Set a handler here to accommodate this.
logger = sys_logging.getLogger(None)
if not logger.handlers:
    logger.addHandler(sys_logging.StreamHandler())

_version_string = version.version_info.release_string()
gmr.TextGuruMeditation.setup_autorun(version=_version_string)
