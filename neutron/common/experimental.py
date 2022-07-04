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


from oslo_config import cfg
from oslo_log import log

from neutron.conf import experimental


LOG = log.getLogger(__name__)


CONF = cfg.CONF
experimental.register_experimental_opts()


def validate_experimental_enabled(feature):
    try:
        is_enabled = cfg.CONF.experimental[feature]
    except cfg.NoSuchOptError:
        LOG.error("Experimental feature '%s' doesn't exist", feature)
        raise SystemExit(1)
    if is_enabled:
        LOG.warning("Feature '%s' is unsupported and is treated as "
                    "experimental. Use at your own risk.", feature)
    else:
        LOG.error("Feature '%s' is experimental and has to be explicitly "
                  "enabled in 'cfg.CONF.experimental'", feature)
        raise SystemExit(1)
