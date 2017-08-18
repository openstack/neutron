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

from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
import osprofiler.initializer
from osprofiler import opts as profiler_opts
import osprofiler.web


CONF = cfg.CONF
profiler_opts.set_defaults(CONF)
LOG = logging.getLogger(__name__)


def setup(name, host='0.0.0.0'):  # nosec
    """Setup OSprofiler notifier and enable profiling.

    :param name: name of the service, that will be profiled
    :param host: host (either host name or host address) the service will be
                 running on. By default host will be set to 0.0.0.0, but more
                 specified host name / address usage is highly recommended.
    """
    if CONF.profiler.enabled:
        osprofiler.initializer.init_from_conf(
            conf=CONF,
            context=context.get_admin_context().to_dict(),
            project="neutron",
            service=name,
            host=host
        )
        LOG.info("OSProfiler is enabled.\n"
                 "Traces provided from the profiler "
                 "can only be subscribed to using the same HMAC keys that "
                 "are configured in Neutron's configuration file "
                 "under the [profiler] section.\n To disable OSprofiler "
                 "set in /etc/neutron/neutron.conf:\n"
                 "[profiler]\n"
                 "enabled=false")
