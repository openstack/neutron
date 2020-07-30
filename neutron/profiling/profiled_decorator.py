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


import cProfile
from datetime import datetime
import functools
import io
import pstats

from oslo_config import cfg
from oslo_log import log

from neutron.common import utils
from neutron.conf import profiling as profiling_conf_opts

LOG = log.getLogger(__name__)


CONF = cfg.CONF
profiling_conf_opts.register_profiling_opts()


SORT_BY = 'cumtime'


def profile(f):
    """Decorator to profile Neutron code.

    This will profile the decorated method or function with cProfile and log
    the result.
    """

    @functools.wraps(f)
    def profile_wrapper(*args, **kwargs):

        try:
            if cfg.CONF.enable_code_profiling:
                profid = "%s.%s" % (f.__module__, f.__name__)
                profiler = cProfile.Profile()
                profiler.enable()
                start_time = datetime.now()
            return f(*args, **kwargs)
        finally:
            if cfg.CONF.enable_code_profiling:
                profiler.disable()
                elapsed_time = datetime.now() - start_time
                elapsed_time_ms = (elapsed_time.seconds * 1000.0 +
                                  elapsed_time.microseconds / 1000.0)
                stream = io.StringIO()
                stats = pstats.Stats(profiler, stream=stream).sort_stats(
                    SORT_BY)
                stats.print_stats(cfg.CONF.code_profiling_calls_to_log)
                stats.print_callers(cfg.CONF.code_profiling_calls_to_log)
                stats.print_callees(cfg.CONF.code_profiling_calls_to_log)
                profiler_info = utils.collect_profiler_info()
                if not profiler_info:
                    profiler_info = {'base_id': 'not available',
                                     'parent_id': 'not available'}
                LOG.debug('os-profiler parent trace-id %(parent_id)s '
                          'trace-id %(trace_id)s %(elapsed_time)7d millisecs '
                          'elapsed for %(method)s(*%(args)s, **%(kwargs)s):'
                          '\n%(profiler_data)s',
                          {'parent_id': profiler_info['parent_id'],
                           'trace_id': profiler_info['base_id'],
                           'elapsed_time': elapsed_time_ms,
                           'method': profid,
                           'args': args,
                           'kwargs': kwargs,
                           'profiler_data': stream.getvalue()})
                stream.close()

    return profile_wrapper
