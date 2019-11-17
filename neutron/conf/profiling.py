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

from neutron._i18n import _


PROFILER_OPTS = [
    cfg.BoolOpt('enable_code_profiling',
                default=False,
                help=_('Enable code execution profiling with cProfile. '
                       'Profiling data are logged at DEBUG level.')),
    cfg.IntOpt('code_profiling_calls_to_log',
               default=50,
               help=_('Number of calls from the cProfile report to log')),
]


def register_profiling_opts(conf=cfg.CONF):
    conf.register_opts(PROFILER_OPTS)
