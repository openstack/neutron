..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Profiling Neutron Code
======================

As more functionality is added to Neutron over time, efforts to improve
performance become more difficult, given the rising complexity of the code.
Identifying performance bottlenecks is frequently not straightforward, because
they arise as a result of complex interactions of different code components.

To help community developers to improve Neutron performance, a Python decorator
has been implemented. Decorating a method or a function with it will result in
profiling data being added to the corresponding Neutron component log file.
These data are generated using `cProfile`_ which is part of the Python standard
library.

.. _`cProfile`: https://docs.python.org/3/library/profile.html

Once a method or function has been decorated, every one of its executions will
add to the corresponding log file data grouped in 3 sections:

#. The top calls (sorted by CPU cumulative time) made by the decorated method
   or function. The number of calls included in this section can be controlled
   by a configuration option, as explained in
   :ref:`config-neutron-for-code-profiling`. Following is a summary example of
   this section:

   .. code-block:: console

      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: DEBUG neutron.profiling.profiled_decorator [None req-dc2d428f-4531-4f07-a12d-56843b5f9374 c_rally_8af8f2b4_YbhFJ6Ge c_rally_8af8f2b4_fqvy1XJp] os-profiler parent trace-id c5b30c7f-100b-4e1c-8f07-b2c38f41ad65 trace-id 6324fa85-ea5f-4ae2-9d89-2aabff0dddfc   16928 millisecs elapsed for neutron.plugins.ml2.plugin.create_port((<neutron.plugins.ml2.plugin.Ml2Plugin object at 0x7f0b4e6ca978>, <neutron_lib.context.Context object at 0x7f0b4bcee240>, {'port': {'tenant_id': '421ab52e126e45af81a3eb1962613e18', 'network_id': 'dc59577a-9589-4617-82b5-6ee31dbdb15d', 'fixed_ips': [{'ip_address': '1.1.5.177', 'subnet_id': 'e15ec947-9edd-4793-bf0f-c463c7ff2f62'}], 'admin_state_up': True, 'device_id': 'f33db890-7958-440e-b07b-432e40bb4049', 'device_owner': 'network:router_interface', 'name': '', 'project_id': '421ab52e126e45af81a3eb1962613e18', 'mac_address': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'allowed_address_pairs': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'extra_dhcp_opts': None, 'binding:vnic_type': 'normal', 'binding:host_id': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'binding:profile': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'port_security_enabled': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'description': '', 'security_groups': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>}}), {}):
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:          247612 function calls (238220 primitive calls) in 16.943 seconds
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    Ordered by: cumulative time
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    List reduced from 1861 to 100 due to restriction <100>
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    ncalls  tottime  percall  cumtime  percall filename:lineno(function)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:       4/2    0.000    0.000   16.932    8.466 /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:132(wrapped)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:         1    0.000    0.000   16.928   16.928 /opt/stack/neutron/neutron/common/utils.py:678(inner)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:      20/9    0.000    0.000   16.884    1.876 /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1317(<genexpr>)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     37/17    0.000    0.000   16.867    0.992 /opt/stack/osprofiler/osprofiler/sqlalchemy.py:84(handler)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     37/17    0.000    0.000   16.860    0.992 /opt/stack/osprofiler/osprofiler/profiler.py:86(stop)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:       8/3    0.005    0.001   16.844    5.615 /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:224(wrapped)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:         1    0.000    0.000   16.836   16.836 /opt/stack/neutron/neutron/plugins/ml2/plugin.py:1395(_create_port_db)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:         1    0.000    0.000   16.836   16.836 /opt/stack/neutron/neutron/db/db_base_plugin_v2.py:1413(create_port_db)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:         1    0.000    0.000   16.836   16.836 /opt/stack/neutron/neutron/db/db_base_plugin_v2.py:1586(_enforce_device_owner_not_router_intf_or_device_id)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:         1    0.000    0.000   16.836   16.836 /opt/stack/neutron/neutron/db/l3_db.py:522(get_router)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:         1    0.000    0.000   16.836   16.836 /opt/stack/neutron/neutron/db/l3_db.py:186(_get_router)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     34/22    0.000    0.000   16.745    0.761 /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/loading.py:35(instances)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:      39/8    0.000    0.000   16.727    2.091 /usr/local/lib/python3.6/dist-packages/sqlalchemy/sql/elements.py:285(_execute_on_connection)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:      39/8    0.001    0.000   16.727    2.091 /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/base.py:1056(_execute_clauseelement)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     17/13    0.000    0.000   16.704    1.285 /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1310(get)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     20/14    0.001    0.000   16.704    1.193 /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1315(_load)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     19/14    0.000    0.000   16.703    1.193 /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/loading.py:88(<listcomp>)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     76/23    0.001    0.000   16.699    0.726 /opt/stack/osprofiler/osprofiler/profiler.py:426(_notify)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:      39/8    0.001    0.000   16.696    2.087 /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/base.py:1163(_execute_context)
      Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:     75/23    0.000    0.000   16.686    0.725 /opt/stack/osprofiler/osprofiler/notifier.py:28(notify)

#. Callers section: all functions or methods that called each function or
   method in the resulting profiling data. This is restricted by the configured
   number of top calls to log, as explained in
   :ref:`config-neutron-for-code-profiling`. Following is a summary example of
   this section:

   ::

           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    Ordered by: cumulative time
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    List reduced from 1861 to 100 due to restriction <100>
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: Function                                                                                                      was called by...
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                   ncalls  tottime  cumtime
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:132(wrapped)                                     <-     2/0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:224(wrapped)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /opt/stack/neutron/neutron/common/utils.py:678(inner)                                                         <-
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1317(<genexpr>)                           <-       3    0.000    0.000  /opt/stack/osprofiler/osprofiler/profiler.py:426(_notify)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000   16.883  /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:132(wrapped)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        2    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/base.py:69(__init__)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/base.py:1056(_execute_clauseelement)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000   16.704  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/query.py:3281(one)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/query.py:3337(__iter__)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/query.py:3362(_execute_and_instances)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/session.py:1127(_connection_for_bind)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1310(get)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1315(_load)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:2033(load_scalar_from_joined_new_row)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                      1/0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/pool/base.py:840(_checkin)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                      1/0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/webob/request.py:1294(send)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /opt/stack/osprofiler/osprofiler/sqlalchemy.py:84(handler)                                                    <-    16/0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/event/attr.py:316(__call__)
           Oct 20 01:52:40.767003 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /opt/stack/osprofiler/osprofiler/profiler.py:86(stop)                                                         <-    16/0    0.000    0.000  /opt/stack/osprofiler/osprofiler/sqlalchemy.py:84(handler)

#. Callees section: a list of all functions or methods that were called by the
   indicated function or method. Again, this is restricted by the configured
   number of top calls to log. Following is a summary example of this section:

   ::

           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    Ordered by: cumulative time
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:    List reduced from 1861 to 100 due to restriction <100>
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: Function                                                                                                      called...
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                   ncalls  tottime  cumtime
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:132(wrapped)                                     ->     1/0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/oslo_db/api.py:135(wrapper)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000   16.883  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1317(<genexpr>)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /opt/stack/neutron/neutron/common/utils.py:678(inner)                                                         ->       1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/neutron_lib/context.py:145(session)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000   16.928  /usr/local/lib/python3.6/dist-packages/neutron_lib/db/api.py:224(wrapped)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/session.py:2986(is_active)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1317(<genexpr>)                           ->       1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/default.py:579(do_execute)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        2    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/default.py:1078(post_exec)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        2    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/engine/default.py:1122(get_result_proxy)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        0    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/event/attr.py:316(__call__)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/event/base.py:266(__getattr__)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                     15/3    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/loading.py:35(instances)
           Oct 20 01:52:40.788842 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1317(<listcomp>)
           Oct 20 01:52:40.791161 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        1    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/orm/strategies.py:1318(<lambda>)
           Oct 20 01:52:40.791161 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]:                                                                                                                        3    0.000    0.000  /usr/local/lib/python3.6/dist-packages/sqlalchemy/util/langhelpers.py:852(__get__)


.. _config-neutron-for-code-profiling:

Setting up  Neutron for code profiling
--------------------------------------

To start profiling Neutron code, the following steps have to be taken:

#. Add he following line to the ``[default]`` section of
   ``/etc/neutron/neutron.conf`` (code profiling is disabled by default):

   .. code-block:: console

      enable_code_profiling = True

#. Add the following import line to each module to be profiled:

   .. code-block:: python

      from neutron.profiling import profiled_decorator

#. Decorate each mehtod or function to be profiled as follows:

   .. code-block:: python

      @profiled_decorator.profile
      def create_subnet(self, context, subnet):

#. For each decorated method or function execution, only the top 50 calls by
   cumulative CPU time are logged. This can be changed adding the following
   line to the ``[default]`` section of ``/etc/neutron/neutron.conf``:

   .. code-block:: console

      code_profiling_calls_to_log = 100


Profiling code with the Neutron Rally job
-----------------------------------------

Code profiling is enabled for the ``neutron-rally-task`` job in Neutron's check
queue in Zuul. Taking advantage of the fact that ``os-profiler`` is enabled for
this job, the data logged by the ``profiled_decorator.profile`` decorator
includes the ``os-profiler`` ``parent trace-id`` and ``trace-id`` as can be
seen here:

.. code-block:: console

   Oct 20 01:52:40.759379 ubuntu-bionic-vexxhost-sjc1-0012393267 neutron-server[19578]: DEBUG neutron.profiling.profiled_decorator [None req-dc2d428f-4531-4f07-a12d-56843b5f9374 c_rally_8af8f2b4_YbhFJ6Ge c_rally_8af8f2b4_fqvy1XJp] os-profiler parent trace-id c5b30c7f-100b-4e1c-8f07-b2c38f41ad65 trace-id 6324fa85-ea5f-4ae2-9d89-2aabff0dddfc   16928 millisecs elapsed for neutron.plugins.ml2.plugin.create_port((<neutron.plugins.ml2.plugin.Ml2Plugin object at 0x7f0b4e6ca978>, <neutron_lib.context.Context object at 0x7f0b4bcee240>, {'port': {'tenant_id': '421ab52e126e45af81a3eb1962613e18', 'network_id': 'dc59577a-9589-4617-82b5-6ee31dbdb15d', 'fixed_ips': [{'ip_address': '1.1.5.177', 'subnet_id': 'e15ec947-9edd-4793-bf0f-c463c7ff2f62'}], 'admin_state_up': True, 'device_id': 'f33db890-7958-440e-b07b-432e40bb4049', 'device_owner': 'network:router_interface', 'name': '', 'project_id': '421ab52e126e45af81a3eb1962613e18', 'mac_address': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'allowed_address_pairs': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'extra_dhcp_opts': None, 'binding:vnic_type': 'normal', 'binding:host_id': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'binding:profile': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'port_security_enabled': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>, 'description': '', 'security_groups': <neutron_lib.constants.Sentinel object at 0x7f0b4fc69860>}}), {}):

Community developers wanting to use this to correlate data from ``os-profiler``
and the ``profiled_decorator.profile`` decorator can submit a ``DNM`` (Do Not
Merge) patch, decorating the functions and methods they want to profile and
optionally:

#. Configure the number of calls to be logged in the ``neutron-rally-task``
   job definition, as described in :ref:`config-neutron-for-code-profiling`.

#. Increase the ``timeout`` parameter value of the ``neutron-rally-task`` job
   in the `.zuul yaml file`_. The value used for the Neutron gate might be too
   short when logging large quantities of profiling data.

.. _`.zuul yaml file`: https://github.com/openstack/neutron/blob/master/.zuul.yaml

The ``profiled_decorator.profile`` and ``os-profiler`` data will be found in
the ``neutron-rally-task`` log files and ``HTML report`` respectively.
