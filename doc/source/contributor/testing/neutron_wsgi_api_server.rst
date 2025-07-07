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

.. _neutron_wsgi_api_server:

Neutron WSGI API server
=======================

Since OpenStack Epoxy (2025.1), the Neutron API server only runs using a uWSGI
server that loads the Neutron WSGI application. The configuration and modules
needed and how to execute the Neutron API using WSGI is described in
:doc:`/admin/config-wsgi`. The ``eventlet`` API server is no longer supported
and the code will be removed.

With the older implementation (``eventlet`` API server) it was easy to create
an entry script to start the Neutron API, using the same code as in the
generated script defined in the ``[entry_points]console_script`` section.
That script started a python executable; it was possible to add break points
(using ``pdb``) or create a profile for PyCharm, for example.

In the WSGI case this is a bit more complicated. It is not possible to attach
a Python debugger to the running process because this is not a Python
executable. The uWSGI server, when a request is received, uses the application
entry point to route the request, but the root process is not a Python
executable.


rpdb
----

An alternative to ``pdb`` is the use of
`rpdb <https://pypi.org/project/rpdb/>`. This library works the same as ``pdb``
but opening a TCP port that can be accessed using telnet, netcat, etc. For
example:

.. code:: python

    import rpdb
    debugger = rpdb.Rpdb(addr='0.0.0.0', port=12345)
    debugger.set_trace()


To access to the remote PDB console, it is needed to execute the following
command:

.. code:: bash

    $ telnet localhost 12345



Executing the generated Neutron API script
------------------------------------------

The ``oslo-config-generator`` script can generate the script located in
``[entry_points]wsgi_scripts``, called ``neutron-api``; this script will
receive the same name. This script can be executed locally and will spawn
a single process Neutron API server, running one single WSGI thread, regardless
of the Neutron ``[DEFAULT]api_workers`` parameter.

It is not possible to pass any configuration file to this executable but the
Neutron API will use the default ones ``/etc/neutron/neutron.conf`` and
``/etc/neutron/plugins/ml2/ml2_conf.ini``. Any parameter needed by the Neutron
API must be defined in these two files.

Because this script will run as a Python process, it is possible to attach a
debugger or add a break point using ``pdb``. It is also possible to create a
PyCharm "configuration" (using its own term) to execute the Neutron API using
the PyCharm builtin debugger.

In order to run the Neutron API using this script, it is only needed to provide
the listening port:

.. code:: bash

    $ neutron-api --port 8000


Once running, it is needed to change the OpenStack endpoint for the networking
service:

.. code:: bash

    $ openstack endpoint list
    +----------------------------------+-----------+--------------+----------------+---------+-----------+-------------------------------------------------+
    | ID                               | Region    | Service Name | Service Type   | Enabled | Interface | URL                                             |
    +----------------------------------+-----------+--------------+----------------+---------+-----------+-------------------------------------------------+
    | 3959198c9b3f457cbb03cf49cd278415 | RegionOne | neutron      | network        | True    | public    | http://192.168.10.100/networking                |
    | 5807512a0c344144a1bd4f3bda4d3316 | RegionOne | glance       | image          | True    | public    | http://192.168.10.100/image                     |
    | 6954de6553c84cb19d2f3441411ca897 | RegionOne | nova_legacy  | compute_legacy | True    | public    | http://192.168.10.100/compute/v2/$(project_id)s |
    | 71fe40ea4e6e431cb800143b4349928c | RegionOne | keystone     | identity       | True    | public    | http://192.168.10.100/identity                  |
    | 73b86abeaca14e7ba18a53b8357dddee | RegionOne | nova         | compute        | True    | public    | http://192.168.10.100/compute/v2.1              |
    | 76f5c962173b419b994d86877070673e | RegionOne | placement    | placement      | True    | public    | http://192.168.10.100/placement                 |
    | 841199dad0b54acbb1c781e0b881cbf3 | RegionOne | designate    | dns            | True    | public    | http://192.168.10.100/dns                       |
    | f4b219c2287448e3add582204db7ac69 | RegionOne | cinder       | block-storage  | True    | public    | http://192.168.10.100/volume/v3                 |
    +----------------------------------+-----------+--------------+----------------+---------+-----------+-------------------------------------------------+
    $ openstack endpoint set --url http://192.168.10.100:8000 3959198c9b3f457cbb03cf49cd278415
