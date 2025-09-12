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
