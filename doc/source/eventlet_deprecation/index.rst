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

==============================
Eventlet Deprecation Reference
==============================

This document contains the information related to the ``eventlet`` library
deprecation. Each section describes how each module has been migrated, the
caveats, the pending technical debt and the missing parts.


OVN Agent
---------

Launch process
~~~~~~~~~~~~~~

The execution of the OVN agent has been replaced. Instead of using
``oslo_services.launch``, that is still using eventlet, the agent creates
a ``threading.Event`` instance and holds the main thread execution by waiting
for this event.

.. note::

  Once the ``oslo_services`` library removes the usage of
  eventlet, the previous implementation will be restored. The
  ``oslo_services.service.ProcessLauncher`` service launcher implements a
  signal handler.


Metadata proxy
~~~~~~~~~~~~~~

The ``UnixDomainWSGIServer`` class has been replaced with a new implementation.
This implementation does not rely on ``neutron.api.wsgi.Server`` nor
``eventlet.wsgi.server``. It inherits from the built-in library class
``socketserver.StreamRequestHandler``.

.. note::

  This implementation doesn't use ``oslo_services`` to spawn the
  processes or the local threads depending on the ``metadata_workers``
  configuration variable. Right now only the embedded form (local thread)
  is implemented (``metadata_workers=0``, the default value). Future
  implementations will enable again this configuration variable.


Neutron API
-----------

The Neutron API currently can be executed only with the uWSGI module; the
eventlet executor has been deprecated, although the code has not been removed
from the repository yet. It is now mandatory to define the configuration
variable ``start-time`` in the uWSGI configuration file, using the magic
variable [1]_ "%t" that provides the *unix time (in seconds, gathered at
instance startup)*.

.. code::

  [uwsgi]
  start-time = %t


The Neutron API consists of the following executables:

* The API server: is a multiprocess worker; each process is created by the
  ``uWSGI`` server.

* The periodic worker: a mult process worker that spawns several threads to
  execute the periodic workers.

* The RPC worker: a multiprocess process worker that attends the requests from
  the RPC clients, for example the Neutron agents.

* The ML2/OVN maintenance worker: single process worker, needed by the ML2/OVN
  mechanism driver.


.. note::

  Right now, only the API server is running without eventlet.




References
----------

.. [1] https://uwsgi-docs.readthedocs.io/en/latest/Configuration.html#magic-variables
