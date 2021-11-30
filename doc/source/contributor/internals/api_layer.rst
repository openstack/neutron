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


Neutron WSGI/HTTP API layer
===========================

This section will cover the internals of Neutron's HTTP API, and the classes
in Neutron that can be used to create Extensions to the Neutron API.

Python web applications interface with webservers through the Python Web
Server Gateway Interface (WSGI) - defined in `PEP 333 <http://legacy.python.org/dev/peps/pep-0333/>`_

Startup
-------

Neutron's WSGI server is started from the `server module <http://opendev.org/openstack/neutron/src/neutron/server/__init__.py>`_
and the entry point `serve_wsgi` is called to build an instance of the
`NeutronApiService`_, which is then returned to the server module,
which spawns a `Eventlet`_ `GreenPool`_ that will run the WSGI
application and respond to requests from clients.


.. _NeutronApiService: http://opendev.org/openstack/neutron/src/neutron/service.py

.. _Eventlet: http://eventlet.net/

.. _GreenPool: http://eventlet.net/doc/modules/greenpool.html

WSGI Application
----------------

During the building of the NeutronApiService, the `_run_wsgi` function
creates a WSGI application using the `load_paste_app` function inside
`config.py`_ - which parses `api-paste.ini`_ - in order to create a WSGI app
using `Paste`_'s `deploy`_.

The api-paste.ini file defines the WSGI applications and routes - using the
`Paste INI file format`_.

The INI file directs paste to instantiate the `APIRouter`_ class of
Neutron, which contains several methods that map Neutron resources (such as
Ports, Networks, Subnets) to URLs, and the controller for each resource.


.. _config.py: http://opendev.org/openstack/neutron/src/neutron/common/config.py

.. _api-paste.ini: http://opendev.org/openstack/neutron/src/etc/api-paste.ini

.. _APIRouter: http://opendev.org/openstack/neutron/src/neutron/api/v2/router.py

.. _Paste: http://pythonpaste.org/

.. _Deploy: http://pythonpaste.org/deploy/

.. _Paste INI file format: http://pythonpaste.org/deploy/#applications

Further reading
---------------

`Yong Sheng Gong: Deep Dive into Neutron <http://www.slideshare.net/gongys2004/inside-neutron-2>`_
