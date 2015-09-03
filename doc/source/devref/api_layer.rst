Neutron WSGI/HTTP API layer
===========================

This section will cover the internals of Neutron's HTTP API, and the classes
in Neutron that can be used to create Extensions to the Neutron API.

Python web applications interface with webservers through the Python Web
Server Gateway Interface (WSGI) - defined in `PEP 333 <http://legacy.python.org/dev/peps/pep-0333/>`_

Startup
-------

Neutron's WSGI server is started from the `server module <http://git.openstack.org/cgit/openstack/neutron/tree/neutron/server/__init__.py>`_
and the entry point `serve_wsgi` is called to build an instance of the
`NeutronApiService`_, which is then returned to the server module,
which spawns a `Eventlet`_ `GreenPool`_ that will run the WSGI
application and respond to requests from clients.


.. _NeutronApiService: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/service.py

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


.. _config.py: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/common/config.py

.. _api-paste.ini: http://git.openstack.org/cgit/openstack/neutron/tree/etc/api-paste.ini

.. _APIRouter: http://git.openstack.org/cgit/openstack/neutron/tree/neutron/api/v2/router.py

.. _Paste: http://pythonpaste.org/

.. _Deploy: http://pythonpaste.org/deploy/

.. _Paste INI file format: http://pythonpaste.org/deploy/#applications

Further reading
---------------

`Yong Sheng Gong: Deep Dive into Neutron <http://www.slideshare.net/gongys2004/inside-neutron-2>`_
