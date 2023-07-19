.. _config-metadata-caching:

========================
Metadata service caching
========================

The OpenStack Networking service proxies requests that VMs send to the
Compute service to obtain their metadata. This functionality is provided by the
``neutron-metadata-agent`` or ``neutron-ovn-metadata-agent``, depending on the
ML2 backend used in the deployment.
To obtain metadata from the Compute service, the instance ID needs to be sent
to the ``nova-metadata-api``.
These two metadata agents provide the same functionality, but do it
in slightly different ways, the difference being how the metadata agents find
out the ID of the instance which is asking for metadata:

* ``neutron-metadata-agent`` uses RPC to ask the neutron-server process for
  details about a port with a specific fixed IP address connected to the given
  network or router (proxy service is spawned for each Neutron router or
  Neutron network),
* ``neutron-ovn-metadata-agent`` checks the instance ID in the port details of
  the OVN Southband DB.

For large scale deployments which are using the ``neutron-metadata-agent`` this
may cause significant load on the RPC bus and neutron-server, since by default
for each request to the metadata service (``169.254.169.254``), the proxy will
need to send an RPC query to retrieve the port details, and `cloud-init
<https://cloudinit.readthedocs.io/>`_ is making many requests to this service
during the VM boot process.
To avoid this high load on the RPC bus, the ``neutron-metadata-agent`` allows
using a caching mechanism for port details.
Neutron uses `oslo cache
<https://docs.openstack.org/oslo.cache/latest/index.html>`_ for
this and it is configured through the following parameters in the ``cache``
section of the ``metadata_agent.ini`` file:

* ``enabled``: enables the caching mechanism.
* ``backend``: backend module to be used for caching.
* ``expiration_time``: TTL, in seconds, for cached items. In case of
  ``neutron-metadata-agent`` it is recommended to use some low value here, for
  example, 10 seconds. Usually cloud-init will make many requests to the
  metadata service in a short time during boot of a VM, so caching port details
  for just a few seconds should be enough to avoid many RPC requests. On the
  other hand, using too big a value may result in having cached details for a
  port which has already been deleted, as a fixed IP address can be quickly
  re-associated to a new port in Neutron.

The oslo.cache module provides many more configuration options which can be
used to tune this caching mechanism. All of them are described in the
oslo.cache `documentation
<https://docs.openstack.org/oslo.cache/latest/configuration/index.html>`_.
