.. _deploy-lb:

=============================
Linux bridge mechanism driver
=============================

The Linux bridge mechanism driver uses only Linux bridges and ``veth`` pairs
as interconnection devices. A layer-2 agent manages Linux bridges on each
compute node and any other node that provides layer-3 (routing), DHCP,
metadata, or other network services.

Compatibility with nftables
~~~~~~~~~~~~~~~~~~~~~~~~~~~

`nftables <https://netfilter.org/projects/nftables/>`_ replaces iptables,
ip6tables, arptables and ebtables, in order to provide a single API for all
``Netfilter`` operations. ``nftables`` provides a backwards compatibility set
of tools for those replaced binaries that present the legacy API to the user
while using the new packet classification framework. As reported in
`LP#1915341 <https://bugs.launchpad.net/neutron/+bug/1915341>`_ and
`LP#1922892 <https://bugs.launchpad.net/neutron/+bug/1922892>`_, the tool
``ebtables-nft`` is not totally compatible with the legacy API and returns some
errors. To use Linux Bridge mechanism driver in newer operating systems that
use ``nftables`` by default, it is needed to switch back to the legacy tool.

.. code-block:: console

   # /usr/bin/update-alternatives --set ebtables /usr/sbin/ebtables-legacy


Since `LP#1922127 <https://bugs.launchpad.net/neutron/+bug/1922127>`_ and
`LP#1922892 <https://bugs.launchpad.net/neutron/+bug/1922892>`_ were fixed,
Neutron Linux Bridge mechanism driver is compatible with the ``nftables``
binaries using the legacy API.

.. note::

   Just to unravel the possible terminology confusion, these are the three
   ``Netfilter`` available framework alternatives:

   * The legacy binaries (``iptables``, ``ip6tables``, ``arptables`` and
     ``ebtables``) that use the legacy API.
   * The new ``nftables`` binaries that use the legacy API, to help in the
     transition to this new framework. Those binaries replicate the same
     commands as the legacy one but using the new framework. The binaries
     have the same name ended in ``-nft``.
   * The new ``nftables`` framework using the new API. All Netfilter
     operations are executed using this new API and one single binary, ``nft``.

   Currently we support the first two options. The migration (total or partial)
   to the new API is tracked in
   `LP#1508155 <https://bugs.launchpad.net/neutron/+bug/1508155>`_.


In order to use the ``nftables`` binaries with the legacy API, it is needed to
execute the following commands.

.. code-block:: console

   # /usr/bin/update-alternatives --set iptables /usr/sbin/iptables-nft
   # /usr/bin/update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
   # /usr/bin/update-alternatives --set ebtables /usr/sbin/ebtables-nft
   # /usr/bin/update-alternatives --set arptables /usr/sbin/arptables-nft


The ``ipset`` tool is not compatible with ``nftables``. To disable it,
``enable_ipset`` must be set to ``False`` in the ML2 plugin configuration file
``/etc/neutron/plugins/ml2/ml2_conf.ini``.

.. path /etc/neutron/plugins/ml2/ml2_conf.ini
.. code-block:: ini

   [securitygroup]
   # ...
   enable_ipset = False


.. toctree::
   :maxdepth: 2

   deploy-lb-provider
   deploy-lb-selfservice
   deploy-lb-ha-vrrp
