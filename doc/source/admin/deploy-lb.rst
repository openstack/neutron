.. _deploy-lb:

=============================
Linux bridge mechanism driver
=============================

The Linux bridge mechanism driver uses only Linux bridges and ``veth`` pairs
as interconnection devices. A layer-2 agent manages Linux bridges on each
compute node and any other node that provides layer-3 (routing), DHCP,
metadata, or other network services.

.. toctree::
   :maxdepth: 2

   deploy-lb-provider
   deploy-lb-selfservice
   deploy-lb-ha-vrrp
