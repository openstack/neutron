=======================
General Feature Support
=======================

.. warning::
    Please note, while this document is still being maintained, this is slowly
    being updated to re-group and classify features using the definitions
    described in here: :doc:`feature_classification_introduction`.

This document covers the maturity and support of the Neutron API
and its API extensions. Details about the API can be found at
`Networking API v2.0 <https://docs.openstack.org/api-ref/network/v2/>`_.

When considering which capabilities should be marked as mature the
following general guiding principles were applied:

* **Inclusivity** - people have shown ability to make effective
  use of a wide range of network plugins and drivers with broadly
  varying feature sets. Aiming to keep the requirements as inclusive
  as possible, avoids second-guessing how a user wants to use their
  networks.

* **Bootstrapping** - a practical use case test is to consider that
  starting point for the network deploy is an empty data center
  with new machines and network connectivity. Then look at what
  are the minimum features required of the network service, in order
  to get user instances running and connected over the network.

* **Reality** - there are many networking drivers and plugins compatible with
  neutron. Each with their own supported feature set.

.. support_matrix:: general_feature_support_matrix.ini
