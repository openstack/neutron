============
Introduction
============

This document describes how features are listed in
:doc:`general_feature_support_matrix` and
:doc:`provider_network_support_matrix`.

Goals
~~~~~

The object of this document is to inform users whether or not
features are complete, well documented, stable, and tested.
This approach ensures good user experience for those well maintained features.

.. note::

    Tests are specific to particular combinations of technologies.
    The plugins chosen for deployment make a big difference to whether
    or not features will work.


Concepts
~~~~~~~~

These definitions clarify the terminology used throughout this document.

Feature status
~~~~~~~~~~~~~~

* Immature
* Mature
* Required
* Deprecated (scheduled to be removed in a future release)

Immature
--------

Immature features do not have enough functionality to satisfy real world
use cases.

An immature feature is a feature being actively developed, which is only
partially functional and upstream tested, most likely introduced in a
recent release, and that will take time to mature thanks to feedback
from downstream QA.

Users of these features will likely identify gaps and/or defects
that were not identified during specification and code review.

Mature
------

A feature is considered mature if it satisfies the following criteria:

* Complete API documentation including concept and REST call definition.
* Complete Administrator documentation.
* Tempest tests that define the correct functionality of the feature.
* Enough functionality and reliability to be useful in real world scenarios.
* Low probability of support for the feature being dropped.

Required
--------

Required features are core networking principles that have been thoroughly
tested and have been implemented in real world use cases.

In addition they satisfy the same criteria for any mature features.

.. note::

    Any new drivers must prove that they support all required features
    before they are merged into neutron.


Deprecated
----------

Deprecated features are no longer supported and only security related fixes
or development will happen towards them.

Deployment rating of features
-----------------------------

The deployment rating shows only the state of the tests for each
feature on a particular deployment.

.. important::

    Despite the obvious parallels that could be drawn, this list is
    unrelated to the Interop effort.
    See `InteropWG <https://docs.opendev.org/openinfra/interop/latest/>`_
