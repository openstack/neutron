.. _repo-overview:

=============
Repo Overview
=============

A terse map of the Neutron repository for contributor orientation.

Root Files
==========

``HACKING.rst``
    Neutron coding style rules and N-check descriptions.
``AGENTS.md``
    Agent routing index and policy for AI-assisted coding tools.
``TESTING.rst``
    Quick-start guide for running Neutron tests.
``tox.ini``
    Test environments, commands, and environment variables.
``pyproject.toml``
    Build system (pbr) and packaging configuration.
``requirements.txt`` / ``test-requirements.txt``
    Runtime and test dependencies (pinned via OpenStack constraints).
``setup.cfg``
    Package metadata, entry points, and console scripts.

neutron/ Package
================

``neutron/api/``
    REST API layer: Pecan WSGI, routing, controllers, API extensions.
``neutron/plugins/ml2/``
    Modular Layer 2 plug-in: type drivers, mechanism drivers (OVS, OVN,
    SR-IOV, macvtap, l2pop), extension drivers.
``neutron/services/``
    Service plug-ins: L3 router, QoS, trunk, metering, segments,
    port forwarding, local IP, conntrack helper, EVPN, PVLAN, and more.
``neutron/agent/``
    L2/L3/DHCP/metadata agent implementations and their extensions.
``neutron/agent/ovn/``
    OVN metadata agent.
``neutron/db/``
    Database models, mixins, and migration scripts (Alembic).
``neutron/objects/``
    Versioned objects: the canonical data model for RPC payloads.
``neutron/extensions/``
    API extension definitions (resource attributes, actions).
``neutron/cmd/``
    Entry points for Neutron services (``neutron-server``,
    ``neutron-openvswitch-agent``, ``neutron-ovn-metadata-agent``,
    ``neutron-dhcp-agent``, ``neutron-l3-agent``, etc.).
``neutron/conf/``
    oslo.config option declarations, one file per subsystem.
``neutron/common/``
    Shared utilities: OVN helpers, IP/network utils, caching.
``neutron/scheduler/``
    Agent schedulers for DHCP, L3, and network resources.
``neutron/quota/``
    Quota enforcement engine and resource tracking.
``neutron/notifiers/``
    Nova and batch notification dispatchers.
``neutron/ipam/``
    IP Address Management drivers and subnet pool logic.
``neutron/pecan_wsgi/``
    Pecan-based WSGI application and hooks.
``neutron/server/``
    Server bootstrap: workers, WSGI serving, eventlet.
``neutron/tests/``
    Unit (``unit/``), functional (``functional/``), and fullstack
    (``fullstack/``) test suites.

doc/ Structure
==============

``doc/source/admin/``
    Operator guides: deployment scenarios, configuration, architecture.
``doc/source/contributor/``
    Developer guides: process, testing, internals, policies.
``doc/source/ovn/``
    ML2/OVN specific documentation: gaps, FAQ, tracing.
``doc/source/install/``
    Installation guides for controller and compute nodes.
``doc/source/configuration/``
    Auto-generated configuration reference.
``doc/source/cli/``
    Command-line tool reference (``neutron-sanity-check``, etc.).
``doc/source/reference/``
    Internal reference documentation.
``releasenotes/``
    Reno release notes (``notes/`` source files + rendered output).

API Docs
========

`neutron-lib api-ref <https://opendev.org/openstack/neutron-lib/src/branch/master/api-ref/source/index.rst>`_
    REST API reference: per-resource ``.inc`` files and index. Built and
    published to docs.openstack.org.

CI and DevStack
===============

``zuul.d/``
    Zuul CI job definitions and project templates.
``devstack/``
    DevStack plugin: local.conf snippets, lib scripts, settings.
``playbooks/``
    Ansible playbooks for CI job setup.
``roles/``
    Ansible roles used by CI playbooks.
``rally-jobs/``
    Rally benchmark job definitions.
``tools/``
    Helper scripts for development, CI, and code generation.
``vagrant/ovn/``
    Vagrant environment for local OVN development and testing.
