Brocade Openstack Quantum Plugin
================================

* up-to-date version of these instructions are located at:
  http://wiki.openstack.org/brocade-quantum-plugin

* N.B.: Please see Prerequisites section  regarding ncclient (netconf client library)

* Supports VCS (Virtual Cluster of Switches)


Openstack Brocade Quantum Plugin implements the Quantum v2.0 API.

This plugin is meant to orchestrate Brocade VCS switches running NOS, examples of these are:

   1. VDX 67xx series of switches
   2. VDX 87xx series of switches

Brocade Quantum plugin implements the Quantum v2.0 API. It uses NETCONF at the backend
to configure the Brocade switch.

             +------------+        +------------+          +-------------+
             |            |        |            |          |             |
             |            |        |            |          |   Brocade   |
             | Openstack  |  v2.0  |  Brocade   |  NETCONF |  VCS Switch |
             | Quantum    +--------+  Quantum   +----------+             |
             |            |        |  Plugin    |          |  VDX 67xx   |
             |            |        |            |          |  VDX 87xx   |
             |            |        |            |          |             |
             |            |        |            |          |             |
             +------------+        +------------+          +-------------+


Directory Structure
===================

Normally you will have your Openstack directory structure as follows:

         /opt/stack/nova/
         /opt/stack/horizon/
         ...
         /opt/stack/quantum/quantum/plugins/

Within this structure, Brocade plugin resides at:

         /opt/stack/quantum/quantum/plugins/brocade


Prerequsites
============

This plugin requires installation of the python netconf client (ncclient) library:

ncclient v0.3.1 - Python library for NETCONF clients available at http://github.com/brocade/ncclient

  % git clone https://www.github.com/brocade/ncclient
  % cd ncclient; sudo python ./setup.py install


Configuration
=============

1. Specify to Quantum that you will be using the Brocade Plugin - this is done
by setting the parameter core_plugin in Quantum:

        core_plugin = quantum.plugins.brocade.QuantumPlugin.BrocadePluginV2

2. Physical switch configuration parameters and Brocade specific database configuration is specified in
the configuration file specified in the brocade.ini files:

        % cat /etc/quantum/plugins/brocade/brocade.ini
        [SWITCH]
        username = admin
        password = password
        address  = <switch mgmt ip address>
        ostype   = NOS

        [database]
        connection = mysql://root:pass@localhost/brocade_quantum?charset=utf8

        (please see list of more configuration parameters in the brocade.ini file)

Running Setup.py
================

Running setup.py with appropriate permissions will copy the default configuration
file to /etc/quantum/plugins/brocade/brocade.ini. This file MUST be edited to
suit your setup/environment.

      % cd /opt/stack/quantum/quantum/plugins/brocade
      % python setup.py


Devstack
========

Please see special notes for devstack at:
http://wiki.openstack.org/brocade-quantum-plugin

In order to use Brocade Quantum Plugin, add the following lines in localrc, if localrc file doe
 not exist create one:

ENABLED_SERVICES=g-api,g-reg,key,n-api,n-crt,n-obj,n-cpu,n-net,n-cond,cinder,c-sch,c-api,c-vol,n-sch,n-novnc,n-xvnc,n-cauth,horizon,rabbit,quantum,q-svc,q-agt
Q_PLUGIN=brocade

As part of running devstack/stack.sh, the configuration files is copied as:

  % cp /opt/stack/quantum/etc/quantum/plugins/brocade/brocade.ini /etc/quantum/plugins/brocade/brocade.ini

(hence it is important to make any changes to the configuration in:
/opt/stack/quantum/etc/quantum/plugins/brocade/brocade.ini)

