#!/bin/bash
rm -rf ./*.deb ./*.tar.gz ./*.dsc ./*.changes
rm -rf */*.deb
rm -rf ./plugins/**/build/ ./plugins/**/dist
rm -rf ./plugins/**/lib/quantum_*_plugin.egg-info ./plugins/quantum-*
