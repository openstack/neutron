from copy import deepcopy
from optparse import OptionParser
from os import path
import re
import sys

from tools import install_venv

ROOT = path.abspath(path.dirname(__file__))
CONFIG_PATH = path.abspath('/etc/quantum')
BASE_PACKAGES = ['common', 'server', 'client']
PLUGINS = ['plugins/sample-plugin', 'plugins/cisco-plugin',
           'plugins/openvswitch-plugin']

RELATIVE = False


def clean_path(dirty):
    """Makes sure path delimiters are OS compliant"""
    return path.join(*dirty.split('/'))


def script_dir():
    script_dir = '/usr/sbin/'
    if RELATIVE:
        script_dir = 'usr/sbin/'
    return script_dir


def create_parser():
    """Setup the option parser"""
    usagestr = "Usage: %prog [OPTIONS] <command> [args]"
    parser = OptionParser(usage=usagestr)
    parser.add_option("-V", "--virtualenv", "--venv", dest="venv",
        action="store_true", default=False, help="Install to a virtual-env")
    parser.add_option("-U", "--user", dest="user", action="store_true",
        default=False, help="Install to users's home")
    options, args = parser.parse_args()

    if args.__len__() is 0:
        print usagestr
        print "Commands:\ninstall\nuninstall\nbuild\nclean"
        exit(0)

    cmd = args[0]
    args = args[1:]
    return (options, cmd, args)


def install_packages(options, args=None):
    """Builds and installs packages"""
    # Start building a command list
    cmd = ['pip', 'install']

    # If no options, just a regular install.  If venv, create, prepare and
    # install in venv.  If --user install in user's local dir.  Usually
    # ~/.local/
    if options.venv:
        if install_venv.VENV_EXISTS:
            print "Virtual-env exists"
        else:
            install_venv.create_virtualenv(install_pip=False)
        install_venv.install_dependencies()
        cmd.extend(['-E', install_venv.VENV])
    elif options.user:
        cmd.append('--user')

    # Install packages
    # TODO(Tyler) allow users to pass in packages in cli
    for package in BASE_PACKAGES + PLUGINS:
        print "Installing %s" % package
        # Each package needs its own command list, and it needs the path
        # in the correct place (after "pip install")
        pcmd = deepcopy(cmd)
        pcmd.insert(2, path.join(ROOT, clean_path(package)))

        if package is 'server':
            pcmd.append("--install-option=--install-scripts=%s" %\
                        script_dir())
        print pcmd
        install_venv.run_command(pcmd)
        print "done."


def uninstall_packages(options, args=None):
    """Removes packages"""
    cmd = ['pip', 'uninstall', '-y']

    for package in ['quantum-' + x.split('/')[-1] \
                    for x in BASE_PACKAGES + PLUGINS]:
        print "Uninstalling %s" % package
        # Each package needs its own command list, and it needs the path
        # in the correct place (after "pip uninstall"
        pcmd = deepcopy(cmd)
        pcmd.insert(2, package)
        print pcmd
        install_venv.run_command(pcmd)
        print "done."


def build_packages(options, args=None):
    """Build RPM and/or deb packages"""
    if not args:
        print "To build packages you must specifiy either 'rpm', " \
              "'deb', or 'all'"
        exit(0)
    if args[0] not in ['rpm', 'deb', 'all']:
        raise Exception("Packge type must be rpm, deb, or all")

    if 'rpm' in args or 'all' in args:
        # Since we need to cd to build rpms, we call this sh script
        cmd = ['tools/build_rpms.sh']
        for package in BASE_PACKAGES + PLUGINS:
            print "Building %s rpm" % package
            pcmd = deepcopy(cmd)
            pcmd.append(package)
            install_venv.run_command(pcmd)
            print "done."

    if 'deb' in args or 'all' in args:
        cmd = ['tools/build_debs.sh']
        for p in BASE_PACKAGES + PLUGINS:
            print "Building %s deb" % p
            pcmd = deepcopy(cmd)
            pcmd.append(p)
            install_venv.run_command(pcmd)
        print "done."


def clean_packages(options, args):
    """Cleans build packages"""
    cmd = ["tools/clean.sh"]
    install_venv.run_command(cmd)


def main():
    """Main Build script for Quantum"""
    options, cmd, args = create_parser()

    if options.user:
        RELATIVE = True

    print "Checking for virtual-env and easy_install"
    install_venv.check_dependencies()

    # Execute command
    try:
        globals()["%s_packages" % cmd](options, args)
    except KeyError as exc:
        print "Command %s' not found" % exc.__str__().split('_')[0]

if __name__ == "__main__":
    main()
