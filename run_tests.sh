#!/bin/bash

function usage {
  echo "Usage: $0 [OPTION]..."
  echo "Run Quantum's test suite(s)"
  echo ""
  echo "  -V, --virtual-env        Always use virtualenv.  Install automatically if not present"
  echo "  -N, --no-virtual-env     Don't use virtualenv.  Run tests in local environment"
  echo "  -c, --coverage           Generate coverage report"
  echo "  -f, --force              Force a clean re-build of the virtual environment. Useful when dependencies have been added."
  echo "  -h, --help               Print this usage message"
  echo ""
  echo "Note: with no options specified, the script will try to run the tests in a virtual environment,"
  echo "      If no virtualenv is found, the script will ask if you would like to create one.  If you "
  echo "      prefer to run tests NOT in a virtual environment, simply pass the -N option."
  exit
}

function process_option {
  case "$1" in
    -h|--help) usage;;
    -V|--virtual-env) let always_venv=1; let never_venv=0;;
    -N|--no-virtual-env) let always_venv=0; let never_venv=1;;
    -f|--force) let force=1;;
    -c|--coverage) coverage=1;;
    -*) noseopts="$noseopts $1";;
    *) noseargs="$noseargs $1"
  esac
}

venv=.quantum-venv
with_venv=tools/with_venv.sh
always_venv=0
never_venv=0
force=0
noseargs=
wrapper=""
coverage=0

for arg in "$@"; do
  process_option $arg
done

# If enabled, tell nose to collect coverage data
if [ $coverage -eq 1 ]; then
    noseopts="$noseopts --with-coverage --cover-package=quantum"
fi

function run_tests {
  # Just run the test suites in current environment
  ${wrapper} rm -f ./$PLUGIN_DIR/tests.sqlite
  ${wrapper} $NOSETESTS
}

NOSETESTS="python ./$PLUGIN_DIR/run_tests.py $noseopts $noseargs"

if [ -n "$PLUGIN_DIR" ]
then
    if ! [ -f ./$PLUGIN_DIR/run_tests.py ]
    then
        echo "Could not find run_tests.py in plugin directory $PLUGIN_DIR"
        exit 1
    fi
fi

if [ $never_venv -eq 0 ]
then
  # Remove the virtual environment if --force used
  if [ $force -eq 1 ]; then
    echo "Cleaning virtualenv..."
    rm -rf ${venv}
  fi
  if [ -e ${venv} ]; then
    wrapper="${with_venv}"
  else
    if [ $always_venv -eq 1 ]; then
      # Automatically install the virtualenv
      python tools/install_venv.py
      wrapper="${with_venv}"
    else
      echo -e "No virtual environment found...create one? (Y/n) \c"
      read use_ve
      if [ "x$use_ve" = "xY" -o "x$use_ve" = "x" -o "x$use_ve" = "xy" ]; then
        # Install the virtualenv and run the test suite in it
        python tools/install_venv.py
		    wrapper=${with_venv}
      fi
    fi
  fi
fi

# Delete old coverage data from previous runs
if [ $coverage -eq 1 ]; then
    ${wrapper} coverage erase
fi

# FIXME(sirp): bzr version-info is not currently pep-8. This was fixed with
# lp701898 [1], however, until that version of bzr becomes standard, I'm just
# excluding the vcsversion.py file
#
# [1] https://bugs.launchpad.net/bzr/+bug/701898
#
PEP8_EXCLUDE=vcsversion.py
PEP8_OPTIONS="--exclude=$PEP8_EXCLUDE --repeat --show-source"
PEP8_INCLUDE="bin/* quantum tests tools run_tests.py"
RV=0
run_tests && pep8 $PEP8_OPTIONS $PEP8_INCLUDE || RV=1

if [ $coverage -eq 1 ]; then
    echo "Generating coverage report in covhtml/"
    ${wrapper} coverage html -d covhtml -i
fi

exit $RV
