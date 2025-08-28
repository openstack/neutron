#!/bin/sh

set -eu

usage () {
    echo "Usage: $0 [OPTION]..."
    echo "Run Neutron's coding check(s)"
    echo ""
    echo "  -Y, --pylint [<basecommit>] Run pylint check on the entire neutron module or just files changed in basecommit (e.g. HEAD~1)"
    echo "  -h, --help                  Print this usage message"
    echo
    exit 0
}

process_options () {
    i=1
    while [ $i -le $# ]; do
        eval opt=\$$i
        case $opt in
            -h|--help) usage;;
            -Y|--pylint) pylint=1;;
            *) scriptargs="$scriptargs $opt"
        esac
        i=$((i+1))
    done
}

run_pylint () {
    local target="${scriptargs:-all}"

    echo "Running pylint..."

    if [ "$target" = "all" ]; then
        echo "You can speed this up by running it on 'HEAD~[0-9]' (e.g. HEAD~1, this change only)..."
        files="neutron"
    else
        case "$target" in
            *HEAD~[0-9]*) files=$(git diff --diff-filter=AM --name-only $target -- "*.py");;
            *) echo "$target is an unrecognized basecommit"; exit 1;;
        esac
    fi
    echo ""
    echo "Consider using the 'pre-commit' tool instead."
    echo ""
    echo "    pip install --user pre-commit"
    echo "    pre-commit install --allow-missing-config"
    echo ""
    if [ -n "${files}" ]; then
        pylint --rcfile=.pylintrc --output-format=colorized ${files}
    else
        echo "No python changes in this commit, pylint check not required."
        exit 0
    fi
}

scriptargs=
pylint=1

process_options $@

if [ $pylint -eq 1 ]; then
    run_pylint
    exit 0
fi
