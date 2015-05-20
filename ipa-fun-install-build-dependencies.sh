#!/bin/bash

##############################################################################
# Author: Tomas Babej <tbabej@redhat.com>
#
# Install the build dependencies.
#
# Usage: $0 <branch>
# Returns: 0 on success, 1 on failure
##############################################################################

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/config.sh

set -e

pushd $IPA_DIR
sudo $DNF install -y rpm-build `grep "^BuildRequires" freeipa.spec.in | awk '{ print $2 }' | grep -v "^/"`
echo `grep "^BuildRequires" freeipa.spec.in | awk '{ print $2 }' | grep -v "^/"`
popd
