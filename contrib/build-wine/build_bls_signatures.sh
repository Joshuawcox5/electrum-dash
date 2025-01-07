#!/bin/bash

set -ev

export BLS_SIGNATURES_REPO="https://github.com/LexxXell/electrum-dash"
export BLS_SIGNATURES_HASH_COMMIT="1bdbe02837121c899038b482c1e842e9170edec7"

echo "Building dashpay/bls-signatures for $WINEARCH."
export PROJ_ROOT=$WINEPREFIX/drive_c/electrum-dash
export DIST_DIR=$WINEPREFIX/drive_c/bls-signatures

cd $PROJ_ROOT
rm -rf dist/bls-signatures/
mkdir -p dist/bls-signatures/
cd dist/bls-signatures/
export PREFIX_DIR="$(pwd)/dist"
# Shallow clone
git init
git remote add origin $BLS_SIGNATURES_REPO
git fetch --depth 1 origin $BLS_SIGNATURES_HASH_COMMIT
git checkout -b pinned "${BLS_SIGNATURES_HASH_COMMIT}^{commit}"

# add reproducible randomness.
echo -e "\nconst char *dash_electrum_tag" \
        " = \"tagged by Dash-Electrum@$ELECTRUM_COMMIT_HASH\";" \
        >> ./src/bls.cpp

echo "LDFLAGS = -no-undefined" >> Makefile.am
./autogen.sh || fail "Could not run autogen."
./configure \
    --host=${GCC_TRIPLET_HOST} \
    --prefix="${PREFIX_DIR}" \
    --disable-bench \
    --disable-tests \
    --disable-static \
    --enable-shared || fail "Could not configure."
make -j4 || fail "Could not build."
make install || fail "Could not install."
. "${PREFIX_DIR}/lib/libdashbls.la"
$host_strip "${PREFIX_DIR}/lib/$dlname"
mkdir -p $DIST_DIR
cp -fpv "${PREFIX_DIR}/lib/$dlname" $DIST_DIR || fail "Could not copy."
