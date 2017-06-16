#!/bin/bash

set -x
set -e

cd app
polymer build --preset es5-bundled
mv build/es5-bundled build/app
cd ..
sudo docker run --rm -v $PWD:/app lts-booking
cp lts-booking app/build/

