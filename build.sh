#!/bin/bash

set -x
set -e

ln -s $(pwd)/app/images_default app/images
cd app
polymer build --preset es5-bundled
mv build/es5-bundled build/app
cd ..
docker run --rm -v $PWD:/app lts-booking
cp lts-booking app/build/

