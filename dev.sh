#!/bin/bash

set -x
set -e

rm -f app/images
ln -s $(pwd)/app/images_default app/images
docker run --rm -v $PWD:/app lts-booking
LTS_BOOKING_PORT=8081 ./lts-booking
