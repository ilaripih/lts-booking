#!/bin/bash

set -x
set -e

docker run --rm -v $PWD:/app lts-booking
LTS_BOOKING_PORT=8081 ./lts-booking
