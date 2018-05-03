#!/bin/bash

set -e
set -x

for PYTHON in python python3; do
    $PYTHON --version
    head -n5 sign.input | $PYTHON eddsa.py
    $PYTHON test.py
done
