#!/bin/bash
for PYTHON in python python3; do
    echo `which $PYTHON`
    $PYTHON --version
    head -n5 sign.input | $PYTHON eddsa.py
    $PYTHON test.py
done
