#! /bin/sh

PYTHON_VERSIONS="python2.7 python3.1 python3.2 python3.3 pypy"
TEST_SCRIPTS="testNSDP.py"

for PYTHON_VERSION in $PYTHON_VERSIONS; do
    PYTHON=`which $PYTHON_VERSION`
    if [ $? -eq 0 ]; then
        echo Testing with $PYTHON_VERSION
        for TEST_SCRIPT in $TEST_SCRIPTS; do
            $PYTHON $TEST_SCRIPT
            if [ $? -ne 0 ]; then
                exit $?
            fi
        done
    else
        echo No executable found for $PYTHON_VERSION
    fi
done

