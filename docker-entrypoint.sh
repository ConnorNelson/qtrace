if [ -d /dist ]; then
    cp /tmp/dist/qtrace-*.whl /dist
else
    pytest -v --durations=0 /tests
fi
