if [ -d /dist ]; then
    cp /tmp/dist/qtrace-*.whl /dist
else
    pytest -v /tests
fi
