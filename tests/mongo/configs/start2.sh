#!/bin/bash
mongosh <<EOF
var config = {
    "_id": "rs0",
    "version": 1,
    "members": [
        {
            "_id": 1,
            "host": "mongo0:27017",
            "priority":1
        },
        {
            "_id": 2,
            "host": "mongo1:27017",
            "priority":0

        }
    ],
};
rs.initiate(config, { force: true });
rs.status();
EOF
