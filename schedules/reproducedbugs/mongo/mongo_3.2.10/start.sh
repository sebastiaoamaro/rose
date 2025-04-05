#!/bin/bash
mongo <<EOF
var config = {
    "_id": "rs0",
    "version": 1,
    "members": [
        {
            "_id": 1,
            "host": "mongo0:27017",
        },
        {
            "_id": 2,
            "host": "mongo1:27017",
        },
        {
            "_id": 3,
            "host": "mongo2:27017",
            "arbiterOnly" : true

        }
    ]
};
rs.initiate(config, { force: true });
rs.status();
EOF
