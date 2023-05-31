#!/bin/bash
#Run in mongo0?

mongo <<EOF
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
        },
        {
            "_id": 3,
            "host": "mongo2:27017",
            "priority":0
        },
        {
            "_id": 4,
            "host": "mongo3:27017",
            "priority":0
        },
        {
            "_id": 5,
            "host": "mongo4:27017",
            "priority":0
        },
        {
            "_id": 6,
            "host": "mongo5:27017",
            "priority":0
        },
        {
            "_id": 7,
            "host": "mongo6:27017",
            "priority":0
        },
        {
            "_id": 8,
            "host": "mongo7:27017",
            "priority":0
        }
    ],
};
rs.initiate(config, { force: true });
rs.status();
EOF