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
        },
        {
            "_id": 9,
            "host": "mongo8:27017",
            "priority":0
        },
        {
            "_id": 10,
            "host": "mongo9:27017",
            "priority":0
        },
        {
            "_id": 11,
            "host": "mongo10:27017",
            "priority":0
        },
        {
            "_id": 12,
            "host": "mongo11:27017",
            "priority":0
        },
        {
            "_id": 13,
            "host": "mongo12:27017",
            "priority":0
        },
        {
            "_id": 14,
            "host": "mongo13:27017",
            "priority":0
        },
        {
            "_id": 15,
            "host": "mongo14:27017",
            "priority":0
        },
        {
            "_id": 16,
            "host": "mongo15:27017",
            "priority":0
        }
    ],
};
rs.initiate(config, { force: true });
rs.status();
EOF
