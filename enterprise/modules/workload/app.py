"""Minimal application tier: proves the app role can reach its own data stores.

GET /health -> reads its secret metadata, writes and reads one DynamoDB item.
The database password is fetched at call time and never logged or returned.
"""
import json
import os
import time

import boto3

TABLE = os.environ["TABLE_NAME"]
SECRET_ARN = os.environ["DB_SECRET_ARN"]


def handler(event, context):
    secret = boto3.client("secretsmanager").get_secret_value(SecretId=SECRET_ARN)
    db = json.loads(secret["SecretString"])

    table = boto3.resource("dynamodb").Table(TABLE)
    table.put_item(Item={"pk": "health", "ts": int(time.time())})
    item = table.get_item(Key={"pk": "health"}).get("Item", {})

    body = {"status": "ok", "db_user": db.get("username"), "last_write": int(item.get("ts", 0))}
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }
