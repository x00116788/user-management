import boto3
import json
import logging
import os
import bcrypt

from datetime import datetime

logger = logging.getLogger()
dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
table = dynamodb.Table(os.getenv("TABLE_NAME", "USERS"))
now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

# bcrypt.hashpw(password.encode(), bcrypt.gensalt()),    

def create_user(event):
    SUPPORTED_METHODS = ["POST"]
    method = event["httpMethod"]
    path = event["path"]
    email = (event["body"]).get("email")
    username = (event["body"]).get("name")
    secret = (event["body"]).get("password")

    if method not in SUPPORTED_METHODS:
        logger.error(
            f"Unsupported method {method}. Path {path} only supports {str(SUPPORTED_METHODS)}"
        )
        return {
            "statusCode": 405,
            "headers": {"Content-Type": "application/json"},
            "body": "Allow: POST",
        }
    if not email or secret or username:
        logger.error("Missing User data")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": "Required: Username, Email, Password",
        }
    user_dict={
        "email": email,
        "username": username,
        "password": secret,
        "last_login": now
    }
    table.put_item(Item = user_dict)
    return{
        "statusCode": 201,
        "headers": {"Content-Type": "application/json"},
        "body": f"User: {username} Created Successfully",
    }

    
def update_user(event):
    # assuming only password is updated
    SUPPORTED_METHODS = ["PATCH"]
    method = event["httpMethod"]
    path = event["path"]
    email = (event["body"]).get("email")
    secret = (event["body"]).get("password")
    new_secret = (event["body"]).get("new_password")
    if method not in SUPPORTED_METHODS:
        logger.error(
            f"Unsupported method {method}. Path {path} only supports {str(SUPPORTED_METHODS)}"
        )
        return {
            "statusCode": 405,
            "headers": {"Content-Type": "application/json"},
            "body": "Allow: POST",
        }
    if not email or secret or new_secret:
        logger.error("Missing User data")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": "Required: Username, Email, Password",
        }
    response = table.update_item(
        Key={"email": email, "password": secret},
        UpdateExpression="set password=:p",
        ExpressionAttributeValues={":p": new_secret},
        ReturnValues="UPDATED_NEW",
    )

    return(
        return(
        "statusCode": 204,
        "headers": {"Content-Type": "application/json"},
        "body": f"Password Updated for {email}")
    )
    
def delete_user(event):
    SUPPORTED_METHODS = ["DELETE"]
    method = event["httpMethod"]
    path = event["path"]
    email = (event["body"]).get("email")
    secret = (event["body"]).get("password")
    
    if method not in SUPPORTED_METHODS:
        logger.error(
            f"Unsupported method {method}. Path {path} only supports {str(SUPPORTED_METHODS)}"
        )
        return {
            "statusCode": 405,
            "headers": {"Content-Type": "application/json"},
            "body": "Allow: DELETE",
        }
    if not email or secret:
        logger.error("Missing User data")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": "Required: Username, Email, Password",
        }
    table.delete_item(
        Key={
            "email": email,
            "password": secret
        }
    )
    return(
        "statusCode": 204,
        "headers": {"Content-Type": "application/json"},
        "body": f"User with email {email} has been Deleted")
    
    
def login(event):
    """Handle API call to retrieve a user items.
    Get item from DB, verify password and return to API caller
    """
    SUPPORTED_METHODS = ["POST"]
    method = event["httpMethod"]
    path = event["path"]
    email = (event["body"]).get("email")
    secret = (event["body"]).get("password")
    
    if method not in SUPPORTED_METHODS:
        logger.error(
            f"Unsupported method {method}. Path {path} only supports {str(SUPPORTED_METHODS)}"
        )
        return {
            "statusCode": 405,
            "headers": {"Content-Type": "application/json"},
            "body": "Allow: POST",
        }
    if not email or secret:
        logger.error("Missing User data")
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": "Required: Username, Email, Password",
        }
    logger.info("Getting user from database")
    response = table.get_item(
        Key={
            "email":email,
            "password": secret
        }
    )
    if not response["Item"]:
        logger.error("User not found")
        return {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json"},
            "body": "Not Found"
        }
    
    if secret == response["Item"]["password"]:
        response["Item" ].pop("password")
        response["Item"]["last_login"] = now
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response["Items"]),
        }
    
def handler(event, context):
    """Lambda entrypoint"""
    logger.info(json.dumps(event))

    # Paths subject to change
    if event["path"] == "user/create":
        return create_user(event)
        
    elif event["path"] == "user/login":
        return login(event)
    
    elif event["path"] == "user/update":
        return update_user(event)
    
    elif event["path"] == "user/delete":
        return delete_user(event)
    else:
        logger.error(f"Path {event['path']} not found")
        return {
            "statusCode": 404,
            "headers": {"Content-Type": "application/json"},
            "body": "Not Found",
        }


if __name__ == "__main__":
    test_payload = {
        "body": {
            "email": "suli@me.com",
            "password":"TestPass"
        },
        "path": "/user/login",
        "httpMethod": "POST",
    }

    handler(test_payload, None)
