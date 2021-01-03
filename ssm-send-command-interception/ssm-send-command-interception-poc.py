#!/usr/bin/env python3

import requests, json, uuid
import aws_requests


def retrieve_meta() -> json:
    resp = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
    return json.loads(resp.text)


def retrieve_role_name() -> str:
    resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    return resp.text


def retrieve_role_creds(role_name) -> json:
    headers = { "X-Aws-Ec2-Metadata-Token-Ttl-Seconds": "21600" }
    resp = requests.put("http://169.254.169.254/latest/api/token", headers=headers)
    api_token = resp.text

    headers = { "X-Aws-Ec2-Metadata-Token": api_token }
    resp = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/"+role_name, headers=headers)
    return json.loads(resp.text)


# Get role name and creds
role_name = retrieve_role_name()
role_creds = retrieve_role_creds(role_name)
meta = retrieve_meta()

# Bother ec2messages to get commands for send-command
while True:
    message_id = ""
    command_id = ""
    while command_id == "":
        message_id = str(uuid.uuid4())
        command_id = aws_requests.get_messages(meta['instanceId'], message_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

    # Get acknowledge message
    aws_requests.acknowledge_message(meta['instanceId'], command_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
    aws_requests.send_reply(meta['instanceId'], command_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
