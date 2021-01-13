#!/usr/bin/env python3

import requests, json, time, uuid
import websocket
import aws_requests
import aws_msg

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

def parse_data_channel(data):
    lines = data.split("\n")
    access_token= lines[2][lines[2].find(">")+1:lines[2].find("</")]
    return access_token

# Get role name and credentials
role_name = retrieve_role_name()
role_creds = retrieve_role_creds(role_name)
meta = retrieve_meta()

aws_requests.post_base(meta['privateIp'], meta['instanceId'], role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

# Create control channel connection
resp = aws_requests.post_control_channel(meta['instanceId'], role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

access_token, url = parse_control_channel(resp)

# Connect to Websocket
path = url[url.find("/v1"):]
control_channel_info = aws_requests.initiate_websocket_connection(url, path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

control_channel = websocket.WebSocket()
control_channel.connect(control_channel_info[0], header=control_channel_info[1])

control_channel.send('{"Cookie":null,"MessageSchemaVersion":"1.0","RequestId":"'+str(uuid.uuid4())+'","TokenValue":"'+access_token+'","AgentVersion":"3.0.161.0","PlatformType":"linux"}')
first_response = aws_msg.deserialize(control_channel.recv())
first_response_payload = json.loads(first_response.payload)
first_response_content = json.loads(first_response_payload['content'])
session_id = first_response_content['SessionId']

# Create data channel connection
resp = aws_requests.post_data_channel(session_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
print(resp)
access_token = parse_data_channel(resp)

# Connect to Websocket
path = "/v1/data-channel/"+session_id+"?role=publish_subscribe"
data_channel_info = aws_requests.initiate_websocket_connection("wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/"+session_id+"?role=publish_subscribe", path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

data_channel = websocket.WebSocket()
print("Data Channel URL: " + data_channel_info[0])
data_channel.connect(data_channel_info[0], header=data_channel_info[1])

data_channel.send('{"MessageSchemaVersion":"1.0","RequestId":"'+str(uuid.uuid4())+'","TokenValue":"'+access_token+'","ClientInstanceId":"i-03a6d204ea995a6fa","ClientId":""}')

created_date = int(round(time.time() * 1000))
msg = aws_msg.serialize('{"SchemaVersion":1,"SessionState":"Connected","SessionId":"'+first_response_content['SessionId']+'"}', "agent_session_state", 1, created_date, 0, 3, uuid.uuid4(), 0)
data_channel.send(bytes(msg))

print(data_channel.recv())
#


# Lost progress by stupidly not saving first
# the fix is the send_binary

#
#    ## Receive first ssm response with binary
#    first_response = aws_msg.deserialize(ws.recv())
#    first_response_payload = json.loads(first_response.payload)
#    first_response_content = json.loads(first_response_payload['content'])
#
#    ws.send('{"MessageSchemaVersion":"1.0","RequestId":"7295c5a0-5827-40af-88bf-d3160c0635f1","TokenValue":"'+access_token+'","ClientInstanceId":"i-03a6d204ea995a6fa","ClientId":""}')
#
#    ## Send first ssm message with binary
#    ## We are acknowledging session state
#    created_date = int(round(time.time() * 1000))
#    msg = aws_msg.serialize('{"SchemaVersion":1,"SessionState":"Connected","SessionId":"'+first_response_content['SessionId']+'"}', "agent_session_state", 1, created_date, 0, 3, uuid.uuid4(), 0)
#    ws.send(bytes(msg))
#
#    res = ws.recv()


