import sys, os, base64, datetime, hashlib, hmac 
import requests, json
import websocket, asyncio
import urllib

def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def initiate_websocket_connection(url, path, access_token, A_access_key, A_secret_access_key, A_session_token):
    method = 'GET'
    service = 'ssmmessages'
    host = 'ssmmessages.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://ssmmessages.us-east-1.amazonaws.com'

    access_key = A_access_key
    secret_key = A_secret_access_key
    session_token = A_session_token

    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    canonical_uri = path[:path.find("?")]
    print(canonical_uri)

    canonical_querystring = path[path.find("?")+1:].replace("amp;","")
    print(canonical_querystring)

    url = url.replace("amp;","")
    print("url: " , url)

    path = path.replace("amp;","")

    canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n' + 'x-amz-security-token:' + session_token + '\n' 

    signed_headers = 'host;x-amz-date;x-amz-security-token'

    payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'X-Amz-Date':amzdate, 'X-Amz-Security-Token':session_token, 'Authorization':authorization_header, 'User-Agent': 'Go-http-client/1.1'}


    request_url = endpoint + '?' + canonical_querystring

    print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    print('Request URL = ' + request_url)
    #r = requests.get(request_url, headers=headers)
    ws = websocket.WebSocket()
    ws.connect(url, header=headers)

    ws.send('{"Cookie":null,"MessageSchemaVersion":"1.0","RequestId":"8e065b9a-f0f2-403b-a77e-a8b559732320","TokenValue":"'+access_token+'","AgentVersion":"3.0.161.0","PlatformType":"linux"}')
    print(ws.recv())
    ws.send('{"MessageSchemaVersion":"1.0","RequestId":"7295c5a0-5827-40af-88bf-d3160c0635f1","TokenValue":"'+access_token+'","ClientInstanceId":"i-08684a964c4c3f139","ClientId":""}')
    ws.send('tagent_session_state             ')
    print(ws.recv())
    ws.send('tacknowledge                     ')
    ws.send('')
    while True:
        res = ws.recv()
        print(res)
        ws.send("Haha!")

def post_control_channel(instanceid, A_access_key, A_secret_access_key, A_session_token):
    method = 'POST'
    service = 'ssmmessages'
    host = 'ssmmessages.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://ssmmessages.us-east-1.amazonaws.com/'
    content_type = 'application/json'
    amz_target = 'AmazonSSM.UpdateInstanceInformation'

    request_parameters =  {}
    request_parameters["MessageSchemaVersion"] = "1.0"
    request_parameters["RequestId"] = "8e065b9a-f0f2-403b-a77e-a8b559732320"

    request_parameters = json.dumps(request_parameters)

    access_key = A_access_key
    secret_key = A_secret_access_key
    session_token = A_session_token

    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    canonical_uri = '/v1/control-channel/'+instanceid

    canonical_querystring = ''

    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target + '\n'

    signed_headers = 'content-type;host;x-amz-date;x-amz-target'

    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    signing_key = getSignatureKey(secret_key, date_stamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'Content-Type':content_type,
               'X-Amz-Date':amz_date,
               'X-Amz-Target':amz_target,
               'X-Amz-Security-Token':session_token,
               'Authorization':authorization_header}

    r = requests.post(endpoint+"v1/control-channel/"+instanceid, data=request_parameters, headers=headers)

    print("Post Base -> Response (%s): %s" % (r.status_code, r.text))
    return r.text


def post_base(ipaddress, instanceid, A_access_key, A_secret_access_key, A_session_token):
    method = 'POST'
    service = 'ssm'
    host = 'ssm.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://ssm.us-east-1.amazonaws.com/'
    content_type = 'application/x-amz-json-1.1'
    amz_target = 'AmazonSSM.UpdateInstanceInformation'

    request_parameters =  {}
    request_parameters["AgentName"] = "amazon-ssm-agent"
    request_parameters["AgentStatus"] = "Active"
    request_parameters["AgentVersion"] = "2.3.978.0"
    request_parameters["ComputerName"] = "ip-172-31-50-113.ec2.internal"
    request_parameters["IPAddress"] = ipaddress
    request_parameters["InstanceId"] = instanceid
    request_parameters["PlatformName"] = "Ubuntu"
    request_parameters["PlatformType"] = "Linux"
    request_parameters["PlatformVersion"] = "20.04"

    request_parameters = json.dumps(request_parameters)

    access_key = A_access_key
    secret_key = A_secret_access_key
    session_token = A_session_token

    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

    canonical_uri = '/'

    canonical_querystring = ''

    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + host + '\n' + 'x-amz-date:' + amz_date + '\n' + 'x-amz-target:' + amz_target + '\n'

    signed_headers = 'content-type;host;x-amz-date;x-amz-target'

    payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash

    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = date_stamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' +  amz_date + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    signing_key = getSignatureKey(secret_key, date_stamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'Content-Type':content_type,
               'X-Amz-Date':amz_date,
               'X-Amz-Target':amz_target,
               'X-Amz-Security-Token':session_token,
               'Authorization':authorization_header}

    r = requests.post(endpoint, data=request_parameters, headers=headers)

    print("Post Base -> Response (%s): %s" % (r.status_code, r.text))
