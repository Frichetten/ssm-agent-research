import requests, json, datetime, hashlib, hmac


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def getSignatureKey(key, date_stamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning


def acknowledge_message(instance_id, acknowledge_id, access_key, secret_access_key, session_token):
    method = 'POST'
    service = 'ec2messages'
    host = 'ec2messages.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://ec2messages.us-east-1.amazonaws.com/'
    content_type = 'application/x-amz-json-1.1'
    amz_target = 'EC2WindowsMessageDeliveryService.AcknowledgeMessage'

    request_parameters =  {}
    request_parameters["MessageId"] = "aws.ssm." + acknowledge_id + "." + instance_id

    request_parameters = json.dumps(request_parameters)

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

    signing_key = getSignatureKey(secret_access_key, date_stamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'Content-Type':content_type,
               'X-Amz-Date':amz_date,
               'X-Amz-Target':amz_target,
               'X-Amz-Security-Token':session_token,
               'Authorization':authorization_header}

    r = requests.post(endpoint, data=request_parameters, headers=headers)

    print("Acknowledge Message -> Response (%s): %s" % (r.status_code, r.text))


def send_reply(instance_id, acknowledge_id, access_key, secret_access_key, session_token):
    method = 'POST'
    service = 'ec2messages'
    host = 'ec2messages.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://ec2messages.us-east-1.amazonaws.com/'
    content_type = 'application/x-amz-json-1.1'
    amz_target = 'EC2WindowsMessageDeliveryService.SendReply'

    request_parameters =  {}
    request_parameters["MessageId"] = "aws.ssm." + acknowledge_id + "." + instance_id
    request_parameters["Payload"] = "{\"additionalInfo\":{\"agent\":{\"lang\":\"en-US\",\"name\":\"amazon-ssm-agent\",\"os\":\"\",\"osver\":\"1\",\"ver\":\"\"},\"dateTime\":\"2021-01-03T19:42:06.770Z\",\"runId\":\"\",\"runtimeStatusCounts\":{\"Success\":1}},\"documentStatus\":\"Success\",\"documentTraceOutput\":\"\",\"runtimeStatus\":{\"aws:runShellScript\":{\"status\":\"Success\",\"code\":0,\"name\":\"aws:runShellScript\",\"output\":\"Ain't your business\\n\",\"startDateTime\":\"2021-01-03T19:42:01.480Z\",\"endDateTime\":\"2021-01-03T19:42:06.769Z\",\"outputS3BucketName\":\"\",\"outputS3KeyPrefix\":\"\",\"stepName\":\"\",\"standardOutput\":\"Ain't your business\\n\",\"standardError\":\"\"}}}"
    request_parameters["ReplyId"] = acknowledge_id

    request_parameters = json.dumps(request_parameters)

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

    signing_key = getSignatureKey(secret_access_key, date_stamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'Content-Type':content_type,
               'X-Amz-Date':amz_date,
               'X-Amz-Target':amz_target,
               'X-Amz-Security-Token':session_token,
               'Authorization':authorization_header}

    r = requests.post(endpoint, data=request_parameters, headers=headers)

    print("Send Reply -> Response (%s): %s" % (r.status_code, r.text))


def get_messages(instance_id, message_id, access_key, secret_access_key, session_token):
    method = 'POST'
    service = 'ec2messages'
    host = 'ec2messages.us-east-1.amazonaws.com'
    region = 'us-east-1'
    endpoint = 'https://ec2messages.us-east-1.amazonaws.com/'
    content_type = 'application/x-amz-json-1.1'
    amz_target = 'EC2WindowsMessageDeliveryService.GetMessages'

    request_parameters =  {}
    request_parameters["Destination"] = instance_id
    request_parameters["MessagesRequestId"] = message_id
    request_parameters["VisibilityTimeoutInSeconds"] = 10

    request_parameters = json.dumps(request_parameters)

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

    signing_key = getSignatureKey(secret_access_key, date_stamp, region, service)

    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

    headers = {'Content-Type':content_type,
               'X-Amz-Date':amz_date,
               'X-Amz-Target':amz_target,
               'X-Amz-Security-Token':session_token,
               'Authorization':authorization_header}

    r = requests.post(endpoint, data=request_parameters, headers=headers)
    response = json.loads(r.text)

    print("Get Messages -> Response (%s): %s" % (r.status_code, r.text))

    if len(response["Messages"]) > 0:
        further = json.loads(response["Messages"][0]["Payload"])
        return further["CommandId"]
    else:
        return ""



