#!/usr/bin/env python3

import sys, uuid, time, hashlib, binascii

# the ssm-agent has this beauty in agent/session/contracts/agentmessage.go
# Shame I didn't start this project in Go, now we're gonna have to write python to 
# deserialize all this. No biggie

# Stealing their constants

# HL - HeaderLength is a 4 byte integer that represents the header length.
# MessageType is a 32 byte UTF-8 string containing the message type.
# SchemaVersion is a 4 byte integer containing the message schema version number.
# CreatedDate is an 8 byte integer containing the message create epoch millis in UTC.
# SequenceNumber is an 8 byte integer containing the message sequence number for serialized message streams.
# Flags is an 8 byte unsigned integer containing a packed array of control flags:
#   Bit 0 is SYN - SYN is set (1) when the recipient should consider Seq to be the first message number in the stream
#   Bit 1 is FIN - FIN is set (1) when this message is the final message in the sequence.
# MessageId is a 40 byte UTF-8 string containing a random UUID identifying this message.
# Payload digest is a 32 byte containing the SHA-256 hash of the payload.
# Payload Type is a 4 byte integer containing the payload type.
# Payload length is an 4 byte unsigned integer containing the byte length of data in the Payload field.
# Payload is a variable length byte data.
#
# | HL|         MessageType           |Ver|  CD   |  Seq  | Flags |
# |         MessageId                     |           Digest              |PayType| PayLen|
# |         Payload                            |


class AgentMessage:
    messageType = ""
    schemaVersion = ""
    createdDate = ""
    sequenceNumber = ""
    flags = ""
    messageId = ""
    payloadDigest = ""
    payloadType = ""
    payloadLength = ""
    headerLength = ""
    payload = ""

    def __init__(self, message):
        self.messageType = getString(message, AgentMessage_MessageTypeOffset, AgentMessage_MessageTypeLength)
        print(f"Message Type: {self.messageType}")

        self.schemaVersion = getUInteger(message, AgentMessage_SchemaVersionOffset)
        print(f"Schema Version: {self.schemaVersion}")

        self.createdDate = getULong(message, AgentMessage_CreatedDateOffset)
        print(f"Created Date: {self.createdDate}")

        self.sequenceNumber = getLong(message, AgentMessage_SequenceNumberOffset)
        print(f"Sequence Number: {self.sequenceNumber}")

        self.flags = getULong(message, AgentMessage_FlagsOffset)
        print(f"Flags: {self.flags}")

        self.messageId = getUuid(message, AgentMessage_MessageIdOffset)
        print(f"Message ID: {self.messageId}")

        self.payloadDigest = getBytes(message, AgentMessage_PayloadDigestOffset, AgentMessage_PayloadDigestLength)
        print(f"Payload Digest: {self.payloadDigest}")

        self.payloadType = getUInteger(message, AgentMessage_PayloadTypeOffset)
        print(f"Payload Type: {self.payloadType}")

        self.payloadLength = getUInteger(message, AgentMessage_PayloadLengthOffset)
        print(f"Payload Length: {self.payloadLength}")

        self.headerLength = getUInteger(message, AgentMessage_HLOffset)
        print(f"Header Length: {self.headerLength}")

        self.payload = message[self.headerLength+AgentMessage_PayloadLengthLength:]
        print(f"Payload: {self.payload}")


AgentMessage_HLLength             = 4
AgentMessage_MessageTypeLength    = 32
AgentMessage_SchemaVersionLength  = 4
AgentMessage_CreatedDateLength    = 8
AgentMessage_SequenceNumberLength = 8
AgentMessage_FlagsLength          = 8
AgentMessage_MessageIdLength      = 16
AgentMessage_PayloadDigestLength  = 32
AgentMessage_PayloadTypeLength    = 4
AgentMessage_PayloadLengthLength  = 4

AgentMessage_HLOffset             = 0
AgentMessage_MessageTypeOffset    = AgentMessage_HLOffset + AgentMessage_HLLength
AgentMessage_SchemaVersionOffset  = AgentMessage_MessageTypeOffset + AgentMessage_MessageTypeLength
AgentMessage_CreatedDateOffset    = AgentMessage_SchemaVersionOffset + AgentMessage_SchemaVersionLength
AgentMessage_SequenceNumberOffset = AgentMessage_CreatedDateOffset + AgentMessage_CreatedDateLength
AgentMessage_FlagsOffset          = AgentMessage_SequenceNumberOffset + AgentMessage_SequenceNumberLength
AgentMessage_MessageIdOffset      = AgentMessage_FlagsOffset + AgentMessage_FlagsLength
AgentMessage_PayloadDigestOffset  = AgentMessage_MessageIdOffset + AgentMessage_MessageIdLength
AgentMessage_PayloadTypeOffset    = AgentMessage_PayloadDigestOffset + AgentMessage_PayloadDigestLength
AgentMessage_PayloadLengthOffset  = AgentMessage_PayloadTypeOffset + AgentMessage_PayloadTypeLength
AgentMessage_PayloadOffset        = AgentMessage_PayloadLengthOffset + AgentMessage_PayloadLengthLength


def deserialize(message):
    return AgentMessage(message)


def serialize(message, message_type, schema_version, created_date, sequence_number, flags, messageid, payload_type):
    payloadLength = len(message)
    headerLength = AgentMessage_PayloadLengthOffset

    totalMessageLength = headerLength + AgentMessage_PayloadLengthLength + payloadLength
    result = bytearray(totalMessageLength)

    result = putUInteger(result, AgentMessage_HLOffset, headerLength)

    startPosition = AgentMessage_MessageTypeOffset
    endPosition = AgentMessage_MessageTypeOffset + AgentMessage_MessageTypeLength - 1
    result = putString(result, startPosition, endPosition, message_type)

    result = putUInteger(result, AgentMessage_SchemaVersionOffset, schema_version)

    result = putULong(result, AgentMessage_CreatedDateOffset, created_date)

    result = putLong(result, AgentMessage_SequenceNumberOffset, sequence_number)
    
    result = putULong(result, AgentMessage_FlagsOffset, flags)

    result = putUuid(result, AgentMessage_MessageIdOffset, messageid)

    hasher = hashlib.sha256(message.encode()).hexdigest()
    hasher_bytes = inputBytes = binascii.unhexlify(hasher)

    startPosition = AgentMessage_PayloadDigestOffset
    endPosition = AgentMessage_PayloadDigestOffset + AgentMessage_PayloadDigestLength - 1

    result = putBytes(result, startPosition, endPosition, hasher_bytes)

    result = putUInteger(result, AgentMessage_PayloadTypeOffset, payload_type)

    result = putUInteger(result, AgentMessage_PayloadLengthOffset, payloadLength)

    startPosition = AgentMessage_PayloadOffset
    endPosition = AgentMessage_PayloadOffset + payloadLength - 1
    
    result = putBytes(result, startPosition, endPosition, message.encode())

    return result

def getUInteger(input_bytes, offset):
    return getInteger(input_bytes, offset)


def putUInteger(result, offset, value):
    return putInteger(result, offset, value)


def getInteger(input_bytes, offset):
    byteArrayLength = len(input_bytes)
    if offset > byteArrayLength-1 or offset+4 > byteArrayLength-1 or offset < 0:
        print("ERROR: getInteger")
    return bytesToInteger(input_bytes[offset:offset+4])


def putInteger(byteArray, offset, value):
    byteArrayLength = len(byteArray)
    if offset > byteArrayLength-1 or offset+4 > byteArrayLength-1 or offset < 0:
        print("ERROR: putInteger")
    
    bytess = integerToBytes(value)
    for count, index in enumerate(range(offset,offset+4)):
        byteArray[index] = bytess[count]

    return byteArray


def bytesToInteger(input_bytes):
    inputLength = len(input_bytes)
    if inputLength != 4:
        print("ERROR: bytesToInteger")
    return int.from_bytes(input_bytes, "big")


def integerToBytes(input_bytes):
    return input_bytes.to_bytes(4, "big")


def getString(input_bytes, offset, stringLength):
    byteArrayLength = len(input_bytes)
    if offset > byteArrayLength-1 or offset+stringLength-1 > byteArrayLength-1 or offset < 0:
        print("ERROR: getString")

    # remove nulls from the bytes array
    return input_bytes[offset:offset+stringLength].decode("UTF-8")


def putString(byteArray, offsetStart, offsetEnd, inputString):
    byteArrayLength = len(byteArray)
    if offsetStart > byteArrayLength-1 or offsetEnd > byteArrayLength-1 or offsetStart > offsetEnd or offsetStart < 0:
        print("ERROR: putString 1")

    if offsetEnd-offsetStart+1 < len(inputString):
        print("ERROR: putString 2")

    for i in range(offsetStart, offsetEnd+1):
        byteArray[i] = ord(' ')

    # previous offsetEnd+1
    byteArray = byteArray[:offsetStart] + inputString.encode() + byteArray[offsetStart+len(inputString.encode()):] 

    return byteArray


def getULong(input_bytes, offset):
    return getLong(input_bytes, offset)


def putULong(byteArray, offset, value):
    return putLong(byteArray, offset, value)


def bytesToLong(input_bytes):
    inputLength = len(input_bytes)
    if inputLength != 8:
        print("ERROR: bytesToLong")
    return int.from_bytes(input_bytes, "big")


def getLong(input_bytes, offset):
    byteArrayLength = len(input_bytes)
    if offset > byteArrayLength-1 or offset+8 > byteArrayLength-1 or offset < 0:
        print("ERROR: getLong")
    return bytesToLong(input_bytes[offset:offset+8])


def putLong(byteArray, offset, value):
    byteArrayLength = len(byteArray)
    if offset > byteArrayLength-1 or offset+8 > byteArrayLength-1 or offset < 0:
        print("ERROR: putLong")

    mbytes = longToBytes(value)

    byteArray = byteArray[:offset] + mbytes + byteArray[offset+8+1:]

    return byteArray


def longToBytes(input_int):
    some_bytes = input_int.to_bytes(8, 'big')
    if len(some_bytes) != 8:
        print("ERROR: longToBytes")
    return some_bytes


def getUuid(input_bytes, offset):
    byteArrayLength = len(input_bytes)
    if offset > byteArrayLength-1 or offset+16-1 > byteArrayLength-1 or offset < 0:
        print("ERROR: getUuid")

    leastSignificantLong = getLong(input_bytes, offset)
    leastSignificantBytes = longToBytes(leastSignificantLong)

    mostSignificantLong = getLong(input_bytes, offset+8)
    mostSignificantBytes = longToBytes(mostSignificantLong)

    uuidBytes = mostSignificantBytes + leastSignificantBytes
    return uuid.UUID(bytes=uuidBytes)


def putUuid(byteArray, offset, input_uuid):
    if len(input_uuid.bytes) == 0:
        print("ERROR: putUuid 1")

    byteArrayLength = len(byteArray)
    if offset > byteArrayLength-1 or offset+16-1 > byteArrayLength-1 or offset < 0 :
        print("ERROR: putUuid 2")

    leastSignificantLong = bytesToLong(input_uuid.bytes[8:16])
    mostSignificantLong = bytesToLong(input_uuid.bytes[0:8])

    byteArray = putLong(byteArray, offset, leastSignificantLong)
    byteArray = putLong(byteArray, offset+8, mostSignificantLong)

    return byteArray


def getBytes(input_bytes, offset, byteLength):
    byteArrayLength = len(input_bytes)
    if offset > byteArrayLength-1 or offset+byteLength-1 > byteArrayLength-1 or offset < 0:
        print("ERROR: getBytes")
    return input_bytes[offset:offset+byteLength]


def putBytes(byteArray, offsetStart, offsetEnd, inputBytes):
    byteArrayLength = len(byteArray)
    #if offsetStart > byteArrayLength-1 or offsetEnd > byteArrayLength-1 or offsetStart > offsetEnd or offsetStart < 0:
    #    print("ERROR: putBytes 1")

    if offsetEnd-offsetStart+1 != len(inputBytes):
        print("ERROR: putBytes 2")

    byteArray = byteArray[:offsetStart] + inputBytes + byteArray[offsetEnd+1:]
    return byteArray


#created_date = int(round(time.time() * 1000))
#a = serialize('{"SchemaVersion":1,"SessionState":"Connected","SessionId":"Nick-09ff5e695b9e8cbc4"}', "agent_session_state", 1, created_date, 0, 3, uuid.uuid4(), 0)
#
#with open('binary.txt','rb') as r:
#    f = r.read()
#    AgentMessage(f)
#    print(f)
#
