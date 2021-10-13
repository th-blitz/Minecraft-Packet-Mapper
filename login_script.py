from Bridge import Proxy2Server
import os
from DataTypes import Packet, A_Packet_Class
from DataTypes import VarInt, Output_Streamer, Bytes_Streamer, Socket_Streamer
import time


output = Output_Streamer()

input = Bytes_Streamer()

login_packets = A_Packet_Class()

SOCK = Socket_Streamer('connect.2b2t.org', 25565, login_packets)

handshake = Packet(login_packets)
handshake.set(['VarInt', 'VarInt', 'String', 'Ushort', 'VarInt'])

status = Packet(login_packets)
status.set(['VarInt', 'String'])

request = Packet(login_packets)
request.set(['VarInt'])

ping_pong = Packet(login_packets)
ping_pong.set(['VarInt', 'Long'])

encryption_req = Packet(login_packets)
encryption_req.set(['VarInt', 'String', 'String', 'String'])

encryption_res = Packet(login_packets)
encryption_res.set(['VarInt', 'String', 'String'])

login_success = Packet(login_packets)
login_success.set(['VarInt', 'String', 'String'])

set_compression = Packet(login_packets)
set_compression.set(['VarInt', 'VarInt'])

def pack_0(self, input):

    if self.compression_enabled == True:
        self.compress(input)

    packet_len = input.add_len()
    # print(packet_len)
    return

def unpack_0(self, input, output):

    # if self.compression_enabled == True:
    #     self.decompress(input)

    output.reset()
    return

login_packets.map_pack(pack_0)
login_packets.map_unpack(unpack_0)




# data = handshake.pack([0x00, 340, b'2b2t.org', 25565, 1])
# server_sock.write(data)
# data = request.pack([0x00])
# server_sock.write(data)

# status.unpack(server_sock, output)

input.write(handshake.pack([0x00, 340, b'2b2t.org', 25565, 2]))

SOCK.write(input)

input.write(status.pack([0x00, b'ThBlitz']))

SOCK.write(input)

SOCK.read(input)

encryption_req.unpack(input, output)

print(f'encryption_req : {output.getvalue()}')

data = output.getvalue()
login_packets.server_id = data[1]
login_packets.server_public_key = data[2]
login_packets.verification_token = data[3]

import secrets
login_packets.aes_key = secrets.randbits(128).to_bytes(16, 'big')

hash , ver_token , shared_secret = login_packets.get_hash()

import mojang_api
uuid , name , token , login_data = mojang_api.login_through_microsoft()
res = mojang_api.join_server(token, uuid, hash)
print(f'response from mojang : {res}')

input.reset()
input.write(encryption_res.pack([0x01, shared_secret, ver_token]))

SOCK.write(input)

login_packets.encryption_enabled = True

SOCK.read(input)

set_compression.unpack(input, output)

login_packets.compression_threshold = output.getvalue()[1]
login_packets.compression_enabled = True

print(f'compression_packet : {output.getvalue()}')

SOCK.read(input)

login_success.unpack(input, output)

print(f'login_success : {output.getvalue()}')

SOCK.read(input)

status.unpack(input, output)
print(input.getvalue())

while True:
    SOCK.read(input)
    print(hex(VarInt.unpack(input)))
    print(input.read())
    time.sleep(1)









# t
