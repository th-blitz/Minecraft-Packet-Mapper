import struct
import io
import zlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hashlib import sha1
import uuid
import socket

# setting the following objects
# bytes_stream.recv(1) == bytes_stream.read(1) is a must and very important
# bytes_stream.send(1) == bytes_stream.write(1) is a must.

class Proxy2Server:

    def __init__(self, host, port):
        super(Proxy2Server, self).__init__()
        self.__port = port
        self.__host = host
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__sock.connect((host, port))

    def read(self, value):
        while True:
            data = self.__sock.recv(value)
            if data:
                break
        return data

    def write(self, value):
        self.__sock.sendall(value)
        return


class Socket_Streamer:

    def __init__(self, host, port, a_packet_class):
        self.__socket_buffer = Proxy2Server(host, port)
        self.__packet_class = a_packet_class
        self.__bytes_buffer = Bytes_Streamer()
        self.__bandwidth = 1024

    def __get(self):
        data = self.__socket_buffer.read(self.__bandwidth)
        if self.__packet_class.encryption_enabled == True:
            data = self.__packet_class.decrypt_data(data)
        self.__bytes_buffer.write(data)
        self.__bytes_buffer.seek(0)

        return

    def read(self, bytes_stream):

        bytes_stream.reset()

        if self.__bytes_buffer.tell() >= 1024 or self.__bytes_buffer.getvalue() == b'':
            self.__bytes_buffer.reset()
            self.__get()

        elif self.__bytes_buffer.tell() >= self.__bytes_buffer.get_len():
            self.__bytes_buffer.reset()
            self.__get()


        packet_len = VarInt.unpack(self.__bytes_buffer)

        data = self.__bytes_buffer.read(packet_len)
        bytes_stream.write(data)
        bytes_stream.seek(0)
        return

    def write(self, bytes_stream):
        if self.__packet_class.encryption_enabled == True:
            self.__packet_class.encrypt(bytes_stream)
        self.__socket_buffer.write(bytes_stream.getvalue())
        bytes_stream.reset()
        return


class Output_Streamer:

    def __init__(self):
        self.__output_buffer = []
        self.__seek = 0

    def write(self, value):
        self.__output_buffer.append(value)
        self.__seek += 1
        return

    def read(self, value = None):
        a = self.__seek
        if value == None:
            data = self.__output_buffer[a:]
        elif value > 0:
            b = self.__seek + value
            data = self.__output_buffer[a:b]
        else:
            data = None
        return data

    def getvalue(self):
        return self.__output_buffer[0:]

    def seek(self, value):
        self.__seek = 0
        return

    def tell(self):
        return self.__seek

    def reset(self):
        self.__output_buffer = []
        self.__seek = 0
        return


class Bytes_Streamer:

    def __init__(self):
        self.__bytes_buffer = io.BytesIO()

    def write(self, value):
        self.__bytes_buffer.write(value)
        return

    def read(self, value = None):
        if value != None:
            data = self.__bytes_buffer.read(value)
        else:
            data = self.__bytes_buffer.read()
        return data

    def reset(self):
        self.__bytes_buffer.close()
        self.__bytes_buffer = io.BytesIO()
        return

    def seek(self, value_0, value_1 = None):
        if value_1 == None:
            self.__bytes_buffer.seek(value_0)
        else:
            self.__bytes_buffer.seek(value_1, value_0)
        return

    def tell(self):
        return self.__bytes_buffer.tell()

    def getvalue(self):
        return self.__bytes_buffer.getvalue()

    def add_len(self):
        data = self.__bytes_buffer.getvalue()
        length = len(data)
        self.reset()
        VarInt.pack(length, self.__bytes_buffer)
        self.__bytes_buffer.write(data)
        return length

    def get_len(self):
        data = self.__bytes_buffer.getvalue()
        length = len(data)
        return length

class A_Packet_Class:

    def __init__(self):

        self.compression_enabled = False
        self.compression_threshold = None
        self.encryption_enabled = False
        self.aes_key = None
        self.aes_decryptor = None
        self.aes_encryptor = None
        self.server_public_key = None
        self.server_id = None
        self.verification_token = None
        self.__hash = sha1()

        self.rsa_algorithm = PKCS1v15()

    def map_pack(self, func):
        self.map_pack = func
        return

    def map_unpack(self, func):
        self.map_unpack = func
        return

    def _pack_it(self, bytes_stream):
        self.map_pack(self, bytes_stream)
        return

    def _unpack_it(self, bytes_stream, output_stream = None):
        self.map_unpack(self, bytes_stream, output_stream)
        return

    def get_hash(self):

        self.__hash.update(self.server_id)
        self.__hash.update(self.aes_key)
        self.__hash.update(self.server_public_key)

        hash_value = int.from_bytes(self.__hash.digest(), byteorder='big', signed=True)
        hash_hex = format(hash_value, 'x')

        rsa = load_der_public_key(self.server_public_key, default_backend())
        e_token = rsa.encrypt(self.verification_token, self.rsa_algorithm)
        e_aes_key = rsa.encrypt(self.aes_key, self.rsa_algorithm)

        aes_cipher = Cipher(algorithms.AES(self.aes_key),
            modes.CFB8(self.aes_key), backend=default_backend())

        self.aes_decryptor = aes_cipher.decryptor()
        self.aes_encryptor = aes_cipher.encryptor()

        return hash_hex, e_token, e_aes_key

    def encrypt(self, bytes_stream):
        data = self.aes_encryptor.update(bytes_stream.getvalue())
        bytes_stream.reset()
        bytes_stream.write(data)
        bytes_stream.seek(0)
        return

    def decrypt(self, bytes_stream):
        data = self.aes_decryptor.update(bytes_stream.getvalue())
        bytes_stream.reset()
        bytes_stream.write(data)
        bytes_stream.seek(0)
        return

    def decrypt_data(self, data):
        data = self.aes_decryptor.update(data)
        return data

    def compress(self, bytes_stream):
        value = bytes_stream.getvalue()
        payload_len = len(value)
        bytes_stream.reset()
        if payload_len > self.compression_threshold != -1:
            VarInt.pack(payload_len, bytes_stream)
            bytes_stream.write(zlib.compress(value))
        else:
            VarInt.pack(0, bytes_stream)
            bytes_stream.write(value)
        bytes_stream.seek(0)
        return payload_len

    def decompress(self, bytes_stream):
        payload_len = VarInt.unpack(bytes_stream)

        if payload_len == 0:
            pass
        elif payload_len > 0:
            value = bytes_stream.getvalue()
            bytes_stream.reset()
            bytes_stream.write(zlib.decompress(value))
            bytes_stream.seek(0)
        return payload_len

    def decompress_data(self, bytes_stream):
        return


class Packet():

    def __init__(self, packet_class_obj):

        self.__set_vars = None
        self.__packet_class = packet_class_obj
        self.__bytes_buffer = Bytes_Streamer()
        self.__available_vars = {
            'VarInt' : VarInt,
            'Ushort' : Ushort,
            'String' : String,
            'Long'   : Long,
            'UUID'   : UUID
        }

    def set(self, values):
        self.__set_vars = values

    def info(self):

        info = {
            'packet_class' : self.__packet_class,
            'available_variables' : self.__available_vars,
            'set' : self.__set_vars
        }

        return info

    def pack(self, values):

        for var, value in zip(self.__set_vars , values):
            self.__available_vars[var].pack(value, self.__bytes_buffer)

        self.__packet_class._pack_it(self.__bytes_buffer)
        output = self.__bytes_buffer.getvalue()
        self.__bytes_buffer.reset()
        return output

    def unpack(self, bytes_stream, output_stream = None):

        self.__packet_class._unpack_it(bytes_stream, output_stream)

        for var in self.__set_vars:
            self.__available_vars[var].unpack(bytes_stream, output_stream)
        return


class VarInt:

    def __init__(self, value, datatype = 'int'):

        self.max_bytes = 5
        self.bytes_buffer = Bytes_Streamer()
        self.int_value = None

        if datatype == 'int':
            self.int_value = value
            self.pack(value, self.bytes_buffer)
        elif datatype == 'bytes':
            self.int_value = self.unpack(value)
            self.bytes_buffer.write(value)

        self.bytes_buffer.seek(0)

    def call(self, datatype = 'int'):

        if datatype == 'int':
            return self.int_value
        elif datatype == 'bytes_stream':
            return self.bytes_buffer
        elif datatype == 'bytes':
            return self.bytes_buffer.getvalue()

    @staticmethod
    def pack(int_value, output_stream = None):

        value = int_value
        output = bytes()
        while True:
            byte = value & 0x7F
            value >>= 7
            output += struct.pack('B', byte | (0x80 if value > 0 else 0))
            if value == 0:
                break

        if len(output) > 5:
            messg0 = r'VarInt.pack() function or VarInt() variable '
            messg1 = r'has encountered an int number of more than 5 bytes.'
            messg2 = f' The number {int_value} is too large to be wrapped as VarInt.'
            raise ValueError(messg0+messg1+messg2)

        if output_stream != None:
            output_stream.write(output)

        return output

    @staticmethod
    def unpack( bytes_stream, output_stream = None):
        flag_ = False
        output = 0
        for byte_count in range(5):
            each_byte = bytes_stream.read(1)
            temp_byte = ord(each_byte)
            output |= (temp_byte & 0x7F) << 7*byte_count
            if not temp_byte & 0x80:
                flag_ = True
                break
        if flag_ == False:
            messg0 = r'VarInt.unpack() function or VarInt() variable '
            messg1 = r'has encountered bytes of more than 5 bytes.'
            raise ValueError(messg0+messg1)
        if output_stream != None:
            output_stream.write(output)
        return output

class Ushort:

    def __init__(self, value, datatype = 'int'):

        self.bytes_length = 2
        self.bytes_buffer = Bytes_Streamer()
        self.int_value = None

        if datatype == 'int':
            self.int_value = value
            self.pack(value, self.bytes_buffer)

        elif datatype == 'bytes':
            self.int_value = self.unpack(value)
            self.bytes_buffer.write(value)

        self.bytes_buffer.seek(0)

    def call(self, datatype = 'int'):

        if datatype == 'int':
            return self.int_value
        elif datatype == 'bytes_stream':
            return self.bytes_buffer
        elif datatype == 'bytes':
            return self.bytes_buffer.getvalue()

    @staticmethod
    def pack(int_value, output_stream = None):
        try:
            output = struct.pack('>H', int_value)
        except struct.error:
            messg0 = f'The int value {int_value} recived by the function '
            messg1 = r'UnsignedShort.pack is too large to be packed as an '
            messg2 = r'UnsignedShort number. '
            messg3 = r'UnsignedShort numbers must have a fixed length of 2 bytes.'
            raise ValueError(messg0+messg1+messg2+messg3)

        if output_stream != None:
            output_stream.write(output)
        return output

    @staticmethod
    def unpack(bytes_stream, output_stream = None):
        bytes = bytes_stream.read(2)
        output = struct.unpack('>H', bytes)[0]
        if output_stream != None:
            output_stream.write(output)
        return output

class String:

    def __init__(self, value, datatype = 'str'):
        self.bytes_len = None
        self.bytes_buffer = Bytes_Streamer()
        self.str_value = None

        if datatype == 'str':
            self.str_value = value
            self.bytes_len, _ = self.pack(value.encode('utf-8'), self.bytes_buffer)

        elif datatype == 'bytes':
            self.bytes_len , self.str_value = self.unpack(value)
            self.str_value = self.str_value.decode('utf-8')
            self.bytes_buffer.write(value)

        self.bytes_buffer.seek(0)

    def call(self, datatype = 'str'):

        if datatype == 'str':
            return self.str_value
        elif datatype == 'bytes_stream':
            return self.bytes_buffer
        elif datatype == 'bytes':
            return self.bytes_buffer.getvalue()

    @staticmethod
    def pack(str_value, output_stream = None):
        str_len = len(str_value)
        temp_buffer = io.BytesIO()
        VarInt.pack(str_len, temp_buffer)
        temp_buffer.write(str_value)
        output = temp_buffer.getvalue()
        temp_buffer.close()
        if output_stream != None:
            output_stream.write(output)
        return str_len , output

    @staticmethod
    def unpack(bytes_stream, output_stream = None):
        temp_buffer = io.BytesIO()
        bytes_len = VarInt.unpack(bytes_stream)
        for i in range(bytes_len):
            temp_buffer.write(bytes_stream.read(1))
        temp_buffer.seek(-bytes_len,2)
        output = temp_buffer.read()
        temp_buffer.close()
        if output_stream != None:
            output_stream.write(output)
        return bytes_len , output


class Long:

    def __init__(self, value, datatype = 'int'):
        self.__bytes_length = 8
        self.__bytes_buffer = Bytes_Streamer()
        self.__int_value = None

        if datatype == 'int':
            self.__int_value = value
            self.pack(value, self.__bytes_buffer)

        elif datatype == 'bytes':
            self.__bytes_buffer.write(value)
            self.__int_value = self.unpack(self.__bytes_buffer)

        self.__bytes_buffer.seek(0)

    def call(self, datatype = 'int'):
        if datatype == 'int':
            return self.__int_value

        elif datatype == 'bytes':
            return self.__bytes_buffer.getvalue()

        elif datatype == 'bytes_stream':
            return self.__bytes_buffer

    @staticmethod
    def pack(int_value, output_stream = None):
        output = struct.pack('>q', int_value)
        if output_stream != None:
            output_stream.write(output)
        return output

    @staticmethod
    def unpack(bytes_stream, output_stream = None):
        output = struct.unpack('>q', bytes_stream.read(8))[0]
        if output_stream != None:
            output_stream.write(output)
        return output

class UUID:

    def __init__(self, value, datatype = 'bytes'):
        self.__bytes_length = 16
        self.__bytes_buffer = Bytes_Streamer()

        if datatype == 'bytes':
            self.__bytes_buffer.write(value)

        self.__bytes_buffer.seek(0)

    def call(self, datatype = 'bytes'):

        if datatype == 'bytes':
            return self.__bytes_buffer.getvalue()

    @staticmethod
    def pack(value, output_stream = None):
        output = uuid.UUID(value).bytes
        if output_stream != None:
            output_stream.write(output)
        return output

    @staticmethod
    def unpack(bytes_stream, output_stream = None):
        output = uuid.UUID(bytes=bytes_stream.read(16))
        if output_stream != None:
            output_stream.write(output)
        return output















        # f
