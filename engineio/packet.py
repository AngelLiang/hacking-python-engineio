import base64
import json as _json

import six

# packet_type 字面量
(OPEN, CLOSE, PING, PONG, MESSAGE, UPGRADE, NOOP) = (0, 1, 2, 3, 4, 5, 6)
# packet名称队列， packet_type正好对应下标
packet_names = ['OPEN', 'CLOSE', 'PING', 'PONG', 'MESSAGE', 'UPGRADE', 'NOOP']

binary_types = (six.binary_type, bytearray)


class Packet(object):
    """Engine.IO packet."""

    json = _json

    def __init__(self, packet_type=NOOP, data=None, binary=None,
                 encoded_packet=None):
        self.packet_type = packet_type
        self.data = data
        if binary is not None:
            self.binary = binary
        elif isinstance(data, six.text_type):
            self.binary = False
        elif isinstance(data, binary_types):
            self.binary = True
        else:
            self.binary = False
        if encoded_packet:
            self.decode(encoded_packet)

    def encode(self, b64=False, always_bytes=True):
        """Encode the packet for transmission."""
        if self.binary and not b64:
            encoded_packet = six.int2byte(self.packet_type)
        else:
            encoded_packet = six.text_type(self.packet_type)
            if self.binary and b64:
                encoded_packet = 'b' + encoded_packet

        if self.binary:
            # 二进制
            if b64:  # 转为base64
                encoded_packet += base64.b64encode(self.data).decode('utf-8')
            else:
                encoded_packet += self.data
        elif isinstance(self.data, six.string_types):
            # 字符串
            encoded_packet += self.data
        elif isinstance(self.data, dict) or isinstance(self.data, list):
            # 字典或列表，用json序列化
            encoded_packet += self.json.dumps(self.data,
                                              separators=(',', ':'))
        elif self.data is not None:
            # 其他情况，则直接转换为str
            encoded_packet += str(self.data)
        if always_bytes and not isinstance(encoded_packet, binary_types):
            encoded_packet = encoded_packet.encode('utf-8')
        return encoded_packet

    def decode(self, encoded_packet):
        """Decode a transmitted package."""
        """
        :param encoded_packet: 已编码的packet

        """
        b64 = False
        # 1、判断 encoded_packet 类型
        if not isinstance(encoded_packet, binary_types):
            # encoded_packet 不是二进制类型直接 encode()
            encoded_packet = encoded_packet.encode('utf-8')
        elif not isinstance(encoded_packet, bytes):
            # encoded_packet 不是 bytes 类型则转为 bytes 类型
            encoded_packet = bytes(encoded_packet)
        # 2、读取 encoded_packet 第一个字节并判断数据包的类型
        self.packet_type = six.byte2int(encoded_packet[0:1])
        if self.packet_type == 98:  # 'b' --> binary base64 encoded packet
            self.binary = True
            encoded_packet = encoded_packet[1:]
            self.packet_type = six.byte2int(encoded_packet[0:1])
            self.packet_type -= 48
            b64 = True
        elif self.packet_type >= 48:
            self.packet_type -= 48
            self.binary = False
        else:
            self.binary = True
        # 3、数据解码并存入 self.data
        self.data = None
        if len(encoded_packet) > 1:
            if self.binary:
                if b64:
                    self.data = base64.b64decode(encoded_packet[1:])
                else:
                    self.data = encoded_packet[1:]
            else:
                try:
                    self.data = self.json.loads(
                        encoded_packet[1:].decode('utf-8'))
                    if isinstance(self.data, int):
                        # do not allow integer payloads, see
                        # github.com/miguelgrinberg/python-engineio/issues/75
                        # for background on this decision
                        raise ValueError
                except ValueError:
                    self.data = encoded_packet[1:].decode('utf-8')
