# TRACE
TRACE: Trusted Return-Path Authentication via Context and Lightweight Encryption TRACE is a lightweight control flow integrity (CFI) mechanism designed to defend against Return-Oriented Programming (ROP) attacks in embedded systems. TRACE dynamically binds return addresses to the unique function call path, making it difficult for attackers to hijack control flow by exploiting buffer overflows and other memory corruption vulnerabilities. This project uses the PRESENT cipher for lightweight encryption of return addresses and provides a defense mechanism that can be easily integrated with embedded applications.
# Project Structure
The project contains the following components:
libmodbus-2.9.3/: This folder contains the Modbus protocol stack used for testing the vulnerabilities in embedded systems.
TRACE_CFI.py: The main defense script that provides the return-path authentication mechanism.
baseline.py: The baseline script with no defense mechanisms, used to test the system without protection for comparison.
canshu.txt: A configuration file that includes the encryption key and counter seed used in the defense mechanism.
automated_run.py: The automation script used to run experiments, either with or without defense.
exp.py: The exploit script used to perform the attack.
README.md: This file, containing the project documentation and instructions.

# Requirements
Operating System: Ubuntu 20.04 (tested)
GDB: GNU Debugger, to run the target program and inject defense logic
Python 3: to run the automation and attack scripts
32-bit GCC toolchain: to build the target program for 32-bit architecture

# Environment Setup
On a fresh Ubuntu 20.04 system, run the following commands in order to set up the environment:

1. Clone the repository: git clone https://github.com/wwww-sudo/TRACE.git

sudo apt update

sudo apt upgrade

--- Install build tools---：

sudo apt install autoconf automake libtool

---Install 32-bit build toolchain and debug libraries---：

sudo apt install gcc-multilib g++-multilib libc6-dev-i386 make libc6-dbg

--- Install 32-bit libc debug symbols---：

sudo apt install libc6-dbg:i386

--- Enable i386 architecture---：

sudo dpkg --add-architecture i386

# Building the Target Program
In the project directory, navigate to libmodbus-2.9.3/ and build the server:(Some error messages in the compilation will not affect the experiment.)

cd libmodbus-2.9.3

./autogen.sh

./configure   --host=i686-linux-gnu   --disable-dependency-tracking   CFLAGS="-m32 -fno-stack-protector -no-pie -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -g -O0"   LDFLAGS="-m32 -no-pie -z execstack -z norelro"

make

make install

# Running the Experiment
1.Enable or disable defense
Open automated_run.py and set the ENABLE_TRACE variable:

Enable TRACE Defense : ENABLE_TRACE = True.

Disable Defense : ENABLE_TRACE = False

2.Run the experiment
From the project root directory : 

python3 automated_run.py

This will:
Start GDB with or without the TRACE defense based on ENABLE_TRACE
Launch the unit-test-server program
Wait for the attack payload (exp.py) to be executed
If the attack is successful (control flow is hijacked), the experiment executes the shellcode

3.Reproducing the Attack
To successfully reproduce the attack (and execute the shellcode), you need to set the correct return address in exp.py that points to the shellcode in memory.

In a separate terminal window, while the server is running under GDB (launched by automated_run.py), execute the attack script: 

python3 exp.py

-----------------------------------------Notes--------------------------------------------------------------

If you do not set the correct return address in exp.py to point to the shellcode, the attack can still cause a segmentation fault (segfault) on the server side when the return address is overwritten with an invalid value.

A segmentation fault also indicates that the attack successfully hijacked the control flow — the return address was tampered with — but the shellcode was not executed

# Important Notes
Ensure that your shellcode is properly placed in memory and accessible at the specified address. This may require debugging and analysis using GDB.

The exact method for obtaining the return address will depend on the target system, so memory inspection tools like GDB are essential.

# Debugging to Find the Return Address
If you want to reproduce the attack and set the correct return address in exp.py, you can use GDB to precisely locate the return address on the stack and compute the memory address of the injected shellcode.

1. Start GDB and set a breakpoint in modbus_reply

2.When the breakpoint hits, examine the stack frame and locate the saved return address for modbus_reply.

3.Next, identify where your shellcode is placed relative to the return address.
For example, if in exp.py you see that the shellcode is appended after a certain number of padding bytes after the return address, you can calculate its position in memory from the stack snapshot in GDB.

4. Once you determine the memory address where your shellcode resides, update the ret variable in exp.py to point to this address: ret = p32(0xYOUR_SHELLCODE_ADDRESS)

5. Run the attack again: python3 exp.py

# What Happens When Shellcode Executes
When the attack is successful (only when TRACE defense is disabled, i.e., in baseline mode), the return address is overwritten to point to your shellcode.
The shellcode provided in exp.py is a classic Linux x86 payload that executes /bin/sh, effectively giving you a shell on the server process.

On the server-side terminal you should see a segmentation fault or illegal instruction if the return address is wrong, which also indicates that control flow was hijacked but crashed.
If the return address is correct and points to the shellcode, you will spawn a shell or see evidence of arbitrary code execution.
# License
This project is licensed under the MIT License - see the LICENSE file for details.


