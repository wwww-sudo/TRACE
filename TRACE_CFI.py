import os
import random
import gdb

class PRESENT:
    """
    Lightweight block cipher implementation based on the PRESENT algorithm.
    Used to generate authentication tags for return address verification.
    """

    def __init__(self, key=None, start_value=0):
        self.key = key
        self.start_value = start_value
        # S-box used for substitution layer
        self.s_box = [
            0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
            0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
        ]

    def add_round_key(self, state, key):
        """
        XOR round key into state (top 64 bits of 80-bit key).
        """
        key_high64 = (key >> 16) & 0xFFFFFFFFFFFFFFFF
        return state ^ key_high64

    def sub_bytes(self, state):
        """
        Substitution layer using the S-box.
        """
        result = 0
        for i in range(16):
            block = (state >> (i * 4)) & 0xF
            result |= self.s_box[block] << (i * 4)
        return result

    def p_layer(self, state):
        """
        Permutation layer: bitwise diffusion across the state.
        """
        result = 0
        for i in range(63):
            bit = (state >> i) & 1
            new_pos = (i * 16) % 63
            result |= bit << new_pos
        result |= (state & (1 << 63))  # retain MSB
        return result

    def update_key(self, key, rc):
        """
        Key schedule: rotate + substitute + inject round constant.
        """
        key = ((key << 61) | (key >> 19)) & 0xFFFFFFFFFFFFFFFFFFFF
        nibble = (key >> 76) & 0xF
        s_val = self.s_box[nibble]
        key = (key & ~(0xF << 76)) | (s_val << 76)
        for i in range(5):
            bit = (rc >> (4 - i)) & 1
            key ^= (bit << (19 - i))
        return key

    def encrypt(self, state, key):
        """
        Full 31-round PRESENT encryption routine.
        """
        for rc in range(1, 32):
            state = self.add_round_key(state, key)
            state = self.sub_bytes(state)
            state = self.p_layer(state)
            key = self.update_key(key, rc)
        state = self.add_round_key(state, key)
        return state

    def present(self, input_value):
        """
        Encrypt input_value (e.g., context + return address) using PRESENT cipher.
        """
        if self.key is None:
            print("[ERROR] Key is not initialized.")
            return None
        plain = (self.start_value + input_value) & 0xFFFFFFFFFFFFFFFF
        cipher = self.encrypt(plain, self.key)
        return cipher


class TraceCFI(gdb.Command):
    """
    GDB Python command to implement TRACE: path-sensitive return address verification.
    """

    def __init__(self):
        super(TraceCFI, self).__init__("tracecfi", gdb.COMMAND_USER)
        self.auth_stack = []           # Stack to store MACs at call time
        self.counter_array = []        # Path state vector (one counter per depth level)
        self.depth = 0                 # Current call depth (stack frame index)
        self.key = None                # Encryption key (loaded from file)
        self.start_value = 0           # Counter seed (for initial plaintext entropy)
        self.load_params()

    def load_params(self):
        """
        Load key and counter seed from external configuration file.
        """
        try:
            with open("parameter.txt", 'r') as f:
                for line in f:
                    if line.startswith("Counter:"):
                        self.start_value = int(line.split(":")[1].strip())
                    elif line.startswith("Key:"):
                        self.key = int(line.split(":")[1].strip())
        except Exception as e:
            print(f"[ERROR] Failed to load params: {e}")

    def construct_ctx(self, return_addr):
        """
        Construct a 64-bit context value based on path state vector + return address.
        """
        ctx = 0
        for i in range(self.depth + 1):
            ctx = (ctx << 8) | self.counter_array[i]
        ctx = (ctx << 32) | (return_addr & 0xFFFFFFFF)
        return ctx & 0xFFFFFFFFFFFFFFFF

    def present_encrypt(self, ctx):
        """
        Perform PRESENT encryption of the context.
        """
        present = PRESENT(self.key, self.start_value)
        return present.encrypt(ctx, self.key)

    def handle_call(self, pc, insn):
        """
        Handle a call instruction: update path state, compute MAC, and push to stack.
        """
        if self.depth >= len(self.counter_array):
            self.counter_array.append(random.getrandbits(8))  # Random seed if new level
        else:
            self.counter_array[self.depth] = (self.counter_array[self.depth] + 1) % 256

        return_addr = self.get_return_address(pc, insn)
        ctx = self.construct_ctx(return_addr)
        mac = self.present_encrypt(ctx)

        self.auth_stack.append(mac)
        self.depth += 1
        print(f"[CALL] PC: {pc:#x} → RA: {return_addr:#x} | MAC: {mac:016x} | Depth: {self.depth}")

    def handle_ret(self, pc, current_pc):
        """
        Handle a ret instruction: pop expected MAC and verify against current context.
        """
        if not self.auth_stack:
            print("[ERROR] Return stack empty.")
            gdb.execute("quit 1")
            return

        self.depth -= 1
        ctx = self.construct_ctx(current_pc)
        mac = self.present_encrypt(ctx)
        expected = self.auth_stack.pop()

        print(f"[RET] PC: {pc:#x} → Expected: {expected:016x}, Actual: {mac:016x}")
        if mac != expected:
            print("[ERROR] MAC mismatch! Potential control-flow attack detected.")
            gdb.execute("quit 1")
        else:
            print(f"[OK] Return verified. Depth: {self.depth}")

    def get_return_address(self, pc, insn):
        """
        Estimate the return address from current call instruction.
        """
        length = insn.get("length", 0)
        if length == 0:
            try:
                next_insn = gdb.selected_frame().architecture().disassemble(pc + 1, count=1)[0]
                length = next_insn["addr"] - pc
            except Exception:
                print(f"[WARN] Instruction length unknown at {pc:#x}")
                length = 0
        return pc + length

    def is_dl_runtime_resolve(self, pc):
        """
        Check if current PC belongs to _dl_runtime_resolve, which should be skipped.
        """
        try:
            sym = gdb.execute(f"info symbol {pc:#x}", to_string=True).strip()
            return "_dl_runtime_resolve" in sym
        except gdb.error:
            return False

    def invoke(self, arg, from_tty):
        """
        GDB entrypoint for the custom tracecfi command.
        Initializes and steps through execution, handling call/ret logic.
        """
        try:
            gdb.execute("delete")
            gdb.execute("break _start")
            gdb.execute("run")
        except gdb.error as e:
            print(f"[ERROR] Program launch failed: {e}")
            return

        while True:
            try:
                frame = gdb.selected_frame()
                pc = frame.pc()
                arch = frame.architecture()
                insn = arch.disassemble(pc, count=1)[0]
                asm = insn["asm"].split()[0]

                if asm.startswith("ret") and self.is_dl_runtime_resolve(pc):
                    print(f"[SKIP] ret in _dl_runtime_resolve @ {pc:#x}")
                    gdb.execute("si", to_string=True)
                    continue

                if asm.startswith("call"):
                    self.handle_call(pc, insn)

                gdb.execute("si", to_string=True)

                new_pc = gdb.selected_frame().pc()
                if asm.startswith("ret"):
                    self.handle_ret(pc, new_pc)

            except gdb.error:
                print("[INFO] Program terminated.")
                break
            except Exception as e:
                print(f"[EXCEPTION] {e}")
                gdb.execute("quit 1")

# Register the custom GDB command
TraceCFI()
