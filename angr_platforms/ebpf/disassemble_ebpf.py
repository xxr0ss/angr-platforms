from angr.block import DisassemblerInsn


class CustomDisassemblerInsn(DisassemblerInsn):
    """
    Represents a capstone instruction.
    """

    __slots__ = ("disasm", "insn_size")

    def __init__(self, disasm, insn_size):
        self.disasm = disasm
        self.insn_size = insn_size

    @property
    def size(self) -> int:
        return self.insn_size

    @property
    def address(self) -> int:
        return self.disasm[0]

    @property
    def mnemonic(self) -> str:
        return self.disasm[1]

    @property
    def op_str(self) -> str:
        return ', '.join(self.disasm[2])
