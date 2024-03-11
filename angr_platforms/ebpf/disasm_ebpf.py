from angr.block import DisassemblerBlock, DisassemblerInsn, register_disassembler
from .arch_ebpf import ArchExtendedBPF
from .instrs_ebpf import EBPFInstruction


class EbpfBlock(DisassemblerBlock):
    __slots__ = ()


class EbpfInsn(DisassemblerInsn):
    """
    Represents a custom eBPF instruction.
    """

    __slots__ = ("insn", "disasm")

    def __init__(self, insn: EBPFInstruction):
        self.insn = insn
        self.disasm = self.insn.disassemble()

    @property
    def size(self) -> int:
        return self.insn.bytewidth

    @property
    def address(self) -> int:
        return self.disasm[0]

    @property
    def mnemonic(self) -> str:
        return self.disasm[1]

    @property
    def op_str(self) -> str:
        return ", ".join(self.disasm[2])


register_disassembler(ArchExtendedBPF, EbpfBlock, EbpfInsn)
