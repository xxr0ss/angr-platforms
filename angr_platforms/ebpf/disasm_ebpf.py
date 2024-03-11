from angr.block import DisassemblerBlock, DisassemblerInsn
from angr.analyses import AnalysesHub, Disassembly
from angr.analyses.disassembly import FuncComment, BlockStart, BlockNode, Hook
from angr.codenode import BlockNode
from .instrs_ebpf import EBPFInstruction
import pyvex
from pyvex.lifting.util import GymratLifter


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


class EbpfDisassembly(Disassembly):
    def parse_block(self, block: BlockNode) -> None:
        """
        Parse instructions for a given block node
        """
        func = self.func_lookup(block)
        if func and func.addr == block.addr:
            self.raw_result.append(FuncComment(block.function))
            self.raw_result.append(func)
        bs = BlockStart(block, func, self.project)
        self.raw_result.append(bs)

        if block.is_hook:
            hook = Hook(block)
            self.raw_result.append(hook)
            self.raw_result_map["hooks"][block.addr] = hook
        else:
            # use our disassembly techs
            self.block_to_insn_addrs[block.addr] = []
            bytestr = self.project.factory.block(block.addr, size=block.size).bytes
            gymrat_lifter: GymratLifter = pyvex.lifters[self.project.arch.name][0](self.project.arch, block.addr)
            gymrat_lifter.lift(bytestr)
            for insn in gymrat_lifter.decoded_insns:
                disasm_insn = EbpfInsn(insn)
                self._add_instruction_to_results(block, disasm_insn, bs)

        if self._include_ir:
            b = self.project.factory.block(block.addr, size=block.size)
            self._add_block_ir_to_results(block, b.vex)


AnalysesHub.register_default("Disassembly", EbpfDisassembly)
