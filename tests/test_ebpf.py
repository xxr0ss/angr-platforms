import unittest
from pathlib import Path

import angr
import ailment
from angr_platforms.ebpf import ArchExtendedBPF, LifterEbpf
from angr.analyses.decompiler import BlockSimplifier as AILBlockSimplifier
from archinfo import Endness


TEST_PROGRAMS_BASE = Path(__file__).parent.parent / "test_programs" / "ebpf"


class TestEbpf(unittest.TestCase):
    @staticmethod
    def _test_prog_always_returns_42(filename: str) -> None:
        proj = angr.Project(TEST_PROGRAMS_BASE / filename)
        assert isinstance(proj.arch, ArchExtendedBPF)

        def on_reg_write(state: angr.SimState):
            inspect = state.inspect
            reg_write_offset = state.solver.eval(inspect.reg_write_offset)
            print('[*] reg_write_offset:', reg_write_offset)

        state = proj.factory.entry_state()
        state.inspect.b('reg_write', when=angr.BP_BEFORE, action=on_reg_write)
        simgr = proj.factory.simgr(state)
        simgr.run()

        assert len(simgr.deadended) == 1
        assert state.solver.eval_exact(simgr.deadended[0].regs.R0, 1) == [42]

    # pylint:disable=missing-class-docstring,no-self-use
    def test_trivial_return(self):
        self._test_prog_always_returns_42("return_42.o")

    def test_branched_return(self):
        self._test_prog_always_returns_42("return_if.o")

    def test_get_ns(self):
        self._test_prog_always_returns_42("get_ns.o")

    def test_ebpf_lift(self):
        proj = angr.Project(TEST_PROGRAMS_BASE / "return_if.o")
        state = proj.factory.entry_state()
        block = proj.factory.block(state.addr)
        lifter = LifterEbpf(proj.arch, block.addr)
        irsb = lifter.lift(block.bytes)
        print(lifter.disassemble())
        
        manager = ailment.Manager(arch=proj.arch)
        ailblock = ailment.IRSBConverter.convert(irsb, manager)
        assert isinstance(ailblock.statements[0], ailment.statement.Assignment)
        print(ailblock)

        cfg = proj.analyses.CFG()
        print(list(cfg.functions))
    
    def test_function(self):
        shellcode = bytes.fromhex(
            # add:
            "63 1a fc ff 00 00 00 00"
            "63 2a f8 ff 00 00 00 00"
            "61 a0 fc ff 00 00 00 00"
            "61 a1 f8 ff 00 00 00 00"
            "0f 10 00 00 00 00 00 00"
            "95 00 00 00 00 00 00 00"
            # sub:
            "63 1a fc ff 00 00 00 00"
            "63 2a f8 ff 00 00 00 00"
            "61 a0 fc ff 00 00 00 00"
            "61 a1 f8 ff 00 00 00 00"
            "1f 10 00 00 00 00 00 00"
            "95 00 00 00 00 00 00 00"
            # main:
            "b7 01 00 00 00 00 00 00"
            "63 1a fc ff 00 00 00 00"
            "18 01 00 00 00 00 00 00"
                # R_BPF_64_64 a
            "61 11 00 00 00 00 00 00"
            "15 01 06 00 00 00 00 00"
            "05 00 00 00 00 00 00 00"
            # LBB2_1:
            "b7 01 00 00 01 00 00 00"
            "b7 02 00 00 02 00 00 00"
            "85 10 00 00 ff ff ff ff"
                # R_BPF_64_32 add
            "63 0a f8 ff 00 00 00 00"
            "05 00 05 00 00 00 00 00"
            # LBB2_2:
            "b7 01 00 00 03 00 00 00"
            "b7 02 00 00 04 00 00 00"
            "85 10 00 00 ff ff ff ff"
                # R_BPF_64_32 sub
            "63 0a f8 ff 00 00 00 00"
            "05 00 00 00 00 00 00 00"
            # LBB2_3:
            "61 a0 f8 ff 00 00 00 00"
            "95 00 00 00 00 00 00 00"
        )
        proj = angr.load_shellcode(shellcode, ArchExtendedBPF(Endness.LE, Endness.LE))
        cfg:angr.analyses.CFG = proj.analyses.CFG()
        print(list(cfg.functions)[0])


if __name__ == "__main__":
    unittest.main()
