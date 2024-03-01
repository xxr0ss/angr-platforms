import unittest
from pathlib import Path

import angr
from angr_platforms.ebpf import ArchExtendedBPF, LifterEbpf


TEST_PROGRAMS_BASE = Path(__file__).parent.parent / "test_programs" / "ebpf"


class TestEbpf(unittest.TestCase):
    @staticmethod
    def _test_prog_always_returns_42(filename: str) -> None:
        proj = angr.Project(TEST_PROGRAMS_BASE / filename)
        assert isinstance(proj.arch, ArchExtendedBPF)

        state = proj.factory.entry_state()
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
        proj = angr.Project(TEST_PROGRAMS_BASE / "return_42.o")
        # print(proj.arch.name)
        # state = proj.factory.entry_state()
        # block = proj.factory.block(state.addr)
        # lifter = LifterEbpf(proj.arch, block.addr)
        # lifter.lift(block.bytes)
        # print()
        # lifter.pp_disas()
        # assert len(lifter.disassemble()) == 2

        ebpf_prog = bytes.fromhex(
            # max:
            'bf 10 00 00 00 00 00 00'	# r0 = r1
            '6d 20 01 00 00 00 00 00'	# if r0 s> r2 goto +0x1 <LBB0_2>
            'bf 20 00 00 00 00 00 00'	# r0 = r2
            # LBB0_2:
            '95 00 00 00 00 00 00 00'   # exit

            # max:
            '6d 21 01 00 00 00 00 00'	# if r1 s> r2 goto +0x1 <LBB0_2>
            'bf 21 00 00 00 00 00 00'	# r1 = r2
            # LBB0_2:
            '8d 00 00 00 03 00 00 00'	# callx r0
            '95 00 00 00 00 00 00 00'	# exit
        )
        proj = angr.load_shellcode(
            ebpf_prog,
            ArchExtendedBPF('Iend_LE', 'Iend_BE'),
        )
        state = proj.factory.blank_state(addr=0)
        block = proj.factory.block(state.addr, size=len(ebpf_prog))
        lifter = LifterEbpf(proj.arch, 0)
        lifter.lift(block.bytes)
        print()
        lifter.pp_disas()

if __name__ == "__main__":
    unittest.main()
