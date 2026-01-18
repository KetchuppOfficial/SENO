import angr
import archinfo
import claripy
import cle
import pathlib
import logging

from typing import Optional, Tuple


def pc_str(state: angr.SimState) -> None:
    solver = state.solver
    val = getattr(state.regs, "ip")
    if solver.symbolic(val):
        return "(symbolic)"
    else:
        return f"{hex(solver.eval(val))}"


def print_state(state: angr.SimState) -> None:
    solver = state.solver
    for reg in state.arch.register_names.values():
        val = getattr(state.regs, reg)
        if solver.symbolic(val):
            print(f"{reg}: (symbolic)")
        else:
            print(f"{reg}: {hex(solver.eval(val))}")
    print("\n")


class StackCheckFailException(Exception):
    def __init__(self, state: angr.sim_state.SimState):
        super().__init__()
        self.state: angr.sim_state.SimState = state


class StackCheckFail(angr.SimProcedure):
    SYMBOL: str = "__stack_chk_fail"

    def run(self):
        raise StackCheckFailException(self.state)


class BufferOverflowDetector:
    _MAX_ARGV_LEN: int = 64

    def __init__(
        self, input: pathlib.Path, argv_count: int, log: Optional[str]
    ):
        if argv_count < 0:
            raise RuntimeError("argv_count shall be a non-negative integer")

        if log:
            self._logger = logging.getLogger(__name__)
            self._logger.propagate = False
            self._logger.setLevel(logging.DEBUG)
            self._logger.addHandler(
                logging.FileHandler(filename=log, mode='w', encoding="utf-8")
            )
        else:
            self._logger = None

        print("Loading the binary...")
        self._proj: angr.Project = angr.Project(
            input, use_sim_procedures=True, auto_load_libs=False
        )

        if type(self._proj.arch) not in [
            archinfo.ArchAMD64,
            archinfo.ArchAArch64,
        ]:
            raise RuntimeError(
                f"Unsupported architecture: \'{type(self._proj.arch).__name__}\'"
            )

        if self._proj.loader.find_symbol(StackCheckFail.SYMBOL):
            self._proj.hook_symbol(
                StackCheckFail.SYMBOL, StackCheckFail(), replace=True
            )

        factory: angr.factory.AngrObjectFactory = self._proj.factory

        self._argv_symbols: list[claripy.BVS] = [
            claripy.BVS(f"argv[{i}]", BufferOverflowDetector._MAX_ARGV_LEN * 8)
            for i in range(argv_count)
        ]

        self._main_symbol: cle.Symbol = (
            self._proj.loader.main_object.get_symbol("main")
        )

        initial_state: angr.sim_state.SimState = factory.entry_state(
            args=["a.out"] + self._argv_symbols,
            options=[
                # Treat the initial value of registers as zero instead of
                # unconstrained symbolic
                angr.sim_options.INITIALIZE_ZERO_REGISTERS,
                # Return a new symbolic variable for any unspecified bytes in
                # memory
                angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            ],
        )

        for argv in self.argv_symbols:
            initial_state.add_constraints(
                argv.get_byte(BufferOverflowDetector._MAX_ARGV_LEN - 1) == 0
            )

        self._simgr: angr.sim_manager.SimulationManager = factory.simgr(
            initial_state,
            save_unconstrained=True,
        )

    @property
    def argv_count(self) -> int:
        return len(self._argv_symbols)

    @property
    def argv_symbols(self) -> list[claripy.BVS]:
        return self._argv_symbols

    def explore(self) -> Optional[Tuple[angr.SimState, str]]:
        if self._logger:
            self._logger.debug(
                "============================================================"
            )
        while self._simgr.active:
            if self._logger:
                self._logger.debug("------------------------------------------")
            for i, active in enumerate(self._simgr.active):
                if self._logger:
                    self._logger.debug(f"jump kind: {active.history.jumpkind}")
                    self._logger.debug(str(active.block().disassembly))
                    self._logger.debug(
                        "------------------------------------------"
                    )

                if active.history.jumpkind == 'Ijk_Exit':
                    self._simgr.active.pop(i)
                maybe_error: Optional[str] = (
                    BufferOverflowDetector._overflow_detected(active)
                )
                if maybe_error:
                    return (active, maybe_error)

            if self._logger:
                self._logger.debug(
                    "============================================================"
                )

            if self._simgr.unconstrained:
                return (self._simgr.one_unconstrained, "unconstrained")

            if self._simgr.deadended:
                return (self._simgr.one_deadended, "deadended")

            try:
                self._simgr.step()
            except StackCheckFailException as e:
                return (e.state, "canary corrupted")

        return None

    @staticmethod
    def _overflow_detected(state: angr.SimState) -> Optional[str]:
        # IP is alias for PC on AArch64 and for RIP on AMD64
        if state.solver.symbolic(state.regs.ip):
            return "PC is symbolic"

        # SP is alias for XSP on AArch64 and for RSP on AMD64
        if state.solver.symbolic(state.regs.sp):
            return "SP is symbolic"

        # BP is alias for X29 on AArch64 and for RBP on AMD64
        if state.solver.symbolic(state.regs.bp):
            return "FP is symbolic"

        # architecture-specific conditions
        match state.arch:
            case archinfo.ArchAArch64():
                if state.solver.symbolic(state.regs.lr):
                    return "AArch64 link register is symbolic"
            case archinfo.ArchAMD64():
                pass

        return None
