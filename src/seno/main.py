import argparse as cli
import pathlib

import seno.buffer_overflow as bo


def check_file(path_str: str) -> pathlib.Path:
    path: pathlib.Path = pathlib.Path(path_str).resolve()
    if not path.is_file():
        raise RuntimeError(
            f"\'{path}\' does not exist or is not a regular file"
        )
    return path


def main() -> None:
    parser: cli.ArgumentParser = cli.ArgumentParser(
        description="SENO: Symbolic Execution for Neutralizing Overflow.\n"
        "A tool finding various cases of overflow in x86-64 and AArch64 ELF binaries"
    )

    parser.add_argument(
        "input",
        help="input ELF file for x86-64 or AArch64 platform",
        type=check_file,
    )

    parser.add_argument(
        "--argv-count",
        help="the number of arguments that main function of the binary expects",
        type=int,
    )

    parser.add_argument("--log", help="name of the log file", type=str)

    args: cli.Namespace = parser.parse_args()

    detector = bo.BufferOverflowDetector(args.input, args.argv_count, args.log)

    print("Starting symbolic execution...")
    maybe_state = detector.explore()
    if maybe_state is None:
        print("No exploitable overflow found")
        return

    state, kind = maybe_state
    print(f"Potential buffer overflow detected: found \'{kind}\' state")


if __name__ == "__main__":
    main()
