import argparse
import json
import os
import sys

from cryptostore.benchmarks import experiments
from cryptostore.benchmarks.report import build_markdown

MEBIBYTE = 1 << 20
KIBIBYTE = 1 << 10


def parse_arguments(argument_list: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="cryptostore-bench",
                                     description="Mide cifrado, sobrecosto por bloque y crecimiento de envolventes.")
    parser.add_argument("--output-dir", default="docs", help="dónde escribir mediciones.md y mediciones.json")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--quick", action="store_true", help="tamaños pequeños, para probar que todo corre")
    return parser.parse_args(argument_list)


def main(argument_list: list[str] | None = None) -> int:
    arguments = parse_arguments(argument_list)
    # En modo rápido todo cabe en unos segundos; el modo normal llega al límite de 100 MiB del enunciado
    largest_file = 2 * MEBIBYTE if arguments.quick else 100 * MEBIBYTE
    throughput_sizes = [0, KIBIBYTE, MEBIBYTE, largest_file] if arguments.quick else \
        [0, KIBIBYTE, MEBIBYTE, 10 * MEBIBYTE, 50 * MEBIBYTE, largest_file]
    end_to_end_sizes = [KIBIBYTE, largest_file] if arguments.quick else \
        [KIBIBYTE, MEBIBYTE, 10 * MEBIBYTE, largest_file]

    steps = [
        ("crypto_throughput", lambda: experiments.crypto_throughput(throughput_sizes, arguments.repetitions)),
        ("block_size_overhead", lambda: experiments.block_size_overhead(
            largest_file, [64 * KIBIBYTE, 256 * KIBIBYTE, MEBIBYTE, 4 * MEBIBYTE], arguments.repetitions)),
        ("grant_growth", lambda: experiments.grant_growth([1, 2, 3, 4, 5], [KIBIBYTE, largest_file],
                                                          arguments.repetitions)),
        ("end_to_end", lambda: experiments.end_to_end(end_to_end_sizes, arguments.repetitions)),
    ]
    results = {"block_size_overhead_file_size": largest_file}
    for step_name, run_step in steps:
        print(f"midiendo {step_name}…", file=sys.stderr)
        results[step_name] = run_step()

    os.makedirs(arguments.output_dir, exist_ok=True)
    with open(os.path.join(arguments.output_dir, "mediciones.json"), "w") as json_file:
        json.dump(results, json_file, indent=2)
    with open(os.path.join(arguments.output_dir, "mediciones.md"), "w") as markdown_file:
        markdown_file.write(build_markdown(results, arguments.repetitions))
    print(f"Resultados en {os.path.join(arguments.output_dir, 'mediciones.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
