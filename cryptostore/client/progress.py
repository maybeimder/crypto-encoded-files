import sys
from typing import TextIO


class TerminalProgressBar:
    def __init__(self, label: str, stream: TextIO = sys.stderr, width: int = 30):
        self._label = label
        self._stream = stream
        self._width = width

    def __call__(self, completed_steps: int, total_steps: int) -> None:
        fraction = completed_steps / total_steps if total_steps else 1.0
        # Se redondea hacia abajo: no muestra 100% hasta terminar de verdad
        percentage = int(fraction * 100)
        filled_width = int(self._width * fraction)
        bar = "#" * filled_width + "-" * (self._width - filled_width)
        # \r vuelve al inicio de la línea: la barra se redibuja en el mismo lugar
        self._stream.write(f"\r{self._label} [{bar}] {percentage:3d}% ({completed_steps}/{total_steps})")
        if completed_steps >= total_steps:
            self._stream.write("\n")
        self._stream.flush()
