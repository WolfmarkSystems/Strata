from pathlib import Path
import runpy

SCRIPT = Path(__file__).resolve().parent / 'bin' / 'kb' / 'dfir_kb_bridge.py'
runpy.run_path(str(SCRIPT), run_name='__main__')
