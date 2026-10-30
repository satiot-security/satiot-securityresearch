import json
from pathlib import Path
CONFIG=json.loads((Path(__file__).resolve().parents[1]/'config/experiments.json').read_text())
