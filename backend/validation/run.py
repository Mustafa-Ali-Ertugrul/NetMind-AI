"""CLI entry point for ``python -m validation.run``.

Ensures the project root (``NetMind-AI/``) is on ``sys.path`` so that
``from backend.xxx`` imports resolve regardless of the working directory.
"""

import sys
from pathlib import Path

# Add project root to sys.path so that 'from backend.xxx' imports work.
# The project root is backend/../ = NetMind-AI/
_project_root = Path(__file__).resolve().parent.parent.parent  # backend/validation/../../
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from .runner import main

main()
