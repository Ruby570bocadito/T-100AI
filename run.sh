#!/bin/bash
# T-100AI - AI-Powered Offensive Security Terminal
# Lanzador para Linux/macOS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activar entorno virtual si existe
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Configurar locale para UTF-8 (recomendado para caracteres especiales)
export LC_ALL=en_US.UTF-8 2>/dev/null || true
export LANG=en_US.UTF-8 2>/dev/null || true

# Asegurar que el paquete (src/) es importable sin necesidad de pip install -e .
export PYTHONPATH="$SCRIPT_DIR/src:${PYTHONPATH:-}"

# Ejecutar T-100AI
python -m t100ai.cli.main "$@"
