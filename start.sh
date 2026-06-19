#!/usr/bin/env bash
set -e

echo "=============================="
echo "  Skoll - Launcher"
echo "=============================="

cd "$(dirname "$0")"

if [ ! -f "pyproject.toml" ]; then
  echo "❌ Ejecuta este script desde la raíz del proyecto."
  exit 1
fi

if [ -z "$GEMINI_API_KEY" ] && [ -f ".env" ]; then
  set -a
  source .env
  set +a
fi

PORT="${1:-8080}"

echo "🚀 Lanzando Skoll en http://localhost:$PORT"
echo "   Proveedor: ${DEFAULT_PROVIDER:-gemini}"
echo ""
python3 -m skoll.main web --port "$PORT"
