#!/usr/bin/env bash
set -e

echo "=============================="
echo "  Skoll - Launcher"
echo "=============================="

# Check if running inside the project directory
if [ ! -f "pyproject.toml" ]; then
  echo "❌ Ejecuta este script desde la raíz del proyecto."
  exit 1
fi

# Check for API key
if [ -z "$GEMINI_API_KEY" ]; then
  # If .env exists, source it
  if [ -f ".env" ]; then
    source .env
  fi
  if [ -z "$GEMINI_API_KEY" ]; then
    echo "⚠️  No se encontró GEMINI_API_KEY."
    echo "   Puedes configurarla después desde la interfaz web."
    echo ""
  fi
fi

# Detect if Docker is available
if command -v docker &>/dev/null; then
  echo "🚀 Usando Docker..."
  docker compose up --build
else
  echo "🚀 Usando Python local..."
  # Check if venv exists
  if [ -d ".venv" ]; then
    source .venv/bin/activate
  fi
  pip install -e . -q 2>/dev/null
  echo "   Abre http://localhost:8000 en tu navegador"
  echo "   O desde otro dispositivo: http://$(hostname -I 2>/dev/null | awk '{print $1}'):8000"
  echo ""
  uvicorn auditor_ai.web_server:app --host 0.0.0.0 --port 8000
fi
