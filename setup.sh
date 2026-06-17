#!/usr/bin/env bash
set -e

echo "=============================="
echo "  Skoll - Setup"
echo "=============================="

# Cargar API key desde .env si existe
if [ -f ".env" ]; then
  set -a
  source .env
  set +a
fi

# Si no hay key en entorno, mostrar aviso (se puede poner desde la web)
if [ -z "$GEMINI_API_KEY" ]; then
  echo "⚠️  No se encontró GEMINI_API_KEY"
  echo "   Puedes configurarla desde la interfaz web al iniciar."
  echo ""
fi

echo "🚀 Instalando dependencias..."
python3 -m venv venv 2>/dev/null || true
if [ -d "venv" ]; then
  source venv/bin/activate
elif [ -d ".venv" ]; then
  source .venv/bin/activate
fi
pip install -e . -q 2>/dev/null

echo "🌐 Servidor en http://localhost:8000"
echo ""
uvicorn auditor_ai.web_server:app --host 0.0.0.0 --port 8000
