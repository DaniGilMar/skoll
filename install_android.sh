#!/usr/bin/env bash
set -e

# ============================================
#  Skoll - Instalación automática Android
# ============================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════╗"
echo "  ║      Skoll for Android      ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${NC}"

# --- 1. Dependencias del sistema ---
echo -e "${YELLOW}[1/4] Instalando dependencias del sistema...${NC}"
pkg update -y -q
pkg upgrade -y -q
pkg install -y git python python-pip openssl

# --- 2. Clonar repo ---
echo -e "${YELLOW}[2/4] Descargando Skoll...${NC}"
if [ -d "$HOME/skoll" ]; then
  echo "Ya existe ~/skoll, actualizando..."
  cd "$HOME/skoll" && git pull
else
  git clone https://github.com/Celot1979/skoll.git "$HOME/skoll"
  cd "$HOME/skoll"
fi

# --- 3. Dependencias Python ---
echo -e "${YELLOW}[3/4] Instalando paquetes Python...${NC}"
pip install -q -e .
pip install -q requests beautifulsoup4

# --- 4. Crear lanzador ---
echo -e "${YELLOW}[4/4] Creando lanzador...${NC}"
LAUNCHER="$HOME/.shortcuts/skoll"
mkdir -p "$HOME/.shortcuts"

cat > "$LAUNCHER" << 'EOF'
#!/usr/bin/env bash
cd $HOME/skoll

# Cargar .env si existe
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

echo ""
echo "  ▶ Skoll arrancando..."
echo ""
echo "  📱 Local:   http://localhost:8000"
echo ""
echo "  🌐 Red:     http://$(ifconfig 2>/dev/null | grep -Eo '192\.168\.[0-9]+\.[0-9]+' | head -1):8000"
echo ""
echo "  ⚙️  Pon tu API key en: http://localhost:8000"
echo ""
exec python -m uvicorn auditor_ai.web_server:app --host 0.0.0.0 --port 8000
EOF

chmod +x "$LAUNCHER"

# --- Fin ---
echo -e "${GREEN}"
echo "  ✅ Instalación completada"
echo ""
echo "  Para arrancar el servidor:"
echo ""
echo "    1. Abre Termux y escribe:  skoll"
echo ""
echo "    2. Abre Chrome y ve a:     http://localhost:8000"
echo ""
echo "    3. Pon tu API key en la web y listo"
echo ""
echo "  📌 TIP: Instala Termux:Widget desde F-Droid"
echo "     y pon un acceso directo en tu escritorio"
echo "     que ejecute: source skoll"
echo -e "${NC}"

# Crear alias en .bashrc si no existe
if ! grep -q "alias skoll=" "$HOME/.bashrc" 2>/dev/null; then
  echo "alias skoll='$HOME/.shortcuts/skoll'" >> "$HOME/.bashrc"
  echo -e "${GREEN}   alias 'skoll' creado. Reinicia Termux o ejecuta: source ~/.bashrc${NC}"
fi
