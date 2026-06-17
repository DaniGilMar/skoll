# Skoll 🛡️🤖

**Skoll** es un asistente CLI de ciberseguridad e ingeniería de software DevSecOps para la terminal, inspirado en el framework open-source **RAPTOR** (Recursive Autonomous Penetration Testing and Observation Robot). 

Funciona de manera completamente gratuita utilizando la API de Google Gemini (Gemini 2.5 Flash / Pro).

## 🚀 Funcionalidades Core

1. **Auditoría de Código y Configuración**: Análisis estático inteligente de archivos y directorios aplicando las **Etapas A-D de RAPTOR**:
   - **Etapa A**: Ruido vs Realidad (Descarte de falsos positivos).
   - **Etapa B**: Requisitos del Atacante.
   - **Etapa C**: Alcanzabilidad del Flujo de Ejecución (Reachability).
   - **Etapa D**: Veredicto de Severidad y Propuesta de Mitigación Detallada.
2. **Chat de Seguridad Interactivo**: Chat interactivo persistente en la terminal precargado con un prompt del sistema DevSecOps especializado.
3. **Escaneo Asistido por SAST**: Integración nativa con linters locales de seguridad como Bandit o Semgrep. Al finalizar, la IA interpreta la salida y la convierte en guías accionables.
4. **Verificación Dinámica Interactiva**: Tras generar el reporte de vulnerabilidad, el sistema preguntará interactivamente al usuario si desea lanzar scripts de prueba, fuzzers o contenedores de validación modular (`verifier.py`).

## 🛠️ Requisitos e Instalación

### Requisitos Previos

- Python >= 3.9
- Una API Key de Google Gemini. Consíguela de forma gratuita en [Google AI Studio](https://aistudio.google.com/).

### Instalación

1. Clona el repositorio e ingresa a él.
2. Exporta tu API Key como variable de entorno:
   ```bash
   export GEMINI_API_KEY="tu_api_key_aqui"
   ```
3. Instala la herramienta localmente en modo ejecutable:
   ```bash
   pip install -e .
   ```

Una vez instalada, tendrás disponible el comando global `skoll` en tu terminal.

## 📖 Instrucciones de Uso

### 1. Iniciar el Chat de Seguridad
Inicia un chat interactivo con el prompt de sistema basado en auditoría RAPTOR:
```bash
skoll chat
```

### 2. Analizar un Archivo o Carpeta Local
Analiza un script o código fuente completo en busca de vulnerabilidades y obtén un reporte exhaustivo:
```bash
skoll analyze ./ruta/del/script.py
```

### 3. Escaneo con Herramientas Locales (Bandit o Semgrep)
Ejecuta herramientas SAST locales y deja que la IA traduzca el output en soluciones:
```bash
skoll scan ./ruta/del/proyecto --tool bandit
```
*(Nota: Para este comando, debes tener instaladas herramientas como `bandit` o `semgrep` en tu sistema).*
