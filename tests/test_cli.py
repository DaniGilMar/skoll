import os

from typer.testing import CliRunner

from skoll.main import app

runner = CliRunner()

def test_help_command():
    """Verifica que el comando de ayuda se despliegue correctamente."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Skoll" in result.stdout
    assert "chat" in result.stdout
    assert "analyze" in result.stdout
    assert "scan" in result.stdout

def test_missing_api_key_error():
    """Verifica que si no está GEMINI_API_KEY, el sistema eleva error y sale de forma controlada."""
    # Guardamos la variable anterior si existe
    old_key = os.environ.get("GEMINI_API_KEY")
    if "GEMINI_API_KEY" in os.environ:
        del os.environ["GEMINI_API_KEY"]

    try:
        # Intentamos ejecutar un comando que requiera la clave con un archivo existente
        result = runner.invoke(app, ["analyze", "pyproject.toml"])
        # Debe salir con error controlado (exit code 1)
        assert result.exit_code == 1
        assert "API Key" in result.stdout or "No se ha proporcionado una API Key" in result.stdout
    finally:
        # Restauramos
        if old_key is not None:
            os.environ["GEMINI_API_KEY"] = old_key

def test_invalid_path_error():
    """Verifica que si la ruta a analizar no existe, lanza error controlado."""
    # Aseguramos tener una clave configurada ficticia para pasar el primer control
    old_key = os.environ.get("GEMINI_API_KEY")
    os.environ["GEMINI_API_KEY"] = "fake_key_for_testing"

    try:
        result = runner.invoke(app, ["analyze", "ruta_inexistente_de_prueba.py"])
        assert result.exit_code == 1
        assert "no existe en el sistema" in result.stdout
    finally:
        if old_key is not None:
            os.environ["GEMINI_API_KEY"] = old_key
        else:
            del os.environ["GEMINI_API_KEY"]
