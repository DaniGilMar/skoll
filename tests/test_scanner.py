import os
import tempfile

from skoll.scanner import (
    ejecutar_bandit,
    ejecutar_escaneo_sast,
    ejecutar_semgrep,
    is_tool_installed,
)


def test_is_tool_installed_true():
    assert is_tool_installed("python3") or is_tool_installed("python")


def test_is_tool_installed_false():
    assert not is_tool_installed("herramienta_inexistente_xyz_123")


def test_ejecutar_bandit_sin_instalar():
    """Si bandit no está instalado, debe devolver mensaje de error."""
    import shutil
    if shutil.which("bandit") is None:
        resultado = ejecutar_bandit("/tmp")
        assert "Bandit no está instalado" in resultado


def test_ejecutar_semgrep_sin_instalar():
    """Si semgrep no está instalado, debe devolver mensaje de error."""
    import shutil
    if shutil.which("semgrep") is None:
        resultado = ejecutar_semgrep("/tmp")
        assert "Semgrep no está instalado" in resultado


def test_ejecutar_escaneo_sast_all():
    """ejecutar_escaneo_sast debe retornar dict con bandit y semgrep."""
    resultado = ejecutar_escaneo_sast("/tmp", tool="all")
    assert isinstance(resultado, dict)
    assert "bandit" in resultado
    assert "semgrep" in resultado


def test_ejecutar_escaneo_sast_solo_bandit():
    resultado = ejecutar_escaneo_sast("/tmp", tool="bandit")
    assert isinstance(resultado, dict)
    assert "bandit" in resultado
    assert "semgrep" not in resultado


def test_ejecutar_escaneo_sast_solo_semgrep():
    resultado = ejecutar_escaneo_sast("/tmp", tool="semgrep")
    assert isinstance(resultado, dict)
    assert "semgrep" in resultado
    assert "bandit" not in resultado


def test_bandit_archivo_temporal():
    import shutil
    if shutil.which("bandit") is None:
        return
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write('import os\nos.system("ls")\n')
        tmpname = f.name
    try:
        resultado = ejecutar_bandit(tmpname)
        assert isinstance(resultado, str)
        assert len(resultado) > 0
    finally:
        os.unlink(tmpname)
