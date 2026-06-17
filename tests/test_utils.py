import os
import tempfile

from skoll.utils import (
    EXCLUDE_DIRS,
    INTERESTING_EXTENSIONS,
    es_directorio_excluido,
    es_extension_valida,
    escanear_directorio,
    leer_archivo,
)


def test_leer_archivo_existente():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write("print('hello')")
        tmpname = f.name
    try:
        contenido = leer_archivo(tmpname)
        assert "print('hello')" in contenido
    finally:
        os.unlink(tmpname)


def test_leer_archivo_inexistente():
    contenido = leer_archivo("/ruta/inexistente/archivo.py")
    assert "No se pudo leer" in contenido


def test_es_extension_valida_py():
    assert es_extension_valida("script.py") is True


def test_es_extension_valida_js():
    assert es_extension_valida("app.js") is True


def test_es_extension_valida_txt():
    assert es_extension_valida("notas.txt") is False


def test_es_extension_valida_dockerfile():
    assert es_extension_valida("Dockerfile") is True


def test_es_extension_valida_sin_extension():
    assert es_extension_valida("Makefile") is False


def test_es_directorio_excluido_git():
    assert es_directorio_excluido("/proyecto/.git/config") is True


def test_es_directorio_excluido_venv():
    assert es_directorio_excluido("/proyecto/venv/bin/python") is True


def test_es_directorio_excluido_normal():
    assert es_directorio_excluido("/proyecto/src/main.py") is False


def test_es_directorio_excluido_node_modules():
    assert es_directorio_excluido("/proyecto/node_modules/pkg/index.js") is True


def test_escanear_directorio_vacio():
    with tempfile.TemporaryDirectory() as tmpdir:
        resultado = escanear_directorio(tmpdir)
        assert "No se encontraron archivos" in resultado


def test_escanear_directorio_con_archivos():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "test.py"), "w") as f:
            f.write("x = 1")
        resultado = escanear_directorio(tmpdir)
        assert "test.py" in resultado
        assert "x = 1" in resultado


def test_escanear_directorio_excluye_venv():
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "venv"))
        with open(os.path.join(tmpdir, "venv", "script.py"), "w") as f:
            f.write("evil")
        with open(os.path.join(tmpdir, "real.py"), "w") as f:
            f.write("good")
        resultado = escanear_directorio(tmpdir)
        assert "real.py" in resultado
        assert "evil" not in resultado


def test_escanear_directorio_solo_extensiones_validas():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "data.txt"), "w") as f:
            f.write("texto")
        with open(os.path.join(tmpdir, "code.py"), "w") as f:
            f.write("print(1)")
        resultado = escanear_directorio(tmpdir)
        assert "code.py" in resultado
        assert "data.txt" not in resultado


def test_escanear_directorio_max_chars():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "big.py"), "w") as f:
            f.write("x" * 200000)
        resultado = escanear_directorio(tmpdir, max_chars=1000)
        assert "TRUNCADO POR LÍMITE" in resultado


def test_interesting_extensions_content():
    assert ".py" in INTERESTING_EXTENSIONS
    assert ".js" in INTERESTING_EXTENSIONS
    assert ".go" in INTERESTING_EXTENSIONS
    assert ".rs" in INTERESTING_EXTENSIONS


def test_exclude_dirs_content():
    assert ".git" in EXCLUDE_DIRS
    assert "node_modules" in EXCLUDE_DIRS
    assert "__pycache__" in EXCLUDE_DIRS
