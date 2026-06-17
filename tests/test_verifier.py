import os
import tempfile

from skoll.verifier import (
    PLUGINS_REGISTRY,
    AstAnalyzerPlugin,
    BanditVerifierPlugin,
    BaseVerificationPlugin,
    DockerSandboxPlugin,
    SemgrepVerifierPlugin,
    registrar_plugin,
)


def test_base_plugin_no_implementado():
    plugin = BaseVerificationPlugin()
    try:
        plugin.verificar("/tmp", {})
        assert False, "Debe lanzar NotImplementedError"
    except NotImplementedError:
        pass


def test_bandit_plugin_estructura():
    plugin = BanditVerifierPlugin()
    resultado = plugin.verificar("/tmp", {})
    assert isinstance(resultado, dict)
    assert "success" in resultado
    assert "log" in resultado
    assert "details" in resultado


def test_semgrep_plugin_estructura():
    plugin = SemgrepVerifierPlugin()
    resultado = plugin.verificar("/tmp", {})
    assert isinstance(resultado, dict)
    assert "success" in resultado
    assert "log" in resultado
    assert "details" in resultado


def test_ast_plugin_con_archivo_seguro():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "safe.py"), "w") as f:
            f.write("x = 1 + 1\nprint(x)")
        plugin = AstAnalyzerPlugin()
        resultado = plugin.verificar(tmpdir, {})
        assert resultado["success"] is True
        assert "No se encontraron patrones peligrosos" in resultado["log"]


def test_ast_plugin_con_archivo_peligroso():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "evil.py"), "w") as f:
            f.write("import os\nos.system('ls')")
        plugin = AstAnalyzerPlugin()
        resultado = plugin.verificar(tmpdir, {})
        assert resultado["success"] is True
        assert "os.system" in resultado["log"]


def test_ast_plugin_detecta_eval():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "danger.py"), "w") as f:
            f.write("eval('print(1)')")
        plugin = AstAnalyzerPlugin()
        resultado = plugin.verificar(tmpdir, {})
        assert "eval()" in resultado["log"]


def test_docker_plugin_sin_docker():
    plugin = DockerSandboxPlugin()
    resultado = plugin.verificar("/tmp", {})
    # Si docker no está instalado, debe fallar amablemente
    import shutil
    if shutil.which("docker") is None:
        assert resultado["success"] is False
        assert "Docker no está instalado" in resultado["log"]
    else:
        assert isinstance(resultado, dict)


def test_registry_contiene_plugins():
    assert "bandit" in PLUGINS_REGISTRY
    assert "semgrep" in PLUGINS_REGISTRY
    assert "ast" in PLUGINS_REGISTRY
    assert "docker" in PLUGINS_REGISTRY


def test_registrar_plugin_externo():
    class MiPlugin(BaseVerificationPlugin):
        name = "TestPlugin"
        description = "Plugin de prueba"
        def verificar(self, target_path, context):
            return {"success": True, "log": "test", "details": "test"}
    registrar_plugin("test", MiPlugin)
    assert "test" in PLUGINS_REGISTRY
    assert PLUGINS_REGISTRY["test"] == MiPlugin
    del PLUGINS_REGISTRY["test"]


def test_plugin_names():
    assert BanditVerifierPlugin.name == "Bandit SAST"
    assert SemgrepVerifierPlugin.name == "Semgrep SAST"
    assert AstAnalyzerPlugin.name == "Analizador AST"
    assert DockerSandboxPlugin.name == "Sandbox Docker"
