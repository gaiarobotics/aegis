"""Tests for skill loader."""

import json

from aegis.skills.loader import LoadResult, SkillLoader
from aegis.skills.manifest import SkillManifest


def _make_manifest(name="test-skill", version="1.0.0", hashes=None):
    """Helper to build a valid SkillManifest."""
    return SkillManifest(
        name=name,
        version=version,
        publisher="test-pub",
        hashes=hashes if hashes is not None else {"skill.py": "placeholder"},
        signature=None,
        capabilities={
            "network": False,
            "filesystem": False,
            "tools": [],
            "read_write": "read",
        },
        secrets=[],
        budgets=None,
        sandbox=True,
    )


class TestLoadCleanSkillApproved:
    def test_load_clean_skill_approved(self, tmp_path):
        """Clean code should be approved by the loader."""
        code = "def hello():\n    return 'world'\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        manifest = _make_manifest()
        result = loader.load_skill(str(skill_file), manifest)

        assert isinstance(result, LoadResult)
        assert result.approved is True
        assert result.skill_hash != ""
        assert result.incubation is False

    def test_load_clean_multi_function(self, tmp_path):
        """Clean code with multiple functions should be approved."""
        code = (
            "import math\n\n"
            "def compute(x):\n    return math.sqrt(x)\n\n"
            "def add(a, b):\n    return a + b\n"
        )
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        result = loader.load_skill(str(skill_file), _make_manifest())
        assert result.approved is True


class TestLoadDangerousSkillRejected:
    def test_load_dangerous_skill_rejected(self, tmp_path):
        """Code with exec() should be rejected."""
        code = 'exec("import os; os.system(\'rm -rf /\')")\n'
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        result = loader.load_skill(str(skill_file), _make_manifest())

        assert isinstance(result, LoadResult)
        assert result.approved is False
        assert "reject" in result.reason.lower() or "dangerous" in result.reason.lower() or "unsafe" in result.reason.lower() or "denied" in result.reason.lower() or "fail" in result.reason.lower()

    def test_load_subprocess_rejected(self, tmp_path):
        """Code with subprocess should be rejected."""
        code = "import subprocess\nsubprocess.run(['ls'])\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        result = loader.load_skill(str(skill_file), _make_manifest())
        assert result.approved is False

    def test_invalid_manifest_rejected(self, tmp_path):
        """Skill with invalid manifest (empty name) should be rejected."""
        code = "def safe():\n    return 1\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        bad_manifest = _make_manifest(name="", version="1.0.0")
        result = loader.load_skill(str(skill_file), bad_manifest)
        assert result.approved is False
        assert "manifest" in result.reason.lower() or "valid" in result.reason.lower()


class TestHashCacheDedup:
    def test_hash_cache_dedup(self, tmp_path):
        """Same code loaded twice should use cached result."""
        code = "def hello():\n    return 'world'\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        manifest = _make_manifest()

        result1 = loader.load_skill(str(skill_file), manifest)
        result2 = loader.load_skill(str(skill_file), manifest)

        assert result1.approved == result2.approved
        assert result1.skill_hash == result2.skill_hash
        # Verify the cache was actually used (same object or same values)
        assert result1.skill_hash in loader._hash_cache

    def test_different_code_different_hash(self, tmp_path):
        """Different code should produce different cache entries."""
        loader = SkillLoader()
        manifest = _make_manifest()

        code1 = "def hello():\n    return 'world'\n"
        file1 = tmp_path / "skill1.py"
        file1.write_text(code1)
        result1 = loader.load_skill(str(file1), manifest)

        code2 = "def goodbye():\n    return 'bye'\n"
        file2 = tmp_path / "skill2.py"
        file2.write_text(code2)
        result2 = loader.load_skill(str(file2), manifest)

        assert result1.skill_hash != result2.skill_hash
        assert len(loader._hash_cache) == 2


class TestIncubationMode:
    def test_incubation_mode(self, tmp_path):
        """When config has incubation_mode, result should set incubation=True."""
        code = "def safe():\n    return 42\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        config = {"incubation_mode": True}
        loader = SkillLoader(config=config)
        manifest = _make_manifest()
        result = loader.load_skill(str(skill_file), manifest)

        assert result.approved is True
        assert result.incubation is True

    def test_no_incubation_by_default(self, tmp_path):
        """Without incubation config, incubation should be False."""
        code = "def safe():\n    return 42\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        loader = SkillLoader()
        manifest = _make_manifest()
        result = loader.load_skill(str(skill_file), manifest)

        assert result.incubation is False


class TestPathContainment:
    def test_path_outside_base_rejected(self, tmp_path):
        """Skills outside the skills_base_dir should be rejected."""
        import os
        import tempfile
        code = "def safe():\n    return 1\n"
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            outside_path = f.name

        base_dir = str(tmp_path / "skills")
        (tmp_path / "skills").mkdir()
        config = {"skills_base_dir": base_dir}
        loader = SkillLoader(config=config)
        result = loader.load_skill(outside_path, _make_manifest())
        assert result.approved is False
        assert "outside" in result.reason.lower()
        os.unlink(outside_path)

    def test_path_inside_base_accepted(self, tmp_path):
        """Skills inside the skills_base_dir should be accepted."""
        code = "def safe():\n    return 1\n"
        base_dir = tmp_path / "skills"
        base_dir.mkdir()
        skill_file = base_dir / "main.py"
        skill_file.write_text(code)

        config = {"skills_base_dir": str(base_dir)}
        loader = SkillLoader(config=config)
        result = loader.load_skill(str(skill_file), _make_manifest())
        assert result.approved is True


class TestHashVerificationInLoader:
    def test_hash_mismatch_rejected(self, tmp_path):
        """Skill file with hash mismatch should be rejected."""
        code = "def safe():\n    return 1\n"
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        manifest = SkillManifest(
            name="test-skill", version="1.0.0", publisher="pub",
            hashes={"main.py": "wrong_hash_value"},
            signature=None, capabilities={}, secrets=[], budgets=None, sandbox=True,
        )
        loader = SkillLoader()
        result = loader.load_skill(str(skill_file), manifest)
        assert result.approved is False
        assert "hash mismatch" in result.reason.lower()

    def test_hash_match_accepted(self, tmp_path):
        """Skill file with correct hash should be accepted."""
        import hashlib
        code = "def safe():\n    return 1\n"
        expected_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        skill_file = tmp_path / "main.py"
        skill_file.write_text(code)

        manifest = SkillManifest(
            name="test-skill", version="1.0.0", publisher="pub",
            hashes={"main.py": expected_hash},
            signature=None, capabilities={}, secrets=[], budgets=None, sandbox=True,
        )
        loader = SkillLoader()
        result = loader.load_skill(str(skill_file), manifest)
        assert result.approved is True
