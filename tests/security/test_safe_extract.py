"""Seguridad de la ingesta en el worker (manual §9: ZIP Slip, symlinks, traversal, bombas)."""

import zipfile

import pytest

from vulnix_sandbox.extract import ExtractionError, ExtractLimits, safe_extract


def _extract(path, tmp_path, limits=None):
    dest = tmp_path / "out"
    dest.mkdir()
    return safe_extract(path, dest, limits), dest


@pytest.mark.parametrize("name", ["../evil.php", "a/../../evil.php", "/etc/passwd", "C:/Windows/evil.dll", "..\\evil.php", "a\\..\\..\\x"])
def test_rejects_traversal_and_absolute_paths(tmp_zip, tmp_path, name):
    with pytest.raises(ExtractionError) as exc:
        _extract(tmp_zip({name: b"x"}), tmp_path)
    assert exc.value.code in ("ZIP_PATH_TRAVERSAL", "ZIP_PATH_INVALID")
    assert not (tmp_path / "evil.php").exists()


def test_rejects_symlinks(tmp_zip, tmp_path):
    with pytest.raises(ExtractionError) as exc:
        _extract(tmp_zip({"ok.php": b"<?php"}, symlinks={"link": "/etc/passwd"}), tmp_path)
    assert exc.value.code == "ZIP_SPECIAL_ENTRY"


@pytest.mark.parametrize("name", ["CON", "dir/nul.txt", "aux.php", "file.php:stream", "trailing. ", "dots."])
def test_rejects_reserved_and_ambiguous_names(tmp_zip, tmp_path, name):
    with pytest.raises(ExtractionError):
        _extract(tmp_zip({name: b"x"}), tmp_path)


def test_rejects_case_collisions(tmp_zip, tmp_path):
    with pytest.raises(ExtractionError) as exc:
        _extract(tmp_zip({"App.php": b"a", "app.php": b"b"}), tmp_path)
    assert exc.value.code == "ZIP_DUPLICATE_ENTRY"


def test_rejects_zip_bomb_by_ratio(tmp_zip, tmp_path):
    bomb = tmp_zip({"bomb.txt": b"\0" * (20 * 1024 * 1024)})
    with pytest.raises(ExtractionError) as exc:
        _extract(bomb, tmp_path)
    assert exc.value.code == "ZIP_BOMB_SUSPECTED"


def test_rejects_too_many_files(tmp_zip, tmp_path):
    with pytest.raises(ExtractionError) as exc:
        _extract(tmp_zip({f"f{i}.txt": b"x" for i in range(11)}), tmp_path, ExtractLimits(max_files=10))
    assert exc.value.code == "ZIP_TOO_MANY_FILES"


def test_rejects_lying_headers(tmp_path):
    """El tamaño declarado en la cabecera no se confía: se cuentan bytes reales."""
    path = tmp_path / "lie.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"A" * 100)
    data = bytearray(path.read_bytes())
    # Reducir el tamaño descomprimido declarado en la cabecera central (offset 24 desde la firma PK\x01\x02).
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 24:cd + 28] = (10).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    with pytest.raises((ExtractionError, zipfile.BadZipFile)):
        _extract(path, tmp_path)


def test_extracts_valid_archive_read_only(tmp_zip, tmp_path):
    names, dest = _extract(tmp_zip({"src/index.php": b"<?php echo 1;", "README.md": b"hola", "src/": b""}), tmp_path)
    assert sorted(names) == ["README.md", "src/index.php"]
    target = dest / "src" / "index.php"
    assert target.read_bytes() == b"<?php echo 1;"
    with pytest.raises(PermissionError):
        target.open("ab")
