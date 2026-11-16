import io
import stat
import zipfile
from pathlib import Path

import pytest

CORPUS = Path(__file__).resolve().parent / "corpus"


def make_zip(entries: dict[str, bytes], symlinks: dict[str, str] | None = None, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return buf.getvalue()


def zip_dir(root: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(root).as_posix())
    return buf.getvalue()


@pytest.fixture
def tmp_zip(tmp_path):
    def _make(entries, symlinks=None, compression=zipfile.ZIP_DEFLATED) -> Path:
        path = tmp_path / "artifact.zip"
        path.write_bytes(make_zip(entries, symlinks, compression))
        return path
    return _make
