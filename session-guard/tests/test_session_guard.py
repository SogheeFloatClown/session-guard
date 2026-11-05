import sys
import pytest
import session_guard as sg


def test_overwrite_deletes_file(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"secret" * 1000)
    assert sg.secure_overwrite(f, passes=2)
    assert not f.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_symlink_is_never_followed(tmp_path):
    target = tmp_path / "keep.txt"
    target.write_text("keep me")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert not sg.secure_overwrite(link)
    assert target.read_text() == "keep me"


def test_tracker_separates_created_from_modified(tmp_path):
    t = sg.WriteTracker(excludes=[])

    class E:
        is_directory = False
        def __init__(self, p): self.src_path = self.dest_path = str(p)

    new, old = tmp_path / "new", tmp_path / "old"
    t.on_created(E(new)); t.on_modified(E(new)); t.on_modified(E(old))
    assert str(new) in t.created and str(new) not in t.modified_existing
    assert str(old) in t.modified_existing
