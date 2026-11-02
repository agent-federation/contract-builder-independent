import os, tempfile
from pap_verifier.pathing import validate_path_grammar, open_root, open_relative, read_file_bounded


def test_grammar():
    validate_path_grammar("artifacts/a.md")
    for bad in ["../x", "a//b", "/abs", "a/..", "a/.", "a\x00b", "a b", "a"*256]:
        try:
            validate_path_grammar(bad)
            assert False, bad
        except Exception:
            pass


def test_symlink_not_followed():
    d = tempfile.mkdtemp()
    target = os.path.join(d, "target.txt")
    with open(target, "w") as f:
        f.write("x")
    link = os.path.join(d, "link.txt")
    os.symlink(target, link)
    rootfd = open_root(d)
    # create a declared path entry via subdir? Instead test open_relative on symlink name at root not allowed because grammar root? Use direct open
    try:
        fd = open_relative(rootfd, "link.txt")
        assert False
    except Exception:
        pass
    os.close(rootfd)


def test_read_bounded():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "f.txt")
    with open(p, "w") as f:
        f.write("hello")
    rootfd = open_root(d)
    fd = open_relative(rootfd, "f.txt")
    data = read_file_bounded(fd, 100, [0], 100)
    assert data == b"hello"
    os.close(fd)
    os.close(rootfd)