import subprocess

import pytest

from secretwall import hook as H

SECRET = "sk-proj-Zx81kQ2mVb7Lw0pTn4Rc9Yd3Hf6Gj5Ks2Ae8Uo1Iq"


def git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd)] + list(args), check=True, capture_output=True)


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    (h / ".ssh").mkdir(parents=True)
    (h / ".ssh" / "id_rsa").write_text("PRIVATE\n")
    (h / ".ssh" / "id_rsa.pub").write_text("ssh-rsa AAAA\n")
    (h / ".aws").mkdir()
    (h / ".aws" / "credentials").write_text("[default]\naws_secret_access_key = x\n")
    return h


@pytest.fixture
def project(tmp_path):
    p = tmp_path / "proj"
    (p / "src").mkdir(parents=True)
    (p / "secrets").mkdir()
    (p / "config").mkdir()
    (p / ".env").write_text("OPENAI_API_KEY=%s\nNODE_ENV=development\n" % SECRET)
    (p / ".env.example").write_text("OPENAI_API_KEY=\n")
    (p / "secrets" / "db.json").write_text('{"password": "hunter2hunter2"}\n')
    (p / "config" / "credentials.json").write_text('{"token": "abc"}\n')
    (p / "src" / "app.py").write_text("print('hi')\n")
    (p / ".gitignore").write_text(".env\nsecrets/\n")
    git(p, "init", "-q")
    return p


@pytest.fixture
def guard(project, home):
    rules = H.Rules.parse(H.DEFAULT_RULES + "\nsecrets/\n")
    return H.Guard(str(project), rules, {}, home=str(home))
