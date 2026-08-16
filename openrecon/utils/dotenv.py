import os
from pathlib import Path

def load_dotenv(dotenv_path: str = None) -> bool:
    """
    Simple, zero-dependency .env loader.
    """
    if dotenv_path is None:
        # Search current working directory, then user home
        cwd_env = Path.cwd() / ".env"
        if cwd_env.is_file():
            dotenv_path = cwd_env
        else:
            return False

    path = Path(dotenv_path)
    if not path.is_file():
        return False

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
        return True
    except Exception:
        return False
