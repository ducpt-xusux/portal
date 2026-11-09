from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class BusinessConfig:
    database_path: Path | None = None
    context: str = 'PORTAL'
    secure_cookie: bool = True
    trusted_origins: tuple[str, ...] = ()
    allow_insecure_loopback: bool = False
    session_seconds: int = 3600
    cookie_name: str = 'portal_session'
    body_limit: int = 16_384

    def __post_init__(self):
        if self.context not in {'TEST', 'PORTAL'}:
            raise ValueError('Invalid business context')
        if not 60 <= self.session_seconds <= 43_200:
            raise ValueError('Invalid session lifetime')
        if self.cookie_name != 'portal_session' or not 1024 <= self.body_limit <= 65_536:
            raise ValueError('Invalid cookie or body limit')
        if not self.secure_cookie and not self.allow_insecure_loopback:
            raise ValueError('Insecure cookies require explicit local loopback mode')
        for origin in self.trusted_origins:
            parsed = urlsplit(origin)
            local = parsed.hostname in {'127.0.0.1', 'localhost', '::1'}
            if not self.secure_cookie and not local:
                raise ValueError('Local insecure cookies require loopback origins only')
            if (parsed.scheme != 'https' and not (parsed.scheme == 'http' and local
                    and self.allow_insecure_loopback)) or parsed.path or parsed.query or parsed.fragment or parsed.username:
                raise ValueError('Origins must be explicit HTTPS origins or opted-in local origins')
