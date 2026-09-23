import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx

MODEL = "deepseek-ai/DeepSeek-V4-Flash-0731"
BASE_URL = "https://alfagen.alfabank.ru/continue-dev/"


class ProviderUnavailable(Exception):
    """AlfaGen недоступен. Никакие детали не пересекают границу API."""


class AlfaGenProvider:
    """Адаптер к AlfaGen (DeepSeek-V4-Flash).

    Требования безопасности:
      - только хост alfaGen, только https;
      - TLS-проверка включена (можно дополнить локальным CA);
      - редиректы и автоматические повторы отключены;
      - ответ ограничен 2 МБ;
      - никакие детали ошибки не уходят наружу.
    """

    name = "alfagen-deepseek-flash"
    local_only = False

    def __init__(
        self,
        key_file: str | None = None,
        ca_file: str | None = None,
        base_url: str = BASE_URL,
        transport: httpx.BaseTransport | None = None,
        *,
        api_key: str | None = None,
    ):
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "alfagen.alfabank.ru"
            or parsed.path.rstrip("/") not in {"/continue-dev", "/continue-dev/v1"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("invalid_alfagen_url")

        if api_key is not None and key_file is not None:
            raise ValueError("multiple_alfagen_keys")
        if api_key is None:
            if not key_file:
                raise ValueError("alfagen_key_required")
            self._key = Path(key_file).read_text(encoding="utf-8").strip()
        else:
            self._key = api_key.strip()
        if not self._key or any(c.isspace() for c in self._key):
            raise ValueError("invalid_alfagen_key")

        self._url = base_url.rstrip("/") + "/chat/completions"

        self._tls = ssl.create_default_context()
        if ca_file:
            self._tls.load_verify_locations(cafile=ca_file)

        self._transport = transport

    def generate(self, protected_text: str) -> str:
        payload = {
            "model": MODEL,
            "stream": False,
            "max_tokens": 2048,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Отвечай на запрос. Сохраняй токены вида [[PD:...]] "
                        "без изменений. Не придумывай персональные данные."
                    ),
                },
                {"role": "user", "content": protected_text},
            ],
        }

        try:
            with httpx.Client(
                verify=self._tls,
                transport=self._transport,
                timeout=30,
                follow_redirects=False,
                trust_env=False,
            ) as client, client.stream(
                "POST",
                self._url,
                headers={"Authorization": "Bearer " + self._key},
                json=payload,
            ) as response:
                if response.status_code != 200:
                    raise ProviderUnavailable()

                data = bytearray()
                for chunk in response.iter_bytes():
                    if len(data) + len(chunk) > 2_000_000:
                        raise ProviderUnavailable()
                    data.extend(chunk)

            answer = json.loads(data)["choices"][0]["message"]["content"]
            if not isinstance(answer, str):
                raise ProviderUnavailable()
            return answer

        except (
            httpx.HTTPError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            ProviderUnavailable,
        ):
         
            raise ProviderUnavailable("alfagen_unavailable") from None
