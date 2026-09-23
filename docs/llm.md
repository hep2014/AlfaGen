# AlfaGen / DeepSeek Flash

Источник — инструкция AlfaGen, страницы 8–9 и 12. Документ описывает Kilo/OpenCode;
использование того же API сервисом подготовлено и требует живой проверки с ключом.

- Модель: `deepseek-ai/DeepSeek-V4-Flash-0731`.
- URL: `https://alfagen.alfabank.ru/continue-dev/`.
- Альтернативный URL из инструкции: `https://alfagen.alfabank.ru/continue-dev/v1`.
- Ключ: https://alfagen.alfabank.ru/plugins → Enterprise Vibe Coding.

## Что предоставить

Сохранить токен без `Bearer` в secret environment variable `ALFAGEN_API_KEY`.
Ключ не помещать в чат, README или шаблон конфигурации. Если платформа умеет
только secret-файлы, используйте `ALFAGEN_KEY_FILE` и укажите путь к файлу.
При ошибке TLS нужны пути к сертификатам из инструкции. Адаптер принимает PEM bundle;
проверка сертификатов не отключается, глобальное хранилище не менялось.
Наличие GOST-сертификата не гарантирует поддержку TLS стандартным Python:
при ошибке потребуется совместимая среда от организаторов.

## Сервис

Дополнительно к настройкам потребителей из README:

```powershell
$env:LLM_PROVIDER = 'alfagen'
$env:ALFAGEN_API_KEY = 'your-alfagen-token'
$env:AUDIT_LOG_DIR = 'logs'
# При необходимости:
# $env:ALFAGEN_CA_FILE = 'C:/path/to/ca-bundle.pem'
# $env:ALFAGEN_BASE_URL = 'https://alfagen.alfabank.ru/continue-dev/v1'
```

В деплое предпочтительно передавать токен через secret environment variable
`ALFAGEN_API_KEY`. Старый вариант с файлом тоже поддерживается:
`ALFAGEN_KEY_FILE=/run/secrets/alfagen.key`. Достаточно указать один из двух
вариантов; при наличии обоих приложение завершает запуск с ошибкой конфигурации.

Без LLM_PROVIDER используется local-echo. Адаптер отправляет POST на chat/completions
относительно base URL. Контракт проверен mock-тестами, реальное подключение ещё не выполнено.
Вариант /v1 не перебирается автоматически. Перенаправления и автоматические повторы отключены;
разрешён только хост AlfaGen. TLS проверяется, доверие можно дополнить локальным CA bundle.
Запросы не стримятся; max_tokens=2048, таймаут 30 секунд на фазу HTTP, ответ не более 2 МБ.
Таймаут не является абсолютным deadline всего запроса.
Перед отправкой проверяются оставшиеся распознаваемые ПД, после — новые значения и токены.
Правила неполны: первый живой тест проводить на синтетическом тексте.

## Помощник для разработки

Kilo Code: пользовательский OpenAI Compatible провайдер, URL, модель и ключ выше.
OpenCode: шаблон `config/opencode.alfagen.example.json` составлен по PDF;
рабочий файл Windows — `%USERPROFILE%/.config/opencode/opencode.jsonc`.
Существующие настройки объединить с шаблоном, не перезаписывать целиком.
Ключ вставляется только в рабочий локальный файл. Лимиты 1 000 000/30 000 в шаблоне
взяты из PDF и не проверены нашим сервисом. Ключ AlfaGen отличается от GATEWAY_API_KEYS.
Прямые вызовы Kilo/OpenCode в AlfaGen не проходят автоматически через наш прокси.
