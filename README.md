# Alpha Privacy Gateway

Каркас единого сервиса защиты персональных данных для задачи AlfaGen на Альфа-Вайб.
Системы банка используют общий API и свои политики вместо разработки отдельных маскировщиков.

**Статус: развиваемый прототип, не готовое решение хакатона.** Работают базовые правила всех 17 обязательных категорий
и двух дополнительных документов,
токенизация, точное обратное преобразование неизменённого текста, авторизация систем,
зашифрованные соответствия с TTL и локальный echo-сценарий. По умолчанию сетевых вызовов LLM нет; адаптер AlfaGen включается явно после настройки ключа.
Полное покрытие вариантов, UI, публикация политик с проверкой регрессий, TPS и подтверждение SLA на целевом стенде ещё предстоят.
Добавлены конкурентные проверки `/process`, ограниченное шифрованное TTL-хранилище и воспроизводимый HTTP-бенчмарк; подробности — [устойчивость и замеры](docs/resilience.md). Адаптер AlfaGen подготовлен, живое подключение не проверено.
После разбора PDF добавлены кеш распознавания, повторное использование токена внутри сообщения,
квитанция решений, режим необратимого скрытия, локальные комбинации типов и новые поля через
конфигурацию. Покрытие и ограничения — в [разборе PDF и реализованных функций](docs/pdf-review-and-features.md).
Крупные запросы `/process` используют отдельный ограниченный пул; общий бюджет входящих
тел ограничен 64 MB. При заполнении этих ресурсов сервис возвращает 429 с `Retry-After: 1`.
Не использовать с реальными данными: неполный детектор не обеспечивает требуемую защиту.

## Запуск в PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e '.[dev]'
$demoKey = .\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:GATEWAY_API_KEYS = @{ 'support-demo' = $demoKey } | ConvertTo-Json -Compress
.\.venv\Scripts\python -m uvicorn alpha_privacy.api:from_env --factory --host 127.0.0.1 --port 8000 --no-access-log
```

В браузере: http://127.0.0.1:8000/docs. Для короткого локального демо хранилище
соответствий находится в памяти — это самый быстрый режим, но он рассчитан на один
процесс и теряет пары при перезапуске.

Для нескольких uvicorn workers включите общий зашифрованный SQLite-WAL vault. Ключ
создаётся один раз в отдельном runtime-файле и читается всеми workers:

```powershell
$env:PROCESS_VAULT_DB = '.runtime/process-vault.sqlite3'
$env:PROCESS_VAULT_KEY_FILE = '.runtime/process-vault.key'
$env:PROCESS_WORKERS = '16'
.\.venv\Scripts\python -m uvicorn alpha_privacy.api:from_env --factory --host 0.0.0.0 --port 8000 --workers 8 --no-access-log
```

В этом режиме первый и второй запрос с одним `payload_id` могут попасть в разные
процессы: атомарная запись и чтение идут через общий vault, а Fernet-ключ не попадает
в репозиторий. `PROCESS_WORKERS` — пул CPU-воркеров внутри каждого процесса; по
умолчанию 16. Для нескольких VM нужен внешний общий store вместо локального файла.
Зависимости заданы диапазонами; воспроизводимый lock-файл — задача следующего этапа.

## Настройка — пять предложений

1. Добавьте систему в `config/policies.json`, а её случайный ключ длиной от 32 символов — в JSON переменной `GATEWAY_API_KEYS`.
2. Поле `enabled` включает или отключает доступ системы.
3. Поле `detect_types` задаёт типы для идентификации и токенизации; доступные типы перечислены в `/health/live`, неизвестный тип останавливает запуск.
4. Поля `restore_enabled` и `session_ttl_seconds` управляют восстановлением и сроком доступности соответствий.
5. После изменения перезапустите сервис; путь к другому файлу задаётся через `POLICY_FILE`.

## Проверка жюри: локальное демо

В другом терминале передайте тот же временный ключ в `$demoKey` (ключ не сохранять в репозитории).

```powershell
$headers = @{ 'X-System-ID' = 'support-demo'; 'X-API-Key' = $demoKey }
$body = @{ text = 'Контакт demo@example.org, +7 (999) 123-45-67.' } | ConvertTo-Json
$masked = Invoke-RestMethod http://127.0.0.1:8000/v1/mask -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
$masked
$restore = @{ text = $masked.text; session_id = $masked.session_id } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/v1/restore -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($restore))
Invoke-RestMethod http://127.0.0.1:8000/v1/demo/roundtrip -Method Post -Headers $headers -ContentType 'application/json; charset=utf-8' -Body ([Text.Encoding]::UTF8.GetBytes($body))
Invoke-RestMethod http://127.0.0.1:8000/metrics -Headers $headers
```

`roundtrip` показывает токенизированный текст и восстановленный ответ **локального echo**.
JSON-логи этапов и обнаруженных типов идут в консоль; `AUDIT_LOG_DIR=logs` добавляет файл с ротацией.
Каждый запрос получает `X-Request-ID`; значений данных, ключей и таблиц соответствий в аудите нет.
Prometheus: `privacy_operation_seconds`, `privacy_requests_total`, `privacy_entities_total`.
RPS вычисляется через `rate(privacy_requests_total[1m])`; TPS появится после выбора токенизатора.
HTTP-счётчик `privacy_http_requests_total` включает отказы авторизации/валидации; `privacy_http_seconds` измеряет полное время обработки HTTP внутри приложения.
Операционные метрики остаются отдельно; roundtrip включает время локального провайдера.

```powershell
.\.venv\Scripts\python -m pytest -q
```


