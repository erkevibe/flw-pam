# FLW PAM Workflow Lab

Первый срез PAM-схемы: локальный процесс заявки, независимого одобрения, отказа, отзыва и проверки срока доступа. Python 3.11+, стандартная библиотека и SQLite. HTTP-сервера, собственных паролей и выдачи реальных полномочий нет.

**Граница лаборатории:** `--actor` — доверенный ввод текущего пользователя ОС, а не аутентификация человека. База и аудит доступны владельцу файла; аудит транзакционный, но не WORM и не защищён от администратора БД. Этот срез не готов к production PAM.

## Быстрый запуск

```bash
python3 -B -m unittest discover -v
python3 workflow.py --help

# Команда вернёт JSON с id; далее подставьте его вместо REQUEST_ID.
python3 workflow.py --db /tmp/flw-pam-demo.db request \
  --actor alice --resource db-read --reason 'Диагностика в лаборатории' --ttl 300
python3 workflow.py --db /tmp/flw-pam-demo.db approve REQUEST_ID --actor bob
python3 workflow.py --db /tmp/flw-pam-demo.db check REQUEST_ID --actor alice --resource db-read
python3 workflow.py --db /tmp/flw-pam-demo.db revoke REQUEST_ID --actor alice --reason 'Работа завершена'
python3 workflow.py --db /tmp/flw-pam-demo.db check REQUEST_ID --actor alice --resource db-read
python3 workflow.py --db /tmp/flw-pam-demo.db audit
```

Проверка разрешённой заявки возвращает exit0, отказ — exit1, ошибочный ввод — exit2. Ресурсы CLI ограничены `db-read` и `server-shell`; TTL — от 1 до 3600 секунд, одобрение срок не продлевает. Состояния: `pending → approved → revoked` либо `pending → denied`. Инициатор не может одобрить собственную заявку.

Публичный Python API и точные правила зафиксированы в [CONTRACT.md](CONTRACT.md). Исходная [PAM-схема](docs/source-architecture.png), [продуктовые требования](docs/product-requirements.md), [независимый архитектурный обзор](docs/architecture-review.md) и [критерии приёмки](docs/acceptance.md) находятся в `docs/`.

## Разработка и проверка

Реальный FLW запускает отдельных Codex workers: разработчика, автора контрактных тестов и security reviewer с правом veto. Первый прогон с профилем СОВЕТа 60 выполнялся последовательно и отклонил developer по таймауту 240 секунд. СОВЕТ выбрал корректирующий профиль 40 (`max_parallel=2`): developer и независимый QA работают параллельно, reviewer ждёт обоих. Непринятый черновик первого прогона проходит новый реальный review/fix worker; он не становится принятой поставкой простым копированием. В корректирующем прогоне worker ограничен 420 секундами, общий deadline — 1200 секунд. Проверки не ослаблены. Контрольная точка этого прогона — 60 секунд, параметр настраивается. Это не обязательный 15-минутный спринт и не имитация возраста или коллективного LLM-решения: policy СОВЕТа в FLW детерминирована.

В репозиторий переносятся только принятый код, тесты и контракт; runtime logs, токены и рабочие базы не публикуются. GitHub Actions запускает unittest на Python 3.11/3.12. Локальный корректирующий FLW прогон завершён `demo_ready`: все три роли приняты, 21 контрактный тест и CLI help прошли, reviewer вынес `approve`. Независимый дополнительный QA проверил ещё 8 security-тестов: вместе 29 успешных тестов на тех же файлах. Первый прогон сохранён как `blocked` из-за таймаутов, а не скрыт. [План и очищенная история прогонов](docs/flw-run.json), [решение reviewer](docs/security-review.json). Наличие CI-конфигурации само по себе не означает, что GitHub CI уже прошёл.
