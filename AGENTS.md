# SubTools maintenance

- This repository is independent. Do not import files or services from the former MySub2 checkout.
- The supported product entry is `run_web.py`, with `web_app.py`, `server_engine.py`, and `web/` providing the web interface. Existing Tk modules remain as compatibility references and regression fixtures; the server must not import them.
- Preserve the existing OAuth, SMS order lifecycle, token rotation recovery, identity matching, and read-only inspection contracts. A cancelled or uncertain operation must never be silently replayed.
- All private configuration, account records, credentials, migration backups, and diagnostic screenshots belong under ignored `data/` or `.browser-smoke/`. Never stage them, print their contents, or include them in Docker build context.
- Paid SMS, live account login, and backend writes need task-specific user authorization. Normal regression tests use only synthetic fixtures and mocked transports.
- Use one server worker: the engine serializes jobs around the fixed loopback OAuth callback port. Do not expose callback port 1455, browser debugging, or the data directory publicly.
- Run relevant tests with `python -m pytest`. Browser smoke tests are opt-in with `SUBTOOLS_BROWSER_TEST=1 python -m pytest tests/test_web_browser.py`; these use a local fixture service.
- Keep `README.md`, deployment examples, and `WEB_VALIDATION.md` aligned with material behavior changes.
