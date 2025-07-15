web: gunicorn src.app:app
release: python -c "from src.app import app, db; app.app_context().push(); db.create_all()"
