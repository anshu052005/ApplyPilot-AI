import os

# Unit tests never touch a database or the network. Set safe defaults before the app is imported.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SUPABASE_URL", "http://127.0.0.1:54321")
