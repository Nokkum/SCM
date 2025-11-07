import json
import os
from typing import Optional, Dict, Any
from threading import Lock
from datetime import datetime
import psycopg2

class Database:
    def __init__(self, filepath: str = "server_settings.json", pg_conn_str: str = None):
        self.filepath = filepath
        self.pg_conn_str = pg_conn_str
        self.lock = Lock()
        self._ensure_file_exists()
        self._create_pg_table()

    def _ensure_file_exists(self):
        if not os.path.exists(self.filepath):
            with open(self.filepath, 'w') as f:
                json.dump({}, f)

    def _create_pg_table(self):
        if self.pg_conn_str:
            conn = psycopg2.connect(self.pg_conn_str)
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS credentials (
                        category TEXT,
                        provider TEXT,
                        info JSON,
                        updated_at TIMESTAMP
                    )
                """)
            conn.commit()
            conn.close()

    def _read_data(self) -> Dict[str, Any]:
        try:
            with open(self.filepath, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _write_data(self, data: Dict[str, Any]):
        with open(self.filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def get(self, category: str, provider: str) -> Optional[Dict[str, Any]]:
        """Get credential metadata by category and provider."""
        with self.lock:
            data = self._read_data()
            return data.get(category, {}).get(provider)

    def set(self, category: str, provider: str, info: Dict[str, Any]):
        """Store credential metadata."""
        with self.lock:
            data = self._read_data()
            data.setdefault(category, {})[provider] = {
                **info,
                "updated_at": datetime.utcnow().isoformat()
            }
            self._write_data(data)

            if self.pg_conn_str:
                conn = psycopg2.connect(self.pg_conn_str)
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO credentials (category, provider, info, updated_at)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (category, provider) DO UPDATE
                        SET info = EXCLUDED.info, updated_at = EXCLUDED.updated_at
                    """, (category, provider, json.dumps(info), datetime.utcnow()))
                conn.commit()
                conn.close()

    def delete(self, category: str, provider: str):
        """Remove provider from database."""
        with self.lock:
            data = self._read_data()
            if category in data and provider in data[category]:
                del data[category][provider]
                if not data[category]:
                    del data[category]
                self._write_data(data)

            if self.pg_conn_str:
                conn = psycopg2.connect(self.pg_conn_str)
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM credentials WHERE category = %s AND provider = %s", (category, provider))
                conn.commit()
                conn.close()

    def list_all(self) -> Dict[str, Any]:
        """Return all credentials metadata."""
        with self.lock:
            return self._read_data()