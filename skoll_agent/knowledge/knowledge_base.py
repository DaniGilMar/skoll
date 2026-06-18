from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


class KnowledgeBase:
    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            skoll_dir = Path.home() / ".skoll"
            skoll_dir.mkdir(parents=True, exist_ok=True)
            db_path = skoll_dir / "knowledge.db"
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._get_conn() as conn:
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                    title, category, content, tags,
                    content='knowledge',
                    content_rowid='rowid'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS knowledge (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    category TEXT NOT NULL DEFAULT 'general',
                    content TEXT NOT NULL,
                    tags TEXT DEFAULT '',
                    source TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge
                BEGIN
                    INSERT INTO knowledge_fts(rowid, title, category, content, tags)
                    VALUES (new.id, new.title, new.category, new.content, new.tags);
                END;
            """)
            conn.execute("""
                CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge
                BEGIN
                    INSERT INTO knowledge_fts(knowledge_fts, rowid, title, category, content, tags)
                    VALUES ('delete', old.id, old.title, old.category, old.content, old.tags);
                END;
            """)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def insert(self, title: str, content: str, category: str = "general",
               tags: str = "", source: str = "") -> int:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    "INSERT INTO knowledge (title, category, content, tags, source) VALUES (?, ?, ?, ?, ?)",
                    (title, category, content, tags, source),
                )
                conn.commit()
                return cur.lastrowid or 0
            finally:
                conn.close()

    def insert_many(self, entries: list[dict[str, Any]]) -> int:
        count = 0
        with self._lock:
            conn = self._get_conn()
            try:
                for entry in entries:
                    conn.execute(
                        "INSERT INTO knowledge (title, category, content, tags, source) VALUES (?, ?, ?, ?, ?)",
                        (
                            entry.get("title", ""),
                            entry.get("category", "general"),
                            entry.get("content", ""),
                            entry.get("tags", ""),
                            entry.get("source", ""),
                        ),
                    )
                    count += 1
                conn.commit()
                return count
            finally:
                conn.close()

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """SELECT k.id, k.title, k.category, k.content, k.tags, k.source,
                              rank as relevance
                       FROM knowledge_fts
                       JOIN knowledge k ON k.id = knowledge_fts.rowid
                       WHERE knowledge_fts MATCH ?
                       ORDER BY rank
                       LIMIT ?""",
                    (query, limit),
                )
                return [dict(row) for row in cur.fetchall()]
            except sqlite3.OperationalError:
                return []
            finally:
                conn.close()

    def search_by_category(self, query: str, category: str, limit: int = 5) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                cur = conn.execute(
                    """SELECT k.id, k.title, k.category, k.content, k.tags, k.source,
                              rank as relevance
                       FROM knowledge_fts
                       JOIN knowledge k ON k.id = knowledge_fts.rowid
                       WHERE knowledge_fts MATCH ? AND k.category = ?
                       ORDER BY rank
                       LIMIT ?""",
                    (query, category, limit),
                )
                return [dict(row) for row in cur.fetchall()]
            except sqlite3.OperationalError:
                return []
            finally:
                conn.close()

    def seed_from_skills(self, skills_dir: str | Path) -> int:
        from skoll_agent.skills.skill_registry import SkillRegistry
        reg = SkillRegistry(skills_dir)
        reg.load_all()
        entries = []
        for skill in reg.skills.values():
            entries.append({
                "title": skill.name,
                "content": skill.content[:2000],
                "category": skill.category,
                "tags": skill.category,
                "source": str(skill.file_path),
            })
        return self.insert_many(entries)

    def count(self) -> int:
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM knowledge")
            return cur.fetchone()[0] or 0
        finally:
            conn.close()

    def clear(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM knowledge")
                conn.execute("DELETE FROM knowledge_fts")
                conn.commit()
            finally:
                conn.close()


_kb: KnowledgeBase | None = None


def get_knowledge_base() -> KnowledgeBase:
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb
