import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

_pool: pool.SimpleConnectionPool | None = None


def init_pool(
    host: str = os.getenv("DB_HOST", "localhost"),
    dbname: str = os.getenv("DB_NAME", "messaging_db"),
    user: str = os.getenv("DB_USER", "messaging_app"),
    password: str = os.getenv("DB_PASSWORD", "password"),
    minconn: int = 1,
    maxconn: int = 10,
) -> None:
    global _pool
    _pool = pool.SimpleConnectionPool(
        minconn, maxconn,
        host=host, dbname=dbname, user=user, password=password
    )


def get_conn() -> psycopg2.extensions.connection:
    if _pool is None:
        raise RuntimeError("Connection pool not initialised — call init_pool() first")
    return _pool.getconn()


def release_conn(conn: psycopg2.extensions.connection) -> None:
    if _pool:
        _pool.putconn(conn)


class DBConnection:
    """Context manager that borrows a connection from the pool."""

    def __enter__(self) -> tuple[psycopg2.extensions.connection, psycopg2.extensions.cursor]:
        self.conn = get_conn()
        self.cur = self.conn.cursor(cursor_factory=RealDictCursor)
        return self.conn, self.cur

    def __exit__(self, exc_type, _exc_val, _exc_tb) -> None:
        if exc_type:
            self.conn.rollback()
        self.cur.close()
        release_conn(self.conn)
