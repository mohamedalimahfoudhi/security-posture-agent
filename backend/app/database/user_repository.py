from app.database.connection import get_connection
import psycopg2.extras

def _map_user(row):
    if not row:
        return None
    return dict(row)

def get_user_by_email(email):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT id, username, email, hashed_password, full_name, role, customer_id, is_active, created_at
            FROM users
            WHERE email = %s
        """, (email,))
        return _map_user(cur.fetchone())
    finally:
        cur.close()
        conn.close()

def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT id, username, email, hashed_password, full_name, role, customer_id, is_active, created_at
            FROM users
            WHERE username = %s
        """, (username,))
        return _map_user(cur.fetchone())
    finally:
        cur.close()
        conn.close()

def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            SELECT id, username, email, hashed_password, full_name, role, customer_id, is_active, created_at
            FROM users
            WHERE id = %s
        """, (user_id,))
        return _map_user(cur.fetchone())
    finally:
        cur.close()
        conn.close()

def create_user(username, email, hashed_password, full_name, role, customer_id, is_active=True):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cur.execute("""
            INSERT INTO users (username, email, hashed_password, full_name, role, customer_id, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id, username, email, full_name, role, customer_id, is_active, created_at
        """, (username, email, hashed_password, full_name, role, customer_id, is_active))
        user = _map_user(cur.fetchone())
        conn.commit()
        return user
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()

def update_user(user_id, updates):
    """
    updates is a dict containing fields to update, e.g. {"full_name": "New Name"}
    """
    if not updates:
        return get_user_by_id(user_id)
        
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        set_clauses = []
        values = []
        for key, val in updates.items():
            set_clauses.append(f"{key} = %s")
            values.append(val)
        
        values.append(user_id)
        
        query = f"""
            UPDATE users
            SET {', '.join(set_clauses)}
            WHERE id = %s
            RETURNING id, username, email, full_name, role, customer_id, is_active, created_at
        """
        cur.execute(query, tuple(values))
        user = _map_user(cur.fetchone())
        conn.commit()
        return user
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()

def delete_user(user_id):
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()

def list_users(customer_id=None):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        if customer_id is not None:
            cur.execute("""
                SELECT id, username, email, full_name, role, customer_id, is_active, created_at
                FROM users
                WHERE customer_id = %s
                ORDER BY id
            """, (customer_id,))
        else:
            cur.execute("""
                SELECT id, username, email, full_name, role, customer_id, is_active, created_at
                FROM users
                ORDER BY id
            """)
        return [_map_user(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()
