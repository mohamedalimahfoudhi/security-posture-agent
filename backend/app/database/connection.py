import os
import logging
from dotenv import load_dotenv
import psycopg2
import psycopg2.extras

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


def get_connection():
    """
    Creates a connection to the PostgreSQL database using environment variables.
    """

    # Get database configuration from environment variables
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "ai_tip")
    db_user = os.getenv("DB_USER", "postgres")
    db_password = os.getenv("DB_PASSWORD")

    logger.debug(f"Connecting to PostgreSQL: host={db_host}, port={db_port}, database={db_name}, user={db_user}")

    try:
        conn = psycopg2.connect(
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_password,
            connect_timeout=10
        )
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise e

    conn.set_client_encoding('UTF8')
    logger.debug("Database connection successful")
    return conn