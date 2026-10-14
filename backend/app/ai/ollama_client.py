import requests
import os
import time
import logging

logger = logging.getLogger(__name__)

# Load environment variables from .env file manually since python-dotenv is not installed
def load_dotenv_manually():
    # Try looking in the directory of the file itself or parent/grandparent, and fallback to CWD
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        ".env"
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, val = line.split("=", 1)
                            # Strip quotes if present
                            val = val.strip().strip("'\"")
                            # Preserve explicitly supplied process settings (for
                            # deployments and isolated test databases), matching
                            # python-dotenv's default non-overriding behavior.
                            os.environ.setdefault(key.strip(), val)
                logger.info(f"[ENV] Successfully loaded configuration from {path}")
                break
            except Exception as e:
                logger.warning(f"[ENV] Failed to read env file at {path}: {e}")

load_dotenv_manually()

# Environment configuration
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))
OLLAMA_CONNECT_TIMEOUT = int(os.getenv("OLLAMA_CONNECT_TIMEOUT", "5"))
OLLAMA_READ_TIMEOUT = int(os.getenv("OLLAMA_READ_TIMEOUT", "60"))
OLLAMA_FALLBACK_MODEL = os.getenv("OLLAMA_FALLBACK_MODEL", "phi3:mini")

logger.info(f"[OLLAMA CONFIG] URL: {OLLAMA_URL}")
logger.info(f"[OLLAMA CONFIG] Primary model: {OLLAMA_MODEL}")
logger.info(f"[OLLAMA CONFIG] Fallback model: {OLLAMA_FALLBACK_MODEL}")
logger.info(f"[OLLAMA CONFIG] Connect timeout: {OLLAMA_CONNECT_TIMEOUT}s")
logger.info(f"[OLLAMA CONFIG] Read timeout: {OLLAMA_READ_TIMEOUT}s")


def _model_available(model_name, available_models):
    """Check if a model is available using prefix matching.
    
    Ollama returns full names like 'mistral:latest' but users configure
    short names like 'mistral'. This matches by prefix.
    """
    for available in available_models:
        if available == model_name or available.startswith(model_name + ":"):
            return True
    return False


def check_ollama_status():
    """Check if Ollama is running and available"""
    try:
        start_time = time.time()
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=10)
        response_time = time.time() - start_time
        
        if response.status_code == 200:
            models = response.json().get("models", [])
            available_models = [model.get("name", "") for model in models]
            
            return {
                "ollama_running": True,
                "model": OLLAMA_MODEL,
                "fallback_model": OLLAMA_FALLBACK_MODEL,
                "response_time": f"{response_time:.2f}s",
                "available_models": available_models,
                "primary_model_available": _model_available(OLLAMA_MODEL, available_models),
                "fallback_model_available": _model_available(OLLAMA_FALLBACK_MODEL, available_models)
            }
        else:
            return {
                "ollama_running": False,
                "error": f"Ollama returned status {response.status_code}"
            }
    except requests.exceptions.ConnectionError:
        return {
            "ollama_running": False,
            "error": "Cannot connect to Ollama service"
        }
    except requests.exceptions.Timeout:
        return {
            "ollama_running": False,
            "error": "Connection to Ollama timed out"
        }
    except Exception as e:
        return {
            "ollama_running": False,
            "error": f"Unexpected error: {str(e)}"
        }


def ask_mistral(prompt, model=None, timeout=None):
    """Send prompt to Ollama model with error handling and logging.
    
    Returns:
        dict: {"response": str, "model": str, "duration": float}
    """
    
    # Use provided model or default
    target_model = model or OLLAMA_MODEL
    
    # Normalize timeout: accept scalar or (connect, read) tuple
    if timeout:
        # If already a tuple (connect, read), use it directly
        if isinstance(timeout, tuple):
            target_timeout = timeout
        else:
            # Single timeout value - use for both connect and read
            target_timeout = (timeout, timeout)
    else:
        # Use configured separate timeouts
        target_timeout = (OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT)
    
    logger.info(f"[OLLAMA] ========================================")
    logger.info(f"[OLLAMA] Connecting to {OLLAMA_URL}")
    logger.info(f"[OLLAMA] Model: {target_model}")
    logger.info(f"[OLLAMA] Connect timeout: {target_timeout[0]}s")
    logger.info(f"[OLLAMA] Read timeout: {target_timeout[1]}s")
    logger.info(f"[OLLAMA] Sending extraction request")
    logger.info(f"[OLLAMA] Prompt length: {len(prompt)} characters")
    
    start_time = time.time()
    
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": target_model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "num_predict": 1500,   # Limit response tokens for speed
                    "temperature": 0.3,    # Lower temperature for more deterministic JSON
                    "num_ctx": 4096,       # Limit context window to prevent slow inference
                }
            },
            timeout=target_timeout
        )
        
        duration = time.time() - start_time
        logger.info(f"[OLLAMA] Response received in {duration:.1f}s")
        logger.info(f"[OLLAMA] Status code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            ai_response = result.get("response", "")
            logger.info(f"[OLLAMA] Response length: {len(ai_response)} characters")
            logger.info(f"[OLLAMA] ========================================")
            return {
                "response": ai_response,
                "model": target_model,
                "duration": round(duration, 2)
            }
        else:
            error_msg = f"Ollama returned status {response.status_code}: {response.text}"
            logger.error(f"[OLLAMA] ✗ {error_msg}")
            logger.error(f"[OLLAMA] ========================================")
            raise Exception(error_msg)
            
    except requests.exceptions.Timeout as e:
        duration = time.time() - start_time
        error_msg = f"Ollama request timed out after {duration:.1f}s (connect={target_timeout[0]}s, read={target_timeout[1]}s)"
        logger.error(f"[OLLAMA] ✗ {error_msg}")
        logger.error(f"[OLLAMA] Connection failed: {OLLAMA_URL}")
        logger.error(f"[OLLAMA] Make sure the Ollama server is running.")
        logger.error(f"[OLLAMA] AI enrichment will use deterministic fallback.")
        logger.error(f"[OLLAMA] ========================================")
        raise Exception(error_msg)
        
    except requests.exceptions.ConnectionError as e:
        duration = time.time() - start_time
        error_msg = f"Cannot connect to Ollama at {OLLAMA_URL} after {duration:.1f}s: {str(e)}"
        logger.error(f"[OLLAMA] ✗ {error_msg}")
        logger.error(f"[OLLAMA] Connection failed: {OLLAMA_URL}")
        logger.error(f"[OLLAMA] Make sure the Ollama server is running.")
        logger.error(f"[OLLAMA] AI enrichment will use deterministic fallback.")
        logger.error(f"[OLLAMA] ========================================")
        raise Exception(error_msg)
        
    except requests.exceptions.RequestException as e:
        duration = time.time() - start_time
        error_msg = f"Ollama request failed after {duration:.1f}s: {str(e)}"
        logger.error(f"[OLLAMA] ✗ {error_msg}")
        logger.error(f"[OLLAMA] ========================================")
        raise Exception(error_msg)
        
    except Exception as e:
        duration = time.time() - start_time
        # Re-raise if it's already our exception (avoid wrapping)
        if "Ollama" in str(e):
            raise
        error_msg = f"Ollama request failed after {duration:.1f}s: {str(e)}"
        logger.error(f"[OLLAMA] ✗ {error_msg}")
        logger.error(f"[OLLAMA] ========================================")
        raise Exception(error_msg)


def ask_mistral_with_fallback(prompt, timeout=None):
    """Try primary model, fallback to secondary if it fails.
    
    Returns:
        dict: {"response": str, "model": str, "duration": float}
    """
    
    # Use separate connect/read timeouts for faster failure detection
    # If caller provides a timeout, use it for both connect and read
    # Otherwise use the configured separate timeouts
    if timeout:
        # Caller provided a single timeout - convert to tuple for both connect and read
        primary_timeout = (timeout, timeout)
        fallback_timeout = (timeout, timeout)
    else:
        # Use configured separate timeouts - pass as tuple directly
        primary_timeout = (OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT)
        fallback_timeout = (OLLAMA_CONNECT_TIMEOUT, OLLAMA_READ_TIMEOUT)
    
    # Try primary model first
    try:
        if isinstance(primary_timeout, tuple):
            logger.info(f"[OLLAMA] Trying primary model: {OLLAMA_MODEL} with timeout (connect={primary_timeout[0]}s, read={primary_timeout[1]}s)")
        else:
            logger.info(f"[OLLAMA] Trying primary model: {OLLAMA_MODEL} with timeout {primary_timeout}s")
        return ask_mistral(prompt, model=OLLAMA_MODEL, timeout=primary_timeout)
    except Exception as e:
        logger.warning(f"[OLLAMA] {OLLAMA_MODEL} failed: {e}")
        logger.info(f"[OLLAMA] Switching to fallback model: {OLLAMA_FALLBACK_MODEL}")
        
        try:
            if isinstance(fallback_timeout, tuple):
                logger.info(f"[OLLAMA] Trying fallback model: {OLLAMA_FALLBACK_MODEL} with timeout (connect={fallback_timeout[0]}s, read={fallback_timeout[1]}s)")
            else:
                logger.info(f"[OLLAMA] Trying fallback model: {OLLAMA_FALLBACK_MODEL} with timeout {fallback_timeout}s")
            return ask_mistral(prompt, model=OLLAMA_FALLBACK_MODEL, timeout=fallback_timeout)
        except Exception as fallback_error:
            error_msg = f"Both primary ({OLLAMA_MODEL}) and fallback ({OLLAMA_FALLBACK_MODEL}) models failed"
            logger.error(f"[OLLAMA] ✗ {error_msg}")
            logger.error(f"[OLLAMA] Primary error: {e}")
            logger.error(f"[OLLAMA] Fallback error: {fallback_error}")
            raise Exception(error_msg)
