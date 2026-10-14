from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user, require_roles
from pydantic import BaseModel
from app.ai.ollama_client import check_ollama_status, OLLAMA_URL, OLLAMA_MODEL, OLLAMA_FALLBACK_MODEL, OLLAMA_TIMEOUT, ask_mistral
from app.ai.prompts import SYSTEM_PROMPT
from app.ai.graph_rag import route_question, build_customer_profile
from app.database.connection import get_connection
import requests
import json
import math
import logging
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/ai",
    tags=["AI"]
)

@router.get("/status")
async def get_ai_status(current_user: dict = Depends(get_current_user)):
    status = check_ollama_status()
    if status.get("ollama_running"):
        return {
            "ollama_running": True,
            "model": OLLAMA_MODEL,
            "fallback_model": OLLAMA_FALLBACK_MODEL,
            "ollama_url": OLLAMA_URL,
            "timeout": OLLAMA_TIMEOUT,
            "response_time": status.get("response_time"),
            "available_models": status.get("available_models"),
            "primary_model_available": status.get("primary_model_available"),
            "fallback_model_available": status.get("fallback_model_available")
        }
    else:
        return {
            "ollama_running": False,
            "error": status.get("error", "Ollama service unavailable")
        }

class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    # Admin users may provide a different customer_id to query on behalf of that
    # customer. Non-admin users: this field is ignored; the JWT customer_id is
    # always used and any mismatch raises 403.
    selected_customer_id: Optional[int] = None

def get_embedding(text: str):
    response = requests.post(
        "http://localhost:11434/api/embeddings",
        json={"model": "nomic-embed-text", "prompt": text},
        timeout=30
    )
    response.raise_for_status()
    return response.json().get("embedding")

def cosine_similarity(v1, v2):
    dot = sum(a * b for a, b in zip(v1, v2))
    norm_v1 = math.sqrt(sum(a * a for a in v1))
    norm_v2 = math.sqrt(sum(b * b for b in v2))
    return dot / (norm_v1 * norm_v2) if norm_v1 and norm_v2 else 0.0

def is_cybersecurity_related(question: str) -> bool:
    """Pre-flight check to determine if a question is broadly related to cybersecurity or our platform."""
    q_lower = question.lower()
    security_keywords = [
        'technology', 'technologies', 'asset', 'assets', 'server', 'database', 
        'environment', 'infrastructure', 'software', 'hardware', 'version',
        'vulnerability', 'vulnerabilities', 'cve', 'risk', 'risks', 'threat', 'attack', 'exploit',
        'alert', 'alerts', 'incident', 'detect', 'remediation', 'mitigate',
        'assessment', 'audit', 'compliance', 'posture', 'security', 'cyber',
        'vendor', 'third party', 'third-party', 'supplier', 'supply chain',
        'mitre', 'att&ck', 'hacker', 'breach', 'ransomware', 'malware', 'phishing'
    ]
    
    # If it contains any security keywords, we allow it to proceed to the LLM
    if any(k in q_lower for k in security_keywords):
        return True
        
    return False

def ask_model(prompt: str, model: str):
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1
        }
    }
    res = requests.post(url, json=payload, timeout=60)
    res.raise_for_status()
    return res.json().get("response", "").strip()

@router.post("/chat")
async def chat_with_assistant(req: ChatRequest, current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    jwt_customer_id = current_user["customer_id"]
    user_id = current_user["id"]
    role = current_user["role"]

    # ── Resolve effective customer_id ──────────────────────────────────────
    if role == "Admin":
        # Admin may switch to any valid customer; default to own if not specified.
        effective_customer_id = req.selected_customer_id or jwt_customer_id
        if effective_customer_id != jwt_customer_id:
            # Validate the requested customer actually exists
            _conn = get_connection()
            _cur = _conn.cursor()
            _cur.execute("SELECT id FROM customers WHERE id = %s", (effective_customer_id,))
            if not _cur.fetchone():
                _cur.close()
                _conn.close()
                raise HTTPException(status_code=404, detail="Requested customer not found")
            _cur.close()
            _conn.close()
    else:
        # Non-admin: always use their JWT customer_id.
        # If they try to request a different customer, return 403.
        if req.selected_customer_id is not None and req.selected_customer_id != jwt_customer_id:
            raise HTTPException(status_code=403, detail="Not authorized to query AI context for another customer")
        effective_customer_id = jwt_customer_id

    customer_id = effective_customer_id
    conversation_id = req.conversation_id
    if conversation_id == 'legacy':
        conversation_id = None
    if not conversation_id:
        conversation_id = str(uuid.uuid4())

    conn = get_connection()
    cur = conn.cursor()
    try:
        logger.info("[AI CHAT DEBUG] User question: %s", req.message)
        
        # 1. Cybersecurity Relevance Check
        if not is_cybersecurity_related(req.message):
            logger.info("[AI CHAT DEBUG] Rejected by pre-flight relevance check.")
            refusal_msg = "I can only answer questions related to cybersecurity and third-party risk."
            
            cur.execute(
                "INSERT INTO chat_messages (user_id, customer_id, conversation_id, message, response) VALUES (%s, %s, %s, %s, %s) RETURNING id, created_at",
                (user_id, customer_id, conversation_id, req.message, refusal_msg)
            )
            inserted = cur.fetchone()
            conn.commit()
            return {
                "response": refusal_msg,
                "conversation_id": conversation_id,
                "chat_entry": {
                    "id": inserted[0],
                    "created_at": inserted[1].isoformat() if inserted and inserted[1] else None
                }
            }
            
        # 2. Structured RAG (Customer-Aware Graph RAG)
        intent = route_question(req.message)
        customer_profile_str = build_customer_profile(cur, customer_id, intent)
        
        logger.info("[AI CHAT DEBUG] Detected intent: %s", intent)
        logger.info("[AI CHAT DEBUG] Generated Graph RAG customer profile:\n%s", customer_profile_str)
        
        # 3. Semantic RAG (Original)
        q_emb = get_embedding(req.message)

        cur.execute("SELECT content_text, embedding FROM knowledge_chunks WHERE customer_id = %s", (customer_id,))
        rows = cur.fetchall()

        if not rows:
            # If no data at all for this customer, we can just supply empty context
            top_5 = []
        else:
            scored_chunks = []
            for content, emb_json in rows:
                score = cosine_similarity(q_emb, emb_json)
                scored_chunks.append((score, content))
            
            scored_chunks.sort(key=lambda x: x[0], reverse=True)
            top_5 = [c[1] for c in scored_chunks[:5]]

        context_str = "\n".join([f"- {c}" for c in top_5]) if top_5 else "No relevant context found."

        # Fallback check
        if customer_profile_str.strip() == "No architecture documents or technology inventory have been uploaded for this customer yet.":
            context_str = customer_profile_str
            prompt = f"""You are AI-TIP, a cybersecurity and third-party risk assistant for SOC analysts.

{customer_profile_str}

User Question: {req.message}

Assistant:"""
        else:
            prompt = f"""You are AI-TIP, a cybersecurity and third-party risk assistant for SOC analysts.

Answer cybersecurity and third-party risk questions directly and usefully. You can analyze vulnerabilities, explain security risks, recommend remediation, summarize assessments, discuss MITRE ATT&CK techniques, and answer questions about assets, alerts, vendors, and security posture.

Use the provided customer profile and semantic context when it is relevant to answer specific questions about the user's environment. Do not ask the user for their technologies; use the context provided.

{customer_profile_str}

## Additional Semantic Context
{context_str}

CRITICAL INSTRUCTION: You may answer questions about the customer's assets, deployed technologies, software versions, infrastructure inventory, vulnerabilities, CVEs, security posture, risks, alerts, assessments, vendors, third-party exposure, remediation, MITRE ATT&CK, and threat intelligence.
HOWEVER, if the User Question below is entirely unrelated to these topics (e.g., general knowledge, geography, weather, cooking, poems, writing code), you MUST refuse and reply EXACTLY with this phrase: "I can only answer questions related to cybersecurity and third-party risk." Do not provide the answer.

User Question: {req.message}

Assistant:"""

        logger.info("[AI CHAT DEBUG] Final prompt sent to Ollama: %s", prompt)
        ans = ask_model(prompt, "qwen2.5:0.5b")
        logger.info("[AI CHAT] Raw model response: %s", ans)

        cur.execute(
            "INSERT INTO chat_messages (user_id, customer_id, conversation_id, message, response) VALUES (%s, %s, %s, %s, %s) RETURNING id, created_at",
            (user_id, customer_id, conversation_id, req.message, ans)
        )
        inserted = cur.fetchone()
        conn.commit()

        return {
            "response": ans,
            "conversation_id": conversation_id,
            "effective_customer_id": effective_customer_id,
            "chat_entry": {
                "id": inserted[0],
                "created_at": inserted[1].isoformat() if inserted and inserted[1] else None
            }
        }
    except Exception as e:
        conn.rollback()
        import traceback
        err_msg = traceback.format_exc()
        raise HTTPException(status_code=500, detail=err_msg)
    finally:
        cur.close()
        conn.close()


@router.get("/conversations")
async def list_chat_conversations(current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    customer_id = current_user["customer_id"]
    user_id = current_user["id"]

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT COALESCE(conversation_id::text, 'legacy') AS conversation_id,
                   MIN(created_at) AS created_at,
                   MAX(created_at) AS last_updated,
                   MIN(message) AS first_message,
                   COUNT(*) AS message_count
            FROM chat_messages
            WHERE user_id = %s AND customer_id = %s
            GROUP BY COALESCE(conversation_id::text, 'legacy')
            ORDER BY last_updated DESC
            """,
            (user_id, customer_id)
        )
        rows = cur.fetchall()
        cur.close()
        conn.close()

        return {
            "conversations": [
                {
                    "conversation_id": row[0],
                    "id": row[0],
                    "title": ('Legacy chat history' if row[0] == 'legacy' else (row[3] or 'New conversation'))[:80],
                    "created_at": row[1].isoformat() if row[1] else None,
                    "last_updated": row[2].isoformat() if row[2] else None,
                    "message_count": row[4]
                }
                for row in rows
            ]
        }
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        raise HTTPException(status_code=500, detail=err_msg)


@router.get("/history")
async def get_chat_history(conversation_id: Optional[str] = None, current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    customer_id = current_user["customer_id"]
    user_id = current_user["id"]

    try:
        conn = get_connection()
        cur = conn.cursor()

        if not conversation_id:
            cur.execute(
                "SELECT COALESCE(conversation_id::text, 'legacy') FROM chat_messages WHERE user_id = %s AND customer_id = %s GROUP BY COALESCE(conversation_id::text, 'legacy') ORDER BY MAX(created_at) DESC LIMIT 1",
                (user_id, customer_id)
            )
            row = cur.fetchone()
            conversation_id = row[0] if row else None

        if conversation_id == 'legacy':
            cur.execute(
                "SELECT id, message, response, created_at FROM chat_messages WHERE user_id = %s AND customer_id = %s AND conversation_id IS NULL ORDER BY created_at ASC",
                (user_id, customer_id)
            )
        elif conversation_id:
            cur.execute(
                "SELECT id, message, response, created_at FROM chat_messages WHERE user_id = %s AND customer_id = %s AND conversation_id = %s ORDER BY created_at ASC",
                (user_id, customer_id, conversation_id)
            )
        else:
            cur.execute("SELECT id, message, response, created_at FROM chat_messages WHERE false")

        rows = cur.fetchall()
        cur.close()
        conn.close()

        return {
            "conversation_id": conversation_id,
            "history": [
                {
                    "id": row[0],
                    "message": row[1],
                    "response": row[2],
                    "created_at": row[3].isoformat() if row[3] else None
                }
                for row in rows
            ]
        }
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        raise HTTPException(status_code=500, detail=err_msg)


@router.delete("/history")
async def clear_chat_history(conversation_id: Optional[str] = None, current_user: dict = Depends(require_roles("Admin", "Analyst"))):
    customer_id = current_user["customer_id"]
    user_id = current_user["id"]

    if not conversation_id:
        raise HTTPException(status_code=400, detail="conversation_id is required to delete a conversation")

    if conversation_id == 'legacy':
        delete_query = "DELETE FROM chat_messages WHERE user_id = %s AND customer_id = %s AND conversation_id IS NULL"
        delete_params = (user_id, customer_id)
    else:
        delete_query = "DELETE FROM chat_messages WHERE user_id = %s AND customer_id = %s AND conversation_id = %s"
        delete_params = (user_id, customer_id, conversation_id)

    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(delete_query, delete_params)
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()

        return {
            "deleted": deleted
        }
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        raise HTTPException(status_code=500, detail=err_msg)
