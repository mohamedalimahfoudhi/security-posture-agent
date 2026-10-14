from fastapi import APIRouter, Depends, HTTPException
from app.auth.deps import get_current_user
from app.database.connection import get_connection
from pydantic import BaseModel
from typing import List, Optional
import psycopg2.extras

router = APIRouter(
    prefix="/api/notifications",
    tags=["Notifications"]
)


class NotificationRecipient(BaseModel):
    id: Optional[int] = None
    customer_id: int
    name: str
    email: str
    created_at: Optional[str] = None


class NotificationDraft(BaseModel):
    id: Optional[int] = None
    alert_id: int
    subject: str
    body: str
    status: str = "draft"
    created_at: Optional[str] = None
    sent_at: Optional[str] = None


@router.get("/recipients")
def get_recipients(current_user: dict = Depends(get_current_user)):
    """Get all notification recipients for the current user's customer"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT id, customer_id, name, email, created_at
        FROM notification_recipients
        WHERE customer_id = %s
        ORDER BY name
    """, (current_user["customer_id"],))
    
    recipients = cursor.fetchall()
    conn.close()
    
    return recipients


@router.post("/recipients")
def create_recipient(recipient: NotificationRecipient, current_user: dict = Depends(get_current_user)):
    """Create a new notification recipient"""
    if recipient.customer_id != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Can only create recipients for your own customer")
    
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        INSERT INTO notification_recipients (customer_id, name, email)
        VALUES (%s, %s, %s)
        RETURNING id, customer_id, name, email, created_at
    """, (recipient.customer_id, recipient.name, recipient.email))
    
    new_recipient = cursor.fetchone()
    conn.commit()
    conn.close()
    
    return new_recipient


@router.delete("/recipients/{recipient_id}")
def delete_recipient(recipient_id: int, current_user: dict = Depends(get_current_user)):
    """Delete a notification recipient"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Verify recipient belongs to user's customer
    cursor.execute("""
        SELECT customer_id FROM notification_recipients
        WHERE id = %s
    """, (recipient_id,))
    
    recipient = cursor.fetchone()
    
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    if recipient["customer_id"] != current_user["customer_id"]:
        raise HTTPException(status_code=403, detail="Can only delete recipients for your own customer")
    
    cursor.execute("""
        DELETE FROM notification_recipients
        WHERE id = %s
    """, (recipient_id,))
    
    conn.commit()
    conn.close()
    
    return {"message": "Recipient deleted successfully"}


@router.get("/drafts")
def get_drafts(current_user: dict = Depends(get_current_user)):
    """Get all notification drafts for the current user's customer"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT nd.id, nd.alert_id, nd.subject, nd.body, nd.status, nd.created_at, nd.sent_at,
               a.title as alert_title, a.risk_level as alert_risk_level
        FROM notification_drafts nd
        JOIN alerts a ON nd.alert_id = a.id
        JOIN customers c ON a.customer_id = c.id
        WHERE c.id = %s
        ORDER BY nd.created_at DESC
    """, (current_user["customer_id"],))
    
    drafts = cursor.fetchall()
    conn.close()
    
    return drafts


@router.get("/drafts/{draft_id}")
def get_draft(draft_id: int, current_user: dict = Depends(get_current_user)):
    """Get a specific notification draft/history entry"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    cursor.execute("""
        SELECT nd.id, nd.alert_id, nd.subject, nd.body, nd.status, nd.created_at, nd.sent_at,
               a.title as alert_title, a.risk_level as alert_risk_level
        FROM notification_drafts nd
        JOIN alerts a ON nd.alert_id = a.id
        JOIN customers c ON a.customer_id = c.id
        WHERE nd.id = %s AND c.id = %s
    """, (draft_id, current_user["customer_id"]))
    
    draft = cursor.fetchone()
    conn.close()
    
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")
    
    return draft
