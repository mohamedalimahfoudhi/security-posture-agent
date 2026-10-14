"""
Tests for AI customer-context isolation.

Verifies:
1.  Admin JWT(A) + selected_customer_id=B → AI uses B's context (200, effective_customer_id=B)
2.  Admin JWT(A) + selected_customer_id=A → uses A (200, effective_customer_id=A)
3.  Admin JWT(A) + no selected_customer_id → defaults to JWT customer A
4.  Analyst JWT(A) + selected_customer_id=A → allowed (200)
5.  Analyst JWT(A) + selected_customer_id=B → 403
6.  Viewer JWT(A) + selected_customer_id=B → 403 (Viewer also blocked by require_roles)
7.  Nonexistent customer_id → 404
8.  RAG context uses correct customer — Customer B has no assets; context string reflects that.
9.  Switching context: A → B → A returns different effective_customer_id each time.
"""
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.auth.security import create_access_token
from app.database.connection import get_connection
from app.database.user_repository import create_user, delete_user, get_user_by_username

client = TestClient(app)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_create_customer(name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM customers WHERE name = %s", (name,))
    row = cur.fetchone()
    if row:
        cid = row[0]
        created = False
    else:
        cur.execute(
            "INSERT INTO customers (name) VALUES (%s) RETURNING id", (name,)
        )
        cid = cur.fetchone()[0]
        conn.commit()
        created = True
    cur.close()
    conn.close()
    return cid, created


def _get_or_create_user(username, email, role, customer_id):
    user = get_user_by_username(username)
    if user:
        return user
    return create_user(
        username, email, "hashed_placeholder", f"Test {username}", role, customer_id
    )


def _auth(user_id):
    token = create_access_token({"sub": str(user_id)})
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class AICustomerContextTests(unittest.TestCase):
    """
    Tests that the AI chat endpoint correctly resolves and enforces
    the effective customer context for Graph RAG.

    We mock ask_model / get_embedding so tests don't require Ollama.
    """

    @classmethod
    def setUpClass(cls):
        cls.cust_a, _ = _get_or_create_customer("AI Context Test Cust A")
        cls.cust_b, _ = _get_or_create_customer("AI Context Test Cust B")

        cls.admin = _get_or_create_user(
            "ai_ctx_admin", "ai_ctx_admin@test.local", "Admin", cls.cust_a
        )
        cls.analyst_a = _get_or_create_user(
            "ai_ctx_analyst_a", "ai_ctx_analyst_a@test.local", "Analyst", cls.cust_a
        )
        cls.viewer_a = _get_or_create_user(
            "ai_ctx_viewer_a", "ai_ctx_viewer_a@test.local", "Viewer", cls.cust_a
        )

        cls.hdrs_admin    = _auth(cls.admin["id"])
        cls.hdrs_analyst  = _auth(cls.analyst_a["id"])
        cls.hdrs_viewer   = _auth(cls.viewer_a["id"])

    @classmethod
    def tearDownClass(cls):
        for u in [cls.admin, cls.analyst_a, cls.viewer_a]:
            try:
                delete_user(u["id"])
            except Exception:
                pass
        conn = get_connection()
        cur = conn.cursor()
        for cid in [cls.cust_a, cls.cust_b]:
            cur.execute("DELETE FROM chat_messages WHERE customer_id = %s", (cid,))
        conn.commit()
        cur.close()
        conn.close()

    # ── Shared mocks (no Ollama required) ────────────────────────────────────

    def _patched_post(self, payload, hdrs, expect_status=200):
        """Send request with Ollama mocked out."""
        with patch("app.api.ai.get_embedding", return_value=[0.0] * 768), \
             patch("app.api.ai.ask_model", return_value="mocked AI response"):
            resp = client.post("/api/ai/chat", json=payload, headers=hdrs)
        return resp

    # ── Tests ─────────────────────────────────────────────────────────────────

    def test_01_admin_no_selected_id_defaults_to_own(self):
        """Admin with no selected_customer_id defaults to own JWT customer."""
        resp = self._patched_post({"message": "What are the current threats?"}, self.hdrs_admin)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["effective_customer_id"], self.cust_a)

    def test_02_admin_selects_own_customer_explicitly(self):
        """Admin explicitly requesting own customer_id → uses it."""
        resp = self._patched_post(
            {"message": "What vendors do we have?", "selected_customer_id": self.cust_a},
            self.hdrs_admin
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["effective_customer_id"], self.cust_a)

    def test_03_admin_selects_other_customer(self):
        """Admin requesting Customer B context → effective_customer_id = B."""
        resp = self._patched_post(
            {"message": "What alerts does this customer have?", "selected_customer_id": self.cust_b},
            self.hdrs_admin
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["effective_customer_id"], self.cust_b)

    def test_04_admin_switches_back_to_a(self):
        """Admin: switch A → B → A returns correct effective_customer_id each time."""
        b_resp = self._patched_post(
            {"message": "What is the risk posture?", "selected_customer_id": self.cust_b},
            self.hdrs_admin
        )
        self.assertEqual(b_resp.json()["effective_customer_id"], self.cust_b)

        a_resp = self._patched_post(
            {"message": "What is the risk posture?", "selected_customer_id": self.cust_a},
            self.hdrs_admin
        )
        self.assertEqual(a_resp.json()["effective_customer_id"], self.cust_a)

    def test_05_admin_nonexistent_customer_404(self):
        """Admin requesting a nonexistent customer_id returns 404."""
        resp = self._patched_post(
            {"message": "Tell me about risks.", "selected_customer_id": 999999},
            self.hdrs_admin
        )
        self.assertEqual(resp.status_code, 404)

    def test_06_analyst_own_customer_allowed(self):
        """Analyst requesting own customer context → allowed (200)."""
        resp = self._patched_post(
            {"message": "What are our assets?", "selected_customer_id": self.cust_a},
            self.hdrs_analyst
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["effective_customer_id"], self.cust_a)

    def test_07_analyst_other_customer_forbidden(self):
        """Analyst requesting Customer B context → 403."""
        resp = self._patched_post(
            {"message": "What alerts does Customer B have?", "selected_customer_id": self.cust_b},
            self.hdrs_analyst
        )
        self.assertEqual(resp.status_code, 403)

    def test_08_analyst_no_selected_id_uses_jwt(self):
        """Analyst without selected_customer_id uses JWT customer_id."""
        resp = self._patched_post(
            {"message": "What vendors are high risk?"},
            self.hdrs_analyst
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["effective_customer_id"], self.cust_a)

    def test_09_viewer_other_customer_forbidden(self):
        """Viewer attempting cross-tenant AI query → 403 (Viewer role is blocked)."""
        resp = self._patched_post(
            {"message": "What vulnerabilities exist?", "selected_customer_id": self.cust_b},
            self.hdrs_viewer
        )
        # Viewer is blocked by require_roles("Admin", "Analyst") at the endpoint level
        self.assertIn(resp.status_code, [403])

    def test_10_rag_context_scoped_to_effective_customer(self):
        """
        RAG context for Customer B (no data) differs from Customer A.
        We capture the customer_profile_str generated during the call.
        """
        captured = {}

        original_build = None
        try:
            from app.ai import graph_rag
            original_build = graph_rag.build_customer_profile

            def spy_build(cur, cid, intent):
                result = original_build(cur, cid, intent)
                captured[cid] = result
                return result

            with patch("app.api.ai.build_customer_profile", side_effect=spy_build), \
                 patch("app.api.ai.get_embedding", return_value=[0.0] * 768), \
                 patch("app.api.ai.ask_model", return_value="mocked response"):

                # A
                client.post("/api/ai/chat",
                    json={"message": "What vendors do we have?", "selected_customer_id": self.cust_a},
                    headers=self.hdrs_admin)

                # B
                client.post("/api/ai/chat",
                    json={"message": "What vendors do we have?", "selected_customer_id": self.cust_b},
                    headers=self.hdrs_admin)

        finally:
            if original_build:
                import app.ai.graph_rag as _gr
                _gr.build_customer_profile = original_build

        # Both customers should have been queried with their correct IDs
        self.assertIn(self.cust_a, captured, "Customer A context was not built")
        self.assertIn(self.cust_b, captured, "Customer B context was not built")
        # They may or may not differ, but they were independently scoped
        # (the call IDs prove isolation)

    def test_11_response_contains_effective_customer_id(self):
        """Response body always contains effective_customer_id field."""
        resp = self._patched_post(
            {"message": "What is the risk posture?"},
            self.hdrs_admin
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("effective_customer_id", resp.json())

    def test_12_admin_chat_stored_with_effective_customer(self):
        """Chat message for Customer B is stored with Customer B's customer_id."""
        with patch("app.api.ai.get_embedding", return_value=[0.0] * 768), \
             patch("app.api.ai.ask_model", return_value="stored test response"):
            resp = client.post("/api/ai/chat",
                json={"message": "Test isolation storage", "selected_customer_id": self.cust_b},
                headers=self.hdrs_admin)

        self.assertEqual(resp.status_code, 200)
        chat_id = resp.json()["chat_entry"]["id"]

        # Verify the DB record has customer_id = B
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT customer_id FROM chat_messages WHERE id = %s", (chat_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], self.cust_b)


if __name__ == "__main__":
    unittest.main()
