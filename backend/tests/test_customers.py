import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.auth.security import create_access_token
from app.database.connection import get_connection

client = TestClient(app)

class TestCustomersAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # We need an admin token and a non-admin token.
        # We can just mint JWT tokens directly since we don't need real users for the endpoints, 
        # except that auth/deps.py might fetch the user.
        # Let's create actual users to be safe.
        conn = get_connection()
        cur = conn.cursor()
        
        # Create a test customer for users
        cur.execute("INSERT INTO customers (name) VALUES ('Test Customer API') RETURNING id")
        cls.test_cust_id = cur.fetchone()[0]
        
        cur.execute("""
            INSERT INTO users (username, email, hashed_password, full_name, role, customer_id)
            VALUES ('admin_test_api', 'admin@testapi.com', 'hash', 'Admin', 'Admin', %s) RETURNING id
        """, (cls.test_cust_id,))
        cls.admin_id = cur.fetchone()[0]
        
        cur.execute("""
            INSERT INTO users (username, email, hashed_password, full_name, role, customer_id)
            VALUES ('analyst_test_api', 'analyst@testapi.com', 'hash', 'Analyst', 'Analyst', %s) RETURNING id
        """, (cls.test_cust_id,))
        cls.analyst_id = cur.fetchone()[0]
        
        conn.commit()
        cur.close()
        conn.close()
        
        cls.admin_token = create_access_token({"sub": str(cls.admin_id)})
        cls.analyst_token = create_access_token({"sub": str(cls.analyst_id)})
        
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}
        cls.analyst_headers = {"Authorization": f"Bearer {cls.analyst_token}"}

    @classmethod
    def tearDownClass(cls):
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id IN (%s, %s)", (cls.admin_id, cls.analyst_id))
        cur.execute("DELETE FROM customers WHERE id = %s", (cls.test_cust_id,))
        conn.commit()
        cur.close()
        conn.close()

    def test_01_admin_create_customer(self):
        payload = {"name": "Test Create Customer", "industry": "Finance"}
        response = client.post("/api/customers/", json=payload, headers=self.admin_headers)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("id", data)
        self.assertEqual(data["name"], "Test Create Customer")
        self.assertEqual(data["industry"], "Finance")
        self.__class__.created_cust_id = data["id"]

    def test_02_admin_rename_customer(self):
        cust_id = self.__class__.created_cust_id
        payload = {"name": "Test Rename Customer", "industry": "Healthcare"}
        response = client.patch(f"/api/customers/{cust_id}", json=payload, headers=self.admin_headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "Test Rename Customer")
        self.assertEqual(data["industry"], "Healthcare")

    def test_03_non_admin_cannot_create(self):
        payload = {"name": "Hacker Customer"}
        response = client.post("/api/customers/", json=payload, headers=self.analyst_headers)
        self.assertEqual(response.status_code, 403)

    def test_04_non_admin_cannot_rename(self):
        cust_id = self.__class__.created_cust_id
        payload = {"name": "Hacked Rename"}
        response = client.patch(f"/api/customers/{cust_id}", json=payload, headers=self.analyst_headers)
        self.assertEqual(response.status_code, 403)

    def test_05_non_admin_cannot_delete(self):
        cust_id = self.__class__.created_cust_id
        response = client.delete(f"/api/customers/{cust_id}", headers=self.analyst_headers)
        self.assertEqual(response.status_code, 403)

    def test_06_admin_delete_customer(self):
        cust_id = self.__class__.created_cust_id
        
        # Give it a dependency to ensure it deletes correctly
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO documents (customer_id, filename, file_type, file_size, file_path) VALUES (%s, 'Test Doc', 'pdf', 1024, '/test/path')", (cust_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        response = client.delete(f"/api/customers/{cust_id}", headers=self.admin_headers)
        self.assertEqual(response.status_code, 204)
        
        # Verify it's gone
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM customers WHERE id = %s", (cust_id,))
        self.assertEqual(cur.fetchone()[0], 0)
        
        # Verify dependency is gone
        cur.execute("SELECT COUNT(*) FROM documents WHERE customer_id = %s", (cust_id,))
        self.assertEqual(cur.fetchone()[0], 0)
        
        cur.close()
        conn.close()

if __name__ == "__main__":
    unittest.main()
