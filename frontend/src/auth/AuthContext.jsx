import { createContext, useContext, useEffect, useState } from "react";
import { API_URL, apiFetch } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const logout = () => {
    localStorage.removeItem("access_token");
    setUser(null);
  };

  const loadUser = async () => {
    if (!localStorage.getItem("access_token")) {
      setLoading(false);
      return;
    }
    try {
      const response = await apiFetch("/api/auth/me");
      if (!response.ok) throw new Error("Session expired");
      setUser(await response.json());
    } catch {
      logout();
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUser();
    window.addEventListener("auth:expired", logout);
    return () => window.removeEventListener("auth:expired", logout);
  }, []);

  const login = async (username, password) => {
    const body = new URLSearchParams({ username, password });
    const url = `${API_URL}/api/auth/login`;
    console.log('[AuthContext] Login attempt to:', url);
    console.log('[AuthContext] API_URL:', API_URL);
    try {
      const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
      console.log('[AuthContext] Response status:', response.status);
      if (!response.ok) {
        const errorText = await response.text();
        console.error('[AuthContext] Login failed:', response.status, errorText);
        throw new Error(`Login failed: ${response.status} - ${errorText}`);
      }
      const token = await response.json();
      console.log('[AuthContext] Login successful, token received');
      localStorage.setItem("access_token", token.access_token);
      await loadUser();
    } catch (err) {
      console.error('[AuthContext] Login error:', err);
      throw err;
    }
  };

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
