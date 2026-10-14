import { useAuth } from "./AuthContext";
import LoginPage from "./LoginPage";

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen bg-void" />;
  return user ? children : <LoginPage />;
}
