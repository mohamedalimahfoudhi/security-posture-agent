from fastapi import APIRouter, Depends
from app.auth.deps import get_current_user
from app.database.connection import get_connection


router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"]
)


@router.get("/summary")
def dashboard_summary(current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT

            COUNT(*) FILTER (
                WHERE a.severity = 'CRITICAL'
            ),

            COUNT(*) FILTER (
                WHERE a.severity = 'HIGH'
            ),

            COUNT(*),

            AVG(a.risk_score)

        FROM assessments a
        INNER JOIN assets ast ON a.asset_id = ast.id
        WHERE a.customer_id = %s;
        """, (current_user["customer_id"],)
    )

    result = cur.fetchone()

    cur.close()
    conn.close()

    return {
        "critical_threats": result[0],
        "high_threats": result[1],
        "total_assessments": result[2],
        "average_risk_score":
            round(result[3], 2)
            if result[3]
            else 0
    }
