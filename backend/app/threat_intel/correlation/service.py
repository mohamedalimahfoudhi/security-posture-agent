import json
from typing import Any, Dict, List

from app.database.connection import get_connection
from app.threat_intel.correlation.matcher import match_article_to_assets


class ThreatIntelCorrelationService:
    def correlate_customer_articles(
        self,
        customer_id: int,
        limit: int = 20,
        force: bool = False
    ) -> Dict[str, int]:
        conn = get_connection()
        cur = conn.cursor()

        try:
            if force:
                cur.execute(
                    "DELETE FROM threat_correlations WHERE customer_id = %s",
                    (customer_id,)
                )

            cur.execute(
                """
                SELECT id, title, summary, vendors, products, cves,
                       severity, confidence, recommendation
                FROM threat_articles
                WHERE processed = TRUE
                  AND id NOT IN (
                    SELECT article_id
                    FROM threat_correlations
                    WHERE customer_id = %s
                  )
                ORDER BY published_date DESC NULLS LAST, created_at DESC
                LIMIT %s
                """,
                (customer_id, limit),
            )
            rows = cur.fetchall()

            correlations_created = 0
            for row in rows:
                article_id = row[0]
                article = {
                    "id": article_id,
                    "title": row[1] or "",
                    "summary": row[2] or "",
                    "vendors": row[3] or [],
                    "products": row[4] or [],
                    "cves": row[5] or [],
                    "severity": row[6] or "",
                    "confidence": row[7] or 0.0,
                    "recommendation": row[8] or "",
                }

                matches = match_article_to_assets(customer_id, article)
                for match in matches:
                    cur.execute(
                        """
                        INSERT INTO threat_correlations
                        (article_id, customer_id, asset_id, match_type, match_text,
                         matched_value, reason, correlation_score, risk_score,
                         priority, correlation_details, severity, confidence,
                         recommendation, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        """,
                        (
                            article_id,
                            customer_id,
                            match["asset_id"],
                            match["match_type"],
                            match["match_text"],
                            match.get("matched_value"),
                            match.get("reason"),
                            match["correlation_score"],
                            match["risk_score"],
                            match["priority"],
                            json.dumps(match["correlation_details"]),
                            article.get("severity"),
                            article.get("confidence"),
                            article.get("recommendation"),
                        ),
                    )
                    correlations_created += 1

            conn.commit()
            return {
                "processed_articles": len(rows),
                "correlations_created": correlations_created,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

    def list_correlations(self, customer_id: int, page: int = 1, limit: int = 20) -> Dict[str, Any]:
        offset = max((page - 1) * limit, 0)
        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute(
                "SELECT COUNT(*) FROM threat_correlations WHERE customer_id = %s",
                (customer_id,),
            )
            total = cur.fetchone()[0]

            cur.execute(
                """
                SELECT tc.id, tc.article_id, ta.title, tc.asset_id, a.technology, a.vendor,
                       a.version, tc.match_type, tc.match_text, tc.correlation_score,
                       tc.risk_score, tc.priority, tc.correlation_details, tc.reason, tc.created_at
                FROM threat_correlations tc
                LEFT JOIN threat_articles ta ON ta.id = tc.article_id
                LEFT JOIN assets a ON a.id = tc.asset_id
                WHERE tc.customer_id = %s
                ORDER BY tc.created_at DESC
                LIMIT %s OFFSET %s
                """,
                (customer_id, limit, offset),
            )
            rows = cur.fetchall()

            correlations: List[Dict[str, Any]] = []
            for row in rows:
                correlations.append(
                    {
                        "id": row[0],
                        "article_id": row[1],
                        "article_title": row[2],
                        "asset_id": row[3],
                        "asset_technology": row[4],
                        "asset_vendor": row[5],
                        "asset_version": row[6],
                        "match_type": row[7],
                        "match_text": row[8],
                        "correlation_score": row[9],
                        "risk_score": row[10],
                        "priority": row[11],
                        "correlation_details": row[12] or {},
                        "reason": row[13],
                        "created_at": row[14],
                    }
                )

            return {
                "page": page,
                "limit": limit,
                "total": total,
                "correlations": correlations,
            }
        finally:
            cur.close()
            conn.close()
