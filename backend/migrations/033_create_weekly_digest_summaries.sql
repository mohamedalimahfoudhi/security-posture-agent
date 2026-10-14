-- Create weekly_digest_summaries table for caching AI-generated digest analysis
CREATE TABLE IF NOT EXISTS weekly_digest_summaries (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    executive_summary TEXT NOT NULL,
    recommendations JSONB NOT NULL,
    future_outlook TEXT NOT NULL,
    generated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(customer_id, period_start, period_end)
);

-- Create index for faster lookup by customer and period
CREATE INDEX IF NOT EXISTS idx_weekly_digest_summaries_customer_period 
    ON weekly_digest_summaries(customer_id, period_start, period_end);
