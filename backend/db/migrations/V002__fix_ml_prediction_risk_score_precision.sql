-- Increase risk_score precision to support the full 0–100 range.
-- Existing records are preserved.

BEGIN;

ALTER TABLE public.ml_predictions
    ALTER COLUMN risk_score TYPE NUMERIC(9, 6);

COMMIT;
