
-- Add a stable unique identifier to collector network flows.
-- Existing network flow records are preserved and backfilled.

BEGIN;

ALTER TABLE public.network_flows
    ADD COLUMN event_id UUID;

UPDATE public.network_flows
SET event_id = gen_random_uuid()
WHERE event_id IS NULL;

ALTER TABLE public.network_flows
    ALTER COLUMN event_id SET NOT NULL;

ALTER TABLE public.network_flows
    ADD CONSTRAINT uq_network_flows_event_id
    UNIQUE (event_id);

COMMIT;
