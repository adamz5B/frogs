-- The id parameter is bound from `sources.order.id` (see
-- orders/{id}/cancel/endpoint.post.json), not from path.id directly — that
-- dependency guarantees the sibling "order" source has already confirmed
-- the order exists (and 404'd otherwise) before this runs. So a zero-row
-- RETURNING here means only one thing: the order exists but is no longer
-- "pending" — mapped to 409 via this source's own "onError" override
-- rather than the registry's default 404 for a "one"-cardinality zero-row
-- result.
UPDATE orders
SET status = 'cancelled'
WHERE id = :id AND status = 'pending'
RETURNING id, status;
