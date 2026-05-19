-- display_id sequence for OLY-NNNN request IDs (alembic: c1d2e3f4a5b6)

CREATE SEQUENCE IF NOT EXISTS display_id_seq START WITH 1 INCREMENT BY 1;

-- Advance to the highest existing OLY-NNNN value so new IDs don't collide.
SELECT setval(
    'display_id_seq',
    GREATEST(
        COALESCE(
            (SELECT MAX(CAST(SPLIT_PART(display_id, '-', 2) AS INTEGER))
             FROM public_records_requests
             WHERE display_id LIKE 'OLY-%'),
            1
        ),
        1
    ),
    COALESCE(
        (SELECT MAX(CAST(SPLIT_PART(display_id, '-', 2) AS INTEGER))
         FROM public_records_requests
         WHERE display_id LIKE 'OLY-%'),
        0
    ) > 0
);
