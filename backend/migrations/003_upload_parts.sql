-- Pieces of a large upload. Vercel rejects a request bigger than about 4.5 MB.
CREATE TABLE IF NOT EXISTS upload_parts (
    upload_id   TEXT NOT NULL,
    part_index  INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    filename    TEXT NOT NULL,
    total_parts INTEGER NOT NULL,
    data        BLOB NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (upload_id, part_index)
);
