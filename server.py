# DPM License Server: safe COUNT(*) result helper for psycopg dict rows or SQLite rows.
# In server.py, add this function near the other helpers:

def get_client_account_count(conn):
    row = conn.execute(
        "SELECT COUNT(*) AS account_count FROM client_accounts"
    ).fetchone()
    if isinstance(row, dict):
        return int(row["account_count"])
    try:
        return int(row["account_count"])
    except (TypeError, KeyError, IndexError):
        return int(row[0])

# Then replace the two failing expressions:
#   conn.execute("SELECT COUNT(*) FROM client_accounts").fetchone()[0]
# with:
#   get_client_account_count(conn)
#
# And replace:
#   _startup_conn.execute("SELECT COUNT(*) FROM client_accounts").fetchone()[0]
# with:
#   get_client_account_count(_startup_conn)
#
# IMPORTANT: This is a patch helper, not a complete server.py. Do not upload it
# as a replacement for server.py. The correct full file must be based on the
# current PostgreSQL-enabled server.py from your GitHub main branch.
