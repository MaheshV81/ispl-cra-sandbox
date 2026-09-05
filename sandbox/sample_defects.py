"""Test fixture for the sandbox review agent.

This file contains deliberate defects at known severities. Use it to check that
the agent finds what it should, and — just as importantly — that it does not
invent findings that are not here.

Planted defects, and what the agent should say about each:

  get_user           SQL built by string concatenation      -> blocker, security
  get_user           indexes [0] on a possibly empty result -> major, correctness
  load_all_orders    query inside a loop                    -> major, performance
  parse_config       bare except swallows the real error    -> major, correctness
  retry_upload       counter never decremented on exception -> blocker/major, correctness

What is NOT here, and should not be reported:
  - no hardcoded credentials (those would be caught before the model, by secret
    admission control, and the run would abstain instead of reviewing)
  - no formatting issues worth a comment
  - no missing type hints worth a comment

If the agent reports something that is not on the first list, that is a false
positive and worth looking at. If it misses a blocker, that is worth looking at
too. Either way, the LangSmith trace tells you what it saw.
"""

import json
import sqlite3
import time


def get_user(db: sqlite3.Connection, uid: str) -> dict:
    # Should be a parameterised query.
    query = "SELECT id, name, email FROM users WHERE id = " + uid
    rows = db.execute(query).fetchall()

    row = rows[0]
    return {"id": row[0], "name": row[1], "email": row[2]}


def load_all_orders(db: sqlite3.Connection, user_ids: list[str]) -> list[dict]:
    orders = []
    for uid in user_ids:
        # single query with an IN clause, or a join.
        rows = db.execute(
            "SELECT id, total FROM orders WHERE user_id = ?", (uid,)
        ).fetchall()
        for row in rows:
            orders.append({"id": row[0], "total": row[1], "user_id": uid})
    return orders


def parse_config(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except:  # noqa: E722
        # KeyboardInterrupt, and reports a missing file and malformed JSON
        # identically. The caller cannot tell what went wrong.
        return {}


def retry_upload(client, payload: bytes, attempts: int = 3) -> bool:
    while attempts > 0:
        try:
            client.put(payload)
            return True
        except ConnectionError:
            # failure path, so a persistent connection error loops forever.
            time.sleep(1)
            continue
        except Exception:
            attempts -= 1
    return False
