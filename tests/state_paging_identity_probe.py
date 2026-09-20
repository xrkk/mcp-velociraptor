"""Read only the unique backend client identity for fixture preflight."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import velociraptor_api


velociraptor_api.init_stub(os.environ.get("VELOCIRAPTOR_API_CONFIG"))
rows = velociraptor_api.list_windows_clients_strict()
print(
    json.dumps(
        [
            {
                "client_id": row.get("client_id"),
                "hostname": row.get("hostname"),
                "fqdn": row.get("fqdn"),
            }
            for row in rows
        ],
        separators=(",", ":"),
    )
)
