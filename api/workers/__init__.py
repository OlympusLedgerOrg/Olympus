"""Background workers for the Olympus FOIA backend.

Each module in this package is a long-running process started outside the
FastAPI application.  They consume work from durable queues persisted in
the same database the API writes to, so they survive process restarts and
can be scaled horizontally.

Run a worker with::

    python -m api.workers.tsa_worker

See each module's docstring for runtime configuration.
"""

from __future__ import annotations
