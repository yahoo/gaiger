# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""Opaque, correlatable client-facing error messages (CWE-209).

The route layer in app/main.py deliberately returns static messages instead of
reflecting caller input. This module extends that control DOWN to the layers
that produce error text (Kubernetes / Flink / Postgres clients, metrics
collector), so a new caller added later cannot bypass it: the sanitization
lives where the data is produced, not at the routes that happen to wrap it.

Why it matters here: a ``kubernetes.client.ApiException`` stringifies to the
API server's response body — the ServiceAccount principal, the namespace, and
the exact denied verb/resource — so returning ``str(e)`` to a caller hands out
an RBAC reconnaissance map. The rule: full detail is logged SERVER-SIDE with a
correlation id; the caller sees only an opaque token they can quote in a
ticket and an operator can find in the container log / your log backend.
"""
import logging

from app.audit import get_correlation_id

logger = logging.getLogger(__name__)


def client_error(context: str, exc: Exception) -> str:
    """Log the real exception server-side; return an opaque, correlatable token.

    The caller-visible string carries no principal, namespace, hostname or
    API-server response body — only enough for a user to quote it in a ticket
    and for an operator to find the full detail server-side by correlation id.
    """
    cid = get_correlation_id() or "-"
    logger.error("%s failed [cid=%s]: %s", context, cid, exc, exc_info=True)
    return f"{context} failed (ref: {cid})"
