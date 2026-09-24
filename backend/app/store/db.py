"""Case persistence: Neo4j graph database.

Graph model
-----------
Nodes
  (:Case)            one per analysed email; carries indexed props + full JSON payload
  (:IOC)             deduplicated indicator of compromise, shared across cases
  (:Signal)          detection signal (per-case, not shared)
  (:CustodyRecord)   chain-of-custody receipt (per-case)
  (:AuditEvent)      operational audit log entry (per-case)
  (:Sender)          unique sender address (artefact, shared across cases)
  (:Domain)          registrable domain   (artefact, shared)
  (:IP)              public relay IP      (artefact, shared)
  (:UrlHost)         URL registrable domain (artefact, shared)
  (:Attachment)      attachment SHA-256   (artefact, shared)

Relationships
  (:Case)-[:HAS_IOC]->(:IOC)
  (:Case)-[:HAS_SIGNAL]->(:Signal)
  (:Case)-[:HAS_CUSTODY]->(:CustodyRecord)
  (:Case)-[:HAS_AUDIT]->(:AuditEvent)
  (:Case)-[:SENT_BY]->(:Sender)
  (:Case)-[:USES_DOMAIN]->(:Domain)
  (:Case)-[:RELAYED_VIA]->(:IP)
  (:Case)-[:LINKS_TO]->(:UrlHost)
  (:Case)-[:HAS_ATTACHMENT]->(:Attachment)

IOC nodes are MERGED by (ioc_type, value) so two cases that share an IP or domain
share a single node - direct graph traversal replaces the SQL self-join in
by_ioc() and makes multi-hop correlation queries natural.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from neo4j import GraphDatabase
from neo4j.exceptions import ClientError, ServiceUnavailable

from ..config import get_settings
from ..schemas import Case, utcnow

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema setup: constraints, indexes, fulltext index
# ---------------------------------------------------------------------------

_CONSTRAINTS = [
    "CREATE CONSTRAINT case_id IF NOT EXISTS FOR (c:Case) REQUIRE c.id IS UNIQUE",
    "CREATE CONSTRAINT case_number IF NOT EXISTS "
    "FOR (c:Case) REQUIRE c.case_number IS UNIQUE",
]

_INDEXES = [
    "CREATE INDEX case_created   IF NOT EXISTS FOR (c:Case) ON (c.created_at)",
    "CREATE INDEX case_status    IF NOT EXISTS FOR (c:Case) ON (c.status)",
    "CREATE INDEX case_verdict   IF NOT EXISTS FOR (c:Case) ON (c.verdict)",
    "CREATE INDEX case_campaign  IF NOT EXISTS FOR (c:Case) ON (c.campaign_id)",
    "CREATE INDEX case_fp        IF NOT EXISTS FOR (c:Case) ON (c.fingerprint)",
    "CREATE INDEX case_email_hash IF NOT EXISTS FOR (c:Case) ON (c.email_hash)",
    "CREATE INDEX case_risk      IF NOT EXISTS FOR (c:Case) ON (c.risk_score)",
    "CREATE INDEX ioc_value      IF NOT EXISTS FOR (n:IOC) ON (n.value)",
    "CREATE INDEX signal_tech    IF NOT EXISTS FOR (s:Signal) ON (s.technique)",
    "CREATE INDEX custody_pair   IF NOT EXISTS "
    "FOR (r:CustodyRecord) ON (r.case_id, r.idx)",
]

_FTS_INDEX = (
    "CREATE FULLTEXT INDEX caseFullText IF NOT EXISTS "
    "FOR (n:Case) ON EACH "
    "[n.subject, n.sender_address, n.sender_domain, n.case_number, n.campaign_id]"
)

_SORTS: Dict[str, str] = {
    "created":    "c.created_at DESC",
    "risk":       "c.risk_score DESC, c.created_at DESC",
    "confidence": "c.confidence DESC, c.created_at DESC",
    "updated":    "c.updated_at DESC",
    "status":     "c.status ASC, c.created_at DESC",
}


# ---------------------------------------------------------------------------
# CaseStore
# ---------------------------------------------------------------------------


class CaseStore:
    """Thread-safe case store backed by Neo4j.

    The Neo4j driver manages its own connection pool, so a single driver
    instance is safe to share across threads.  Each public method opens and
    closes a session; no session is held across calls.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
    ) -> None:
        s = get_settings()
        self._uri      = uri      or s.neo4j_uri
        self._user     = user     or s.neo4j_user
        self._password = password or s.neo4j_password
        self._database = database or s.neo4j_database
        self._driver   = GraphDatabase.driver(
            self._uri, auth=(self._user, self._password)
        )
        self._fts = False
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._driver.session(database=self._database) as s:
            for stmt in _CONSTRAINTS + _INDEXES:
                try:
                    s.run(stmt)
                except ClientError as exc:
                    log.debug("Schema stmt skipped (%s): %s", exc.code, stmt[:60])
            try:
                s.run(_FTS_INDEX)
                self._fts = True
            except ClientError as exc:
                log.info("Full-text index unavailable (%s); search uses CONTAINS fallback",
                         exc.code)

    @property
    def search_backend(self) -> str:
        return "neo4j-fts" if self._fts else "neo4j-contains"

    def close(self) -> None:
        self._driver.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, case: Case) -> Case:
        """Insert or update the full case. Idempotent by case id."""
        payload = json.dumps(case.to_dict(), sort_keys=True, default=str)
        origin  = case.origin or {}
        props   = {
            "id":             case.id,
            "case_number":    case.case_number,
            "status":         case.status,
            "verdict":        case.verdict.label,
            "threat_class":   case.verdict.threat_class or "",
            "risk_score":     float(case.verdict.risk_score),
            "confidence":     float(case.verdict.confidence),
            "actor_type":     case.attribution.actor_type or "",
            "subject":        (case.subject or "")[:400],
            "sender_address": case.sender_address or "",
            "sender_domain":  case.parsed_email.from_domain or "",
            "recipient":      case.recipient or "",
            "email_hash":     case.email_hash or "",
            "fingerprint":    case.fingerprint or "",
            "campaign_id":    case.campaign.id or "",
            "is_duplicate":   bool(case.campaign.is_duplicate),
            "origin_country": str(origin.get("country", origin.get("place", "")))[:120],
            "origin_ip":      str(origin.get("ip", "")),
            "requires_review": bool(case.verdict.requires_human_review),
            "action_status":  case.action.status or "",
            "analyst":        case.action.analyst or "",
            "tx_hash":        case.chain_receipts[-1].tx_hash if case.chain_receipts else "",
            "chain_simulated": bool(
                not case.chain_receipts or case.chain_receipts[-1].simulated
            ),
            "report_path":    case.report_path or "",
            "created_at":     case.created_at or utcnow(),
            "updated_at":     case.updated_at or utcnow(),
            "completed_at":   case.completed_at or "",
            "payload":        payload,
        }

        with self._driver.session(database=self._database) as session:
            def _tx(tx: Any) -> None:
                # Upsert the Case node
                tx.run(
                    "MERGE (c:Case {id: $id}) SET c += $props",
                    id=case.id, props=props,
                )

                # Replace per-case Signal nodes (one set per save)
                tx.run(
                    "MATCH (c:Case {id: $id})-[:HAS_SIGNAL]->(s:Signal) DETACH DELETE s",
                    id=case.id,
                )
                for sig in case.signals:
                    if not sig.triggered:
                        continue
                    tx.run(
                        "MATCH (c:Case {id: $cid}) "
                        "CREATE (c)-[:HAS_SIGNAL]->(s:Signal {"
                        "  signal_id: $sid, title: $title, weight: $w, "
                        "  severity: $sev, category: $cat, technique: $tech})",
                        cid=case.id, sid=sig.id, title=sig.title or "",
                        w=float(sig.weight), sev=sig.severity or "",
                        cat=sig.category or "",
                        tech=getattr(sig, "mitre_technique", "") or "",
                    )

                # Replace IOC relationships; IOC nodes are shared (MERGE by value)
                tx.run(
                    "MATCH (c:Case {id: $id})-[r:HAS_IOC]->() DELETE r",
                    id=case.id,
                )
                for ioc in case.iocs:
                    if not ioc.value:
                        continue
                    tx.run(
                        "MATCH (c:Case {id: $cid}) "
                        "MERGE (i:IOC {ioc_type: $t, value: $v}) "
                        "  ON CREATE SET i.confidence = $conf, "
                        "               i.context = $ctx, "
                        "               i.first_seen = $fs "
                        "  ON MATCH  SET i.confidence = CASE WHEN $conf > i.confidence "
                        "                               THEN $conf ELSE i.confidence END "
                        "MERGE (c)-[:HAS_IOC]->(i)",
                        cid=case.id,
                        t=ioc.ioc_type,
                        v=ioc.value.lower(),
                        conf=int(ioc.confidence),
                        ctx=ioc.context or "",
                        fs=ioc.first_seen or "",
                    )

                # Upsert custody records
                for idx, receipt in enumerate(case.chain_receipts):
                    tx.run(
                        "MERGE (r:CustodyRecord {case_id: $cid, idx: $idx}) "
                        "SET r.action = $action, r.tx_hash = $txh, "
                        "    r.payload_hash = $ph, r.simulated = $sim, "
                        "    r.written_at = $wa "
                        "WITH r MATCH (c:Case {id: $cid}) "
                        "MERGE (c)-[:HAS_CUSTODY]->(r)",
                        cid=case.id, idx=idx,
                        action=receipt.action or "",
                        txh=receipt.tx_hash or "",
                        ph=receipt.payload_hash or "",
                        sim=bool(receipt.simulated),
                        wa=receipt.written_at or "",
                    )

                # Artefact nodes (enable graph-traversal correlation)
                if case.sender_address:
                    tx.run(
                        "MERGE (s:Sender {address: $addr}) "
                        "WITH s MATCH (c:Case {id: $cid}) MERGE (c)-[:SENT_BY]->(s)",
                        addr=case.sender_address.lower(), cid=case.id,
                    )
                if case.parsed_email.from_domain:
                    tx.run(
                        "MERGE (d:Domain {name: $name}) "
                        "WITH d MATCH (c:Case {id: $cid}) MERGE (c)-[:USES_DOMAIN]->(d)",
                        name=case.parsed_email.from_domain.lower(), cid=case.id,
                    )
                for hop in case.relay_hops:
                    if hop.ip and not hop.is_private:
                        tx.run(
                            "MERGE (ip:IP {address: $addr}) "
                            "WITH ip MATCH (c:Case {id: $cid}) "
                            "MERGE (c)-[:RELAYED_VIA]->(ip)",
                            addr=hop.ip, cid=case.id,
                        )
                for url in case.parsed_email.urls[:20]:
                    host = (url.registrable_domain or url.domain or "").lower()
                    if host:
                        tx.run(
                            "MERGE (u:UrlHost {host: $host}) "
                            "WITH u MATCH (c:Case {id: $cid}) "
                            "MERGE (c)-[:LINKS_TO]->(u)",
                            host=host, cid=case.id,
                        )
                for att in case.parsed_email.attachments:
                    if att.sha256:
                        tx.run(
                            "MERGE (a:Attachment {sha256: $sha}) "
                            "WITH a MATCH (c:Case {id: $cid}) "
                            "MERGE (c)-[:HAS_ATTACHMENT]->(a)",
                            sha=att.sha256, cid=case.id,
                        )

            session.execute_write(_tx)

        return case

    def log_event(
        self,
        case_id: str,
        event: str,
        actor: str = "system",
        detail: str = "",
    ) -> None:
        """Append an operational audit event. Not the custody chain."""
        with self._driver.session(database=self._database) as session:
            session.run(
                "MATCH (c:Case {id: $cid}) "
                "CREATE (c)-[:HAS_AUDIT]->(a:AuditEvent {"
                "  event: $event, actor: $actor, detail: $detail, at: $at})",
                cid=case_id,
                event=event,
                actor=actor,
                detail=detail[:500],
                at=utcnow(),
            )

    def next_case_number(self) -> str:
        """``MT-2026-0001`` — sequential per year, sortable chronologically."""
        year   = datetime.now(timezone.utc).year
        prefix = "MT-%d-" % year
        with self._driver.session(database=self._database) as session:
            row = session.run(
                "MATCH (c:Case) WHERE c.case_number STARTS WITH $pfx "
                "RETURN c.case_number AS n ORDER BY c.case_number DESC LIMIT 1",
                pfx=prefix,
            ).single()
        if row:
            try:
                return "%s%04d" % (prefix, int(str(row["n"]).split("-")[-1]) + 1)
            except ValueError:
                pass
        return prefix + "0001"

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def find_by_hash(self, email_hash: str) -> Optional[Case]:
        """Return the earliest case with a matching email_hash, or None."""
        with self._driver.session(database=self._database) as session:
            row = session.run(
                "MATCH (c:Case {email_hash: $h}) "
                "RETURN c.payload AS payload "
                "ORDER BY c.created_at ASC LIMIT 1",
                h=email_hash,
            ).single()
        if row is None:
            return None
        return Case.from_dict(json.loads(row["payload"]))

    def get(self, case_id: str) -> Optional[Case]:
        with self._driver.session(database=self._database) as session:
            row = session.run(
                "MATCH (c:Case) WHERE c.id = $cid OR c.case_number = $cid "
                "RETURN c.payload AS payload LIMIT 1",
                cid=case_id,
            ).single()
        if row is None:
            return None
        return Case.from_dict(json.loads(row["payload"]))

    def all_cases(self, limit: int = 500) -> List[Case]:
        """Full Case objects, newest first. Used by correlation."""
        with self._driver.session(database=self._database) as session:
            rows = session.run(
                "MATCH (c:Case) RETURN c.payload AS payload "
                "ORDER BY c.created_at DESC LIMIT $lim",
                lim=limit,
            ).data()
        return [Case.from_dict(json.loads(r["payload"])) for r in rows]

    def queue(
        self,
        status: Optional[str] = None,
        verdict: Optional[str] = None,
        threat_class: Optional[str] = None,
        min_risk: Optional[float] = None,
        campaign_id: Optional[str] = None,
        include_duplicates: bool = True,
        sort: str = "created",
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Filtered queue projection — returns summaries, not full payloads."""
        where: List[str] = []
        params: Dict[str, Any] = {}

        if status:
            where.append("c.status = $status")
            params["status"] = status
        if verdict:
            where.append("c.verdict = $verdict")
            params["verdict"] = verdict
        if threat_class:
            where.append("c.threat_class = $threat_class")
            params["threat_class"] = threat_class
        if min_risk is not None:
            where.append("c.risk_score >= $min_risk")
            params["min_risk"] = float(min_risk)
        if campaign_id:
            where.append("c.campaign_id = $campaign_id")
            params["campaign_id"] = campaign_id
        if not include_duplicates:
            where.append("c.is_duplicate = false")

        where_clause = ("WHERE " + " AND ".join(where)) if where else ""
        order_clause = _SORTS.get(sort, _SORTS["created"])

        with self._driver.session(database=self._database) as session:
            total_row = session.run(
                f"MATCH (c:Case) {where_clause} RETURN count(c) AS total",
                **params,
            ).single()
            total = int(total_row["total"]) if total_row else 0

            rows = session.run(
                f"MATCH (c:Case) {where_clause} "
                f"RETURN c.payload AS payload "
                f"ORDER BY {order_clause} "
                f"SKIP $offset LIMIT $limit",
                **params,
                offset=offset,
                limit=limit,
            ).data()

        items = [Case.from_dict(json.loads(r["payload"])).summary() for r in rows]
        return {
            "total": total,
            "count": len(items),
            "offset": offset,
            "sort": sort,
            "items": items,
        }

    def search(self, query: str, limit: int = 50) -> Dict[str, Any]:
        """Full-text search across subject, sender, body, indicators and campaign."""
        query = (query or "").strip()
        if not query:
            return {"backend": self.search_backend, "count": 0, "items": []}

        items: List[Dict[str, Any]] = []
        with self._driver.session(database=self._database) as session:
            if self._fts:
                try:
                    rows = session.run(
                        "CALL db.index.fulltext.queryNodes('caseFullText', $q) "
                        "YIELD node, score "
                        "RETURN node.payload AS payload, score "
                        "ORDER BY score DESC LIMIT $lim",
                        q=_lucene_query(query),
                        lim=limit,
                    ).data()
                except ClientError as exc:
                    log.info("FTS query rejected (%s); falling back to CONTAINS", exc.code)
                    rows = self._contains_rows(session, query, limit)
            else:
                rows = self._contains_rows(session, query, limit)

        for r in rows:
            items.append(Case.from_dict(json.loads(r["payload"])).summary())

        return {
            "backend": self.search_backend,
            "query": query,
            "count": len(items),
            "items": items,
        }

    def _contains_rows(
        self, session: Any, query: str, limit: int
    ) -> List[Dict[str, Any]]:
        q = query.lower()
        return session.run(
            "MATCH (c:Case) "
            "WHERE toLower(c.subject) CONTAINS $q "
            "   OR toLower(c.sender_address) CONTAINS $q "
            "   OR toLower(c.sender_domain) CONTAINS $q "
            "   OR toLower(c.case_number) CONTAINS $q "
            "   OR toLower(c.campaign_id) CONTAINS $q "
            "RETURN c.payload AS payload, 1.0 AS score "
            "ORDER BY c.created_at DESC LIMIT $lim",
            q=q,
            lim=limit,
        ).data()

    def by_ioc(self, value: str, limit: int = 50) -> List[Dict[str, Any]]:
        """All cases that share an IOC with this value — direct graph traversal."""
        with self._driver.session(database=self._database) as session:
            rows = session.run(
                "MATCH (i:IOC {value: $v})<-[:HAS_IOC]-(c:Case) "
                "RETURN c.payload AS payload "
                "ORDER BY c.created_at DESC LIMIT $lim",
                v=value.lower(),
                lim=limit,
            ).data()
        return [Case.from_dict(json.loads(r["payload"])).summary() for r in rows]

    def campaigns(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Campaign roll-up computed from the graph — stable because it reads Case props."""
        with self._driver.session(database=self._database) as session:
            rows = session.run(
                "MATCH (c:Case) "
                "WHERE c.campaign_id IS NOT NULL AND c.campaign_id <> '' "
                "WITH c.campaign_id AS campaign_id, "
                "     count(c)                    AS cases, "
                "     max(c.risk_score)            AS max_risk, "
                "     avg(c.risk_score)            AS avg_risk, "
                "     min(c.created_at)            AS first_seen, "
                "     max(c.created_at)            AS last_seen, "
                "     sum(CASE WHEN c.verdict = 'phishing' THEN 1 ELSE 0 END) AS phishing, "
                "     collect(DISTINCT c.sender_domain) AS domains, "
                "     collect(DISTINCT c.threat_class)  AS classes "
                "RETURN campaign_id, cases, max_risk, avg_risk, "
                "       first_seen, last_seen, phishing, domains, classes "
                "ORDER BY cases DESC, last_seen DESC LIMIT $lim",
                lim=limit,
            ).data()

        out = []
        for r in rows:
            out.append({
                "campaign_id":    r["campaign_id"],
                "cases":          int(r["cases"]),
                "max_risk":       round(float(r["max_risk"] or 0), 1),
                "avg_risk":       round(float(r["avg_risk"] or 0), 1),
                "first_seen":     r["first_seen"],
                "last_seen":      r["last_seen"],
                "phishing_cases": int(r["phishing"] or 0),
                "sender_domains": sorted(set(r["domains"] or []) - {"", None}),
                "threat_classes": sorted(set(r["classes"] or []) - {"", None}),
            })
        return out

    def stats(self) -> Dict[str, Any]:
        """Dashboard counters — one round-trip for the main row, four for breakdowns."""
        with self._driver.session(database=self._database) as session:
            row = session.run(
                "MATCH (c:Case) "
                "RETURN "
                "  count(c) AS total, "
                "  sum(CASE WHEN c.verdict = 'phishing'      THEN 1 ELSE 0 END) AS phishing, "
                "  sum(CASE WHEN c.verdict = 'suspicious'    THEN 1 ELSE 0 END) AS suspicious, "
                "  sum(CASE WHEN c.verdict = 'indeterminate' THEN 1 ELSE 0 END) AS indeterminate, "
                "  sum(CASE WHEN c.verdict = 'benign'        THEN 1 ELSE 0 END) AS benign, "
                "  sum(CASE WHEN c.requires_review = true "
                "       AND c.action_status = 'pending' THEN 1 ELSE 0 END) AS awaiting_review, "
                "  sum(CASE WHEN c.is_duplicate    = true  THEN 1 ELSE 0 END) AS duplicates, "
                "  sum(CASE WHEN c.chain_simulated = false THEN 1 ELSE 0 END) AS anchored, "
                "  avg(c.risk_score)   AS avg_risk, "
                "  avg(c.confidence)   AS avg_confidence "
            ).single()

            classes = session.run(
                "MATCH (c:Case) WHERE c.threat_class IS NOT NULL AND c.threat_class <> '' "
                "RETURN c.threat_class AS k, count(*) AS n"
            ).data()

            actors = session.run(
                "MATCH (c:Case) WHERE c.actor_type IS NOT NULL AND c.actor_type <> '' "
                "RETURN c.actor_type AS k, count(*) AS n"
            ).data()

            techniques = session.run(
                "MATCH (c:Case)-[:HAS_SIGNAL]->(s:Signal) "
                "WHERE s.technique IS NOT NULL AND s.technique <> '' "
                "RETURN s.technique AS technique, count(DISTINCT c) AS cases "
                "ORDER BY cases DESC LIMIT 10"
            ).data()

            countries = session.run(
                "MATCH (c:Case) "
                "WHERE c.origin_country IS NOT NULL AND c.origin_country <> '' "
                "RETURN c.origin_country AS k, count(*) AS n "
                "ORDER BY n DESC LIMIT 10"
            ).data()

        r = dict(row) if row else {}
        return {
            "total":             int(r.get("total") or 0),
            "phishing":          int(r.get("phishing") or 0),
            "suspicious":        int(r.get("suspicious") or 0),
            "indeterminate":     int(r.get("indeterminate") or 0),
            "benign":            int(r.get("benign") or 0),
            "awaiting_review":   int(r.get("awaiting_review") or 0),
            "duplicates":        int(r.get("duplicates") or 0),
            "chain_anchored":    int(r.get("anchored") or 0),
            "avg_risk":          round(float(r.get("avg_risk") or 0), 1),
            "avg_confidence":    round(float(r.get("avg_confidence") or 0), 1),
            "threat_classes":    {x["k"]: int(x["n"]) for x in classes},
            "actor_types":       {x["k"]: int(x["n"]) for x in actors},
            "top_techniques":    [
                {"technique": x["technique"], "cases": int(x["cases"])}
                for x in techniques
            ],
            "top_origins":       [
                {"country": x["k"], "cases": int(x["n"])}
                for x in countries
            ],
            "search_backend":    self.search_backend,
        }

    def audit_trail(
        self, case_id: str, limit: int = 100
    ) -> List[Dict[str, Any]]:
        with self._driver.session(database=self._database) as session:
            rows = session.run(
                "MATCH (c:Case {id: $cid})-[:HAS_AUDIT]->(a:AuditEvent) "
                "RETURN a.event AS event, a.actor AS actor, "
                "       a.detail AS detail, a.at AS at "
                "ORDER BY a.at DESC LIMIT $lim",
                cid=case_id,
                lim=limit,
            ).data()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def clear_all(self) -> int:
        """Delete every node and relationship in the database."""
        with self._driver.session(database=self._database) as session:
            total_row = session.run("MATCH (c:Case) RETURN count(c) AS n").single()
            count = int(total_row["n"]) if total_row else 0
            # Delete in batches to avoid heap pressure on large graphs
            while True:
                result = session.run(
                    "MATCH (n) WITH n LIMIT 10000 DETACH DELETE n RETURN count(*) AS deleted"
                ).single()
                if not result or int(result["deleted"]) == 0:
                    break
        return count

    def redact_expired(
        self,
        retention_days: Optional[int] = None,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """Strip message content from cases past the retention window.

        The Case node itself is kept — verdict, hashes, IOCs, signals, custody
        receipts and the report path remain, so the investigation is still
        provable and countable after the personal data inside it is gone.
        """
        days   = int(retention_days if retention_days is not None
                     else get_settings().retention_days)
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()

        with self._driver.session(database=self._database) as session:
            rows = session.run(
                "MATCH (c:Case) WHERE c.created_at < $cutoff "
                "RETURN c.id AS id, c.payload AS payload",
                cutoff=cutoff,
            ).data()

        affected: List[str] = []
        for r in rows:
            data = json.loads(r["payload"])
            pe   = data.get("parsed_email", {})
            if not (pe.get("body_text") or pe.get("body_html") or pe.get("attachments")):
                continue
            affected.append(r["id"])
            if dry_run:
                continue
            pe["body_text"] = ""
            pe["body_html"] = ""
            for att in pe.get("attachments", []):
                att.pop("preview", None)
            keep = (
                "from", "to", "subject", "date", "message-id", "received",
                "return-path", "reply-to", "authentication-results",
            )
            pe["headers"] = [
                h for h in (pe.get("headers") or [])
                if str(h.get("name", "")).lower() in keep
            ]
            data.setdefault("privacy", {})["content_purged_at"] = utcnow()
            new_payload = json.dumps(data, sort_keys=True)
            with self._driver.session(database=self._database) as session:
                session.run(
                    "MATCH (c:Case {id: $id}) "
                    "SET c.payload = $payload, c.updated_at = $upd",
                    id=r["id"],
                    payload=new_payload,
                    upd=utcnow(),
                )
            self.log_event(
                r["id"], "retention_purge", "system",
                "message content removed after %d days" % days,
            )

        return {
            "retention_days":  days,
            "cutoff":          cutoff,
            "dry_run":         dry_run,
            "cases_affected":  len(affected),
            "case_ids":        affected[:50],
            "kept":            "verdict, hashes, IOCs, signals, custody receipts, report path",
        }


# ---------------------------------------------------------------------------
# FTS query helpers
# ---------------------------------------------------------------------------


def _lucene_query(query: str) -> str:
    """Build a safe Lucene prefix-match expression for Neo4j fulltext search.

    Strips special Lucene syntax chars and appends ``*`` for prefix matching
    on the last term so type-as-you-search feels responsive.
    """
    terms = [t for t in re.split(r"\s+", query.strip()) if t]
    if not terms:
        return '""'
    safe = []
    for t in terms:
        cleaned = re.sub(r'[+\-&|!(){}\[\]^"~*?:\\/]', " ", t).strip()
        if cleaned:
            safe.append(cleaned + "*")
    return " AND ".join(safe) or '""'


# ---------------------------------------------------------------------------
# Module-level singleton (mirrors the SQLite API used by pipeline + routes)
# ---------------------------------------------------------------------------

_store: Optional[CaseStore] = None
_store_lock = threading.Lock()


def get_store(path: Optional[str] = None) -> CaseStore:
    """Return the process-wide CaseStore.

    The ``path`` argument is accepted for backward compatibility with callers
    that passed a SQLite file path; it is silently ignored — connection details
    are read from settings (NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD).
    """
    global _store
    with _store_lock:
        if _store is None:
            _store = CaseStore()
        return _store


def reset_store() -> None:
    """Close and drop the cached store (used by tests)."""
    global _store
    with _store_lock:
        if _store is not None:
            try:
                _store.close()
            except Exception:
                pass
        _store = None
