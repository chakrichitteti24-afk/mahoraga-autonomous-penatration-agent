"""
Scan History, Comparison and Persistence Store for CipherFlux Labs.
"""
import os
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from . import get_cipherflux_data_dir
from backend.models.schemas import ScanResponse, SecurityFinding

class HistoryStore:
    def __init__(self, data_dir: Optional[str] = None):
        if data_dir is None:
            self.data_dir = get_cipherflux_data_dir()
        else:
            self.data_dir = Path(data_dir)

        self.scans_dir = self.data_dir / "scans"
        self.scans_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.data_dir / "history_index.json"
        self._index: List[Dict[str, Any]] = []
        self.load_index()

    def load_index(self) -> None:
        if self.index_file.exists():
            try:
                with open(self.index_file, "r", encoding="utf-8") as f:
                    self._index = json.load(f)
            except Exception:
                self._index = []
        else:
            self._index = []

    def save_index(self) -> None:
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(self._index, f, indent=2)

    def save_scan(self, scan: ScanResponse) -> None:
        scan_dict = scan.model_dump()
        file_path = self.scans_dir / f"{scan.scanId}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(scan_dict, f, indent=2)

        # Update index
        entry = {
            "scanId": scan.scanId,
            "target": scan.target,
            "scanType": scan.scanType.value if hasattr(scan.scanType, "value") else str(scan.scanType),
            "status": scan.status,
            "timestamp": getattr(scan, "createdAt", getattr(scan, "timestamp", datetime.now(timezone.utc).isoformat())),
            "totalFindings": scan.summary.totalFindings,
            "confirmedCount": scan.summary.confirmedCount,
            "potentialCount": scan.summary.potentialCount,
            "criticalCount": scan.summary.criticalCount,
            "highCount": scan.summary.highCount,
            "mediumCount": scan.summary.mediumCount,
            "lowCount": scan.summary.lowCount,
            "riskScore": scan.summary.riskScore,
            "durationSeconds": scan.summary.durationSeconds,
            "filePath": str(file_path),
        }
        # Remove existing if overwriting
        self._index = [i for i in self._index if i["scanId"] != scan.scanId]
        self._index.insert(0, entry)
        self.save_index()

    def list_scans(self) -> List[Dict[str, Any]]:
        return list(self._index)

    def get_scan(self, scan_id: str) -> Optional[ScanResponse]:
        file_path = self.scans_dir / f"{scan_id}.json"
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return ScanResponse.model_validate(data)
        except Exception:
            return None

    def compare_scans(self, scan_id_older: str, scan_id_newer: str) -> Dict[str, Any]:
        """
        Compare two scans of the same target to discover:
        - new_findings
        - resolved_findings (only if verified absent in newer scan)
        - persistent_findings
        """
        scan_a = self.get_scan(scan_id_older)
        scan_b = self.get_scan(scan_id_newer)

        if not scan_a or not scan_b:
            return {"error": "One or both scan IDs could not be loaded."}

        # Build fingerprint set for finding identity: (category, cweId, targetScope, title)
        def fingerprint(f: SecurityFinding) -> str:
            return f"{f.category}|{f.cweId or ''}|{f.targetScope}|{f.title}"

        map_a = {fingerprint(f): f for f in scan_a.findings}
        map_b = {fingerprint(f): f for f in scan_b.findings}

        persistent_keys = set(map_a.keys()).intersection(set(map_b.keys()))
        new_keys = set(map_b.keys()) - set(map_a.keys())
        resolved_keys = set(map_a.keys()) - set(map_b.keys())

        return {
            "olderScanId": scan_id_older,
            "newerScanId": scan_id_newer,
            "target": scan_b.target,
            "newFindingsCount": len(new_keys),
            "resolvedFindingsCount": len(resolved_keys),
            "persistentFindingsCount": len(persistent_keys),
            "newFindings": [map_b[k].model_dump() for k in new_keys],
            "resolvedFindings": [map_a[k].model_dump() for k in resolved_keys],
            "persistentFindings": [map_b[k].model_dump() for k in persistent_keys],
            "riskDelta": round(scan_b.summary.riskScore - scan_a.summary.riskScore, 2),
        }

    def delete_scan(self, scan_id: str) -> bool:
        file_path = self.scans_dir / f"{scan_id}.json"
        deleted = False
        if file_path.exists():
            file_path.unlink()
            deleted = True
        self._index = [i for i in self._index if i["scanId"] != scan_id]
        self.save_index()
        return deleted

history_store = HistoryStore()
