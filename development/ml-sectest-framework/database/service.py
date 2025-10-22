"""
Database Service Layer
======================

Provides CRUD operations for scans and batch scans.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional, Dict, Any
from datetime import datetime

from .models import Scan, BatchScan


# ============================================================================
# Scan CRUD Operations
# ============================================================================

def create_scan(
    db: Session,
    scan_id: str,
    target_url: str,
    challenge_name: str = "custom",
    agents: Optional[List[str]] = None,
    parallel: bool = False,
    timeout: int = 300,
    report_format: str = "json",
    batch_id: Optional[str] = None
) -> Scan:
    """Create a new scan record."""
    scan = Scan(
        scan_id=scan_id,
        target_url=target_url,
        challenge_name=challenge_name,
        agents=agents,
        parallel=parallel,
        timeout=timeout,
        report_format=report_format,
        batch_id=batch_id,
        status="queued"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
    """Get a scan by ID."""
    return db.query(Scan).filter(Scan.scan_id == scan_id).first()


def get_all_scans(db: Session, limit: int = 100, offset: int = 0) -> List[Scan]:
    """Get all scans with pagination."""
    return db.query(Scan).order_by(desc(Scan.created_at)).limit(limit).offset(offset).all()


def get_scans_by_status(db: Session, status: str) -> List[Scan]:
    """Get all scans with a specific status."""
    return db.query(Scan).filter(Scan.status == status).all()


def update_scan_status(
    db: Session,
    scan_id: str,
    status: str,
    error: Optional[str] = None
) -> Optional[Scan]:
    """Update scan status."""
    scan = get_scan(db, scan_id)
    if scan:
        scan.status = status
        scan.updated_at = datetime.now()

        if status == "running" and not scan.started_at:
            scan.started_at = datetime.now()

        if status in ["completed", "failed"]:
            scan.completed_at = datetime.now()
            if scan.started_at:
                scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

        if error:
            scan.error = error

        db.commit()
        db.refresh(scan)
    return scan


def update_scan_result(
    db: Session,
    scan_id: str,
    result: Dict[str, Any]
) -> Optional[Scan]:
    """Update scan result."""
    scan = get_scan(db, scan_id)
    if scan:
        scan.result = result
        scan.status = "completed"
        scan.updated_at = datetime.now()
        scan.completed_at = datetime.now()

        if scan.started_at:
            scan.duration_seconds = (scan.completed_at - scan.started_at).total_seconds()

        db.commit()
        db.refresh(scan)
    return scan


def delete_scan(db: Session, scan_id: str) -> bool:
    """Delete a scan."""
    scan = get_scan(db, scan_id)
    if scan:
        db.delete(scan)
        db.commit()
        return True
    return False


# ============================================================================
# Batch Scan CRUD Operations
# ============================================================================

def create_batch_scan(
    db: Session,
    batch_id: str,
    total_scans: int,
    filename: Optional[str] = None,
    file_format: Optional[str] = None
) -> BatchScan:
    """Create a new batch scan record."""
    batch = BatchScan(
        batch_id=batch_id,
        filename=filename,
        file_format=file_format,
        total_scans=total_scans,
        queued_scans=total_scans,
        status="queued"
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    return batch


def get_batch_scan(db: Session, batch_id: str) -> Optional[BatchScan]:
    """Get a batch scan by ID."""
    return db.query(BatchScan).filter(BatchScan.batch_id == batch_id).first()


def get_all_batch_scans(db: Session, limit: int = 100, offset: int = 0) -> List[BatchScan]:
    """Get all batch scans with pagination."""
    return db.query(BatchScan).order_by(desc(BatchScan.created_at)).limit(limit).offset(offset).all()


def update_batch_status(db: Session, batch_id: str) -> Optional[BatchScan]:
    """
    Update batch scan status based on individual scan statuses.

    Automatically recalculates counts and determines overall status.
    """
    batch = get_batch_scan(db, batch_id)
    if not batch:
        return None

    # Get all scans in this batch
    scans = db.query(Scan).filter(Scan.batch_id == batch_id).all()

    # Count statuses
    completed = sum(1 for s in scans if s.status == "completed")
    failed = sum(1 for s in scans if s.status == "failed")
    running = sum(1 for s in scans if s.status == "running")
    queued = sum(1 for s in scans if s.status == "queued")

    # Update counts
    batch.completed_scans = completed
    batch.failed_scans = failed
    batch.running_scans = running
    batch.queued_scans = queued
    batch.updated_at = datetime.now()

    # Determine overall status
    if completed + failed == batch.total_scans:
        if failed == 0:
            batch.status = "completed"
        else:
            batch.status = "partial"

        if not batch.completed_at:
            batch.completed_at = datetime.now()
            batch.duration_seconds = (batch.completed_at - batch.created_at).total_seconds()
    elif running > 0:
        batch.status = "running"
    else:
        batch.status = "queued"

    db.commit()
    db.refresh(batch)
    return batch


def get_batch_scans_for_batch(db: Session, batch_id: str) -> List[Scan]:
    """Get all scans belonging to a batch."""
    return db.query(Scan).filter(Scan.batch_id == batch_id).all()


def update_batch_summary(
    db: Session,
    batch_id: str,
    summary: Dict[str, Any]
) -> Optional[BatchScan]:
    """Update batch scan summary statistics."""
    batch = get_batch_scan(db, batch_id)
    if batch:
        batch.summary = summary
        batch.updated_at = datetime.now()
        db.commit()
        db.refresh(batch)
    return batch


def delete_batch_scan(db: Session, batch_id: str) -> bool:
    """Delete a batch scan and all its scans."""
    batch = get_batch_scan(db, batch_id)
    if batch:
        db.delete(batch)  # CASCADE will delete related scans
        db.commit()
        return True
    return False


# ============================================================================
# Statistics & Reporting
# ============================================================================

def get_scan_statistics(db: Session) -> Dict[str, Any]:
    """Get overall scan statistics."""
    total_scans = db.query(Scan).count()
    completed = db.query(Scan).filter(Scan.status == "completed").count()
    failed = db.query(Scan).filter(Scan.status == "failed").count()
    running = db.query(Scan).filter(Scan.status == "running").count()
    queued = db.query(Scan).filter(Scan.status == "queued").count()

    return {
        "total_scans": total_scans,
        "completed": completed,
        "failed": failed,
        "running": running,
        "queued": queued,
        "success_rate": (completed / total_scans * 100) if total_scans > 0 else 0
    }


def get_batch_statistics(db: Session) -> Dict[str, Any]:
    """Get overall batch scan statistics."""
    total_batches = db.query(BatchScan).count()
    completed = db.query(BatchScan).filter(BatchScan.status == "completed").count()
    partial = db.query(BatchScan).filter(BatchScan.status == "partial").count()
    failed = db.query(BatchScan).filter(BatchScan.status == "failed").count()
    running = db.query(BatchScan).filter(BatchScan.status == "running").count()

    return {
        "total_batches": total_batches,
        "completed": completed,
        "partial": partial,
        "failed": failed,
        "running": running
    }
