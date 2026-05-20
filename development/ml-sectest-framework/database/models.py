"""
SQLAlchemy Database Models for ML-SecTest Framework
====================================================

Defines database schema for scans, batches, and results using SQLAlchemy ORM.
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import uuid

Base = declarative_base()


def generate_uuid():
    """Generate UUID string for primary keys."""
    return str(uuid.uuid4())


class Scan(Base):
    """
    Individual scan record.

    Stores configuration and status for a single security scan.
    """
    __tablename__ = "scans"

    # Primary key
    scan_id = Column(String(36), primary_key=True, default=generate_uuid)

    # Scan configuration
    target_url = Column(String(512), nullable=False, index=True)
    challenge_name = Column(String(128), nullable=False, default="custom")
    agents = Column(JSON, nullable=True)  # List of agent names
    parallel = Column(Boolean, default=False)
    timeout = Column(Integer, default=300)
    report_format = Column(String(32), default="json")

    # Status tracking
    status = Column(String(32), nullable=False, default="queued", index=True)
    # Status values: queued, running, completed, failed

    # Timestamps
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Results (JSON blob for flexibility)
    result = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)

    # Duration in seconds
    duration_seconds = Column(Float, nullable=True)

    # Foreign key for batch scans
    batch_id = Column(String(36), ForeignKey("batch_scans.batch_id"), nullable=True, index=True)

    # Relationship to batch
    batch = relationship("BatchScan", back_populates="scans")

    def to_dict(self):
        """Convert model to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "challenge_name": self.challenge_name,
            "agents": self.agents,
            "parallel": self.parallel,
            "timeout": self.timeout,
            "report_format": self.report_format,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "batch_id": self.batch_id
        }


class BatchScan(Base):
    """
    Batch scan record.

    Groups multiple scans together for coordinated execution.
    """
    __tablename__ = "batch_scans"

    # Primary key
    batch_id = Column(String(36), primary_key=True, default=generate_uuid)

    # Batch metadata
    filename = Column(String(256), nullable=True)
    file_format = Column(String(32), nullable=True)  # csv, json

    # Status tracking
    status = Column(String(32), nullable=False, default="queued", index=True)
    # Status values: queued, running, completed, failed, partial

    # Scan counts
    total_scans = Column(Integer, default=0)
    completed_scans = Column(Integer, default=0)
    failed_scans = Column(Integer, default=0)
    running_scans = Column(Integer, default=0)
    queued_scans = Column(Integer, default=0)

    # Timestamps
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    # Duration in seconds
    duration_seconds = Column(Float, nullable=True)

    # Summary statistics (JSON for flexibility)
    summary = Column(JSON, nullable=True)

    # Relationship to scans
    scans = relationship("Scan", back_populates="batch", cascade="all, delete-orphan")

    def to_dict(self):
        """Convert model to dictionary."""
        return {
            "batch_id": self.batch_id,
            "filename": self.filename,
            "file_format": self.file_format,
            "status": self.status,
            "total_scans": self.total_scans,
            "completed_scans": self.completed_scans,
            "failed_scans": self.failed_scans,
            "running_scans": self.running_scans,
            "queued_scans": self.queued_scans,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "summary": self.summary
        }

    def calculate_progress(self) -> int:
        """Calculate progress percentage."""
        if self.total_scans == 0:
            return 0
        completed = self.completed_scans + self.failed_scans
        return int((completed / self.total_scans) * 100)
