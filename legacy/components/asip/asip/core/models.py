from sqlalchemy import Column, String, JSON, DateTime, Float, Integer, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import uuid
import enum

Base = declarative_base()

class SeverityEnum(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class InvestigationStatusEnum(str, enum.Enum):
    pending = "pending"
    parsing = "parsing"
    running = "running"
    awaiting_password = "awaiting_password"
    completed = "completed"
    failed = "failed"

class Investigation(Base):
    __tablename__ = "investigations"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(500))
    status = Column(Enum(InvestigationStatusEnum), default=InvestigationStatusEnum.pending)
    severity = Column(Enum(SeverityEnum), default=SeverityEnum.info)
    source_platform = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Password state for encrypted archives
    password_required = Column(String(255), nullable=True)  # Name of archive requiring password
    archive_paths = Column(JSON, default=list)  # List of paths to extract
    
    # Raw alert details pasted by user
    alert_details = Column(Text, nullable=True)
    
    # Summary results
    root_cause = Column(Text, nullable=True)
    attack_summary = Column(Text, nullable=True)
    confidence_score = Column(Float, nullable=True)
    
    # Relationships
    events = relationship("NormalizedEvent", back_populates="investigation", cascade="all, delete-orphan")
    iocs = relationship("IOC", back_populates="investigation", cascade="all, delete-orphan")
    mitre_mappings = relationship("MITREMapping", back_populates="investigation", cascade="all, delete-orphan")
    timeline_entries = relationship("TimelineEntry", back_populates="investigation", cascade="all, delete-orphan")

class NormalizedEvent(Base):
    __tablename__ = "normalized_events"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_platform = Column(String(100))
    event_type = Column(String(100))  # process, network, file, auth, registry, alert
    host_name = Column(String(255), nullable=True)
    host_ip = Column(String(50), nullable=True)
    user_name = Column(String(255), nullable=True)
    process_name = Column(String(255), nullable=True)
    process_pid = Column(Integer, nullable=True)
    parent_process_name = Column(String(255), nullable=True)
    parent_process_pid = Column(Integer, nullable=True)
    commandline = Column(Text, nullable=True)
    file_path = Column(Text, nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    dst_ip = Column(String(50), nullable=True)
    dst_port = Column(Integer, nullable=True)
    raw_event = Column(JSON, nullable=True)
    tags = Column(JSON, default=list)
    
    investigation = relationship("Investigation", back_populates="events")

class IOC(Base):
    __tablename__ = "iocs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"))
    ioc_type = Column(String(50))  # ipv4, domain, sha256, url, email, registry_key, mutex, named_pipe
    value = Column(String(1000))
    confidence = Column(Float, default=1.0)
    context = Column(Text, nullable=True)
    
    # Enrichment fields
    vt_score = Column(String(50), nullable=True)
    vt_malicious_count = Column(Integer, default=0)
    abuseipdb_score = Column(Integer, default=0)
    otx_pulse_count = Column(Integer, default=0)
    threat_actor = Column(String(255), nullable=True)
    malware_family = Column(String(255), nullable=True)
    
    investigation = relationship("Investigation", back_populates="iocs")

class MITREMapping(Base):
    __tablename__ = "mitre_mappings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"))
    technique_id = Column(String(20))
    technique_name = Column(String(255))
    tactic = Column(String(100))
    evidence = Column(Text)
    confidence = Column(Float, default=1.0)
    
    investigation = relationship("Investigation", back_populates="mitre_mappings")

class TimelineEntry(Base):
    __tablename__ = "timeline_entries"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String(36), ForeignKey("investigations.id"))
    timestamp = Column(DateTime)
    event_description = Column(Text)
    event_type = Column(String(100))
    severity = Column(String(50))
    evidence_source = Column(String(255))
    
    investigation = relationship("Investigation", back_populates="timeline_entries")
