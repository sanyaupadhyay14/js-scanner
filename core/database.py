# core/database.py
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Text, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import config

# Database setup
engine = create_engine(config.get_database_url())
Session = sessionmaker(bind=engine)
Base = declarative_base()


# Database Models
class Asset(Base):
    __tablename__ = 'assets'
    domain = Column(String, primary_key=True)
    js_url = Column(String, primary_key=True)
    latest_sha1 = Column(String)
    latest_etag = Column(String)
    latest_last_modified = Column(String)
    is_vendor = Column(Boolean)
    last_seen_at = Column(DateTime)


class Finding(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String)
    js_url = Column(String)
    sha1 = Column(String)
    rule_id = Column(String)
    excerpt = Column(Text)
    ts = Column(DateTime)


class DatabaseManager:
    """Database operations manager."""
    
    @staticmethod
    def init_db():
        """Initialize database tables."""
        Base.metadata.create_all(engine)
    
    @staticmethod
    def get_asset(domain, js_url):
        """Get asset from database."""
        session = Session()
        try:
            asset = session.query(Asset).filter_by(domain=domain, js_url=js_url).first()
            if asset:
                return {
                    'domain': asset.domain,
                    'js_url': asset.js_url,
                    'latest_sha1': asset.latest_sha1,
                    'latest_etag': asset.latest_etag,
                    'latest_last_modified': asset.latest_last_modified,
                    'is_vendor': asset.is_vendor,
                    'last_seen_at': asset.last_seen_at
                }
            return None
        finally:
            session.close()
    
    @staticmethod
    def update_asset(domain, js_url, sha1, etag, last_modified, is_vendor):
        """Update or create asset in database."""
        session = Session()
        try:
            asset = session.query(Asset).filter_by(domain=domain, js_url=js_url).first()
            current_time = datetime.now()
            
            if asset:
                asset.latest_sha1 = sha1
                asset.latest_etag = etag
                asset.latest_last_modified = last_modified
                asset.is_vendor = is_vendor
                asset.last_seen_at = current_time
            else:
                asset = Asset(
                    domain=domain,
                    js_url=js_url,
                    latest_sha1=sha1,
                    latest_etag=etag,
                    latest_last_modified=last_modified,
                    is_vendor=is_vendor,
                    last_seen_at=current_time
                )
                session.add(asset)
            
            session.commit()
        finally:
            session.close()
    
    @staticmethod
    def add_finding(domain, js_url, sha1, rule_id, excerpt):
        """Add finding to database."""
        session = Session()
        try:
            current_time = datetime.now()
            finding = Finding(
                domain=domain,
                js_url=js_url,
                sha1=sha1,
                rule_id=rule_id,
                excerpt=excerpt,
                ts=current_time
            )
            session.add(finding)
            session.commit()
        finally:
            session.close()


# Global database manager instance
db = DatabaseManager()