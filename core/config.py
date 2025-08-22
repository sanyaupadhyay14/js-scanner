# core/config.py
import os
import yaml
import logging
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for the scanner application."""
    
    def __init__(self):
        # Load environment variables
        load_dotenv()
        
        # Database configuration
        self.DB_HOST = os.getenv("DB_HOST", "localhost")
        self.DB_PORT = os.getenv("DB_PORT", "5432")
        self.DB_NAME = os.getenv("DB_NAME", "scannerdb")
        self.DB_USER = os.getenv("DB_USER", "sanyakumari")
        self.DB_PASSWORD = os.getenv("DB_PASSWORD", "")
        self.BLOBS_DIR = os.getenv("BLOBS_DIR", "storage/blobs")
        
        # Load YAML configurations
        self.app_config = self._load_yaml_config("config.yaml")
        self.rules_config = self._load_yaml_config("rules.yaml")
    
    def _load_yaml_config(self, filename):
        """Load YAML configuration file."""
        try:
            with open(filename, "r") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file {filename} not found")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing {filename}: {e}")
            return {}
    
    def get_database_url(self):
        """Get PostgreSQL connection URL."""
        return f"postgresql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    @property
    def timeout_secs(self):
        return self.app_config.get("timeout_secs", 30)
    
    @property
    def concurrency(self):
        return self.app_config.get("concurrency", 10)
    
    @property
    def per_domain_rate_limit(self):
        return self.app_config.get("per_domain_rate_limit", 2)
    
    @property
    def scan_interval_hours(self):
        return self.app_config.get("scan_interval_hours", 24)
    
    @property
    def user_agent(self):
        return self.app_config.get("user_agent", "Mozilla/5.0 (compatible; JSScanner/1.0)")
    
    @property
    def rescan_unchanged_secret_check(self):
        return self.app_config.get("rescan_unchanged_secret_check", False)
    
    @property
    def rules(self):
        return self.rules_config.get("rules", [])
    
    @property
    def mask_percent(self):
        return self.rules_config.get("mask_percent", 70)


# Global config instance
config = Config()