import json
import os
from dataclasses import dataclass, asdict
from typing import List, Optional
from datetime import datetime

@dataclass
class UWFConfig:
    """Stores configuration settings for the Unified Write Filter."""
    current_status: str = "Disabled"
    next_boot_status: str = "Disabled"
    horm_enabled: str = "No"
    overlay_type: str = "RAM"
    overlay_size: str = "1024"
    warning_threshold: str = "80"
    critical_threshold: str = "90"
    protected_volumes: List[str] = None
    last_updated: str = None

    def __post_init__(self):
        """Initializes default values for protected volumes and timestamp."""
        if self.protected_volumes is None:
            self.protected_volumes = []
        if self.last_updated is None:
            self.last_updated = datetime.now().isoformat()

class ConfigManager:
    """Manages UWF configuration file operations."""
    def __init__(self):
        """Sets up configuration directory and initial settings."""
        self.config_dir = "C:\\UWFConfiguration"
        self.config_file = os.path.join(self.config_dir, "uwf_config.json")
        self.config = UWFConfig()
        self.initialize_config()

    def initialize_config(self):
        """Creates or loads the configuration file."""
        try:
            if not os.path.exists(self.config_dir):
                os.makedirs(self.config_dir)

            if os.path.exists(self.config_file):
                self.load_config()
            else:
                self.save_config()
        except Exception as e:
            raise RuntimeError(f"Configuration initialization failed: {str(e)}")

    def load_config(self):
        """Reads configuration from JSON file."""
        try:
            with open(self.config_file, 'r') as f:
                data = json.load(f)
                self.config = UWFConfig(**data)
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {str(e)}")

    def save_config(self):
        """Writes current configuration to JSON file."""
        try:
            self.config.last_updated = datetime.now().isoformat()
            with open(self.config_file, 'w') as f:
                json.dump(asdict(self.config), f, indent=4)
        except Exception as e:
            raise RuntimeError(f"Failed to save configuration: {str(e)}")

    def update_config(self, **kwargs):
        """Updates configuration with provided values."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        self.save_config()

    def get_config(self) -> UWFConfig:
        """Returns current configuration object."""
        return self.config

    def add_protected_volume(self, volume: str):
        """Adds a volume to protected volumes list."""
        if volume not in self.config.protected_volumes:
            self.config.protected_volumes.append(volume)
            self.save_config()

    def remove_protected_volume(self, volume: str):
        """Removes a volume from protected volumes list."""
        if volume in self.config.protected_volumes:
            self.config.protected_volumes.remove(volume)
            self.save_config()

    def set_overlay_config(self, overlay_type: str, size: str,
                         warning_threshold: str, critical_threshold: str):
        """Updates overlay configuration settings."""
        self.config.overlay_type = overlay_type
        self.config.overlay_size = size
        self.config.warning_threshold = warning_threshold
        self.config.critical_threshold = critical_threshold
        self.save_config()

    def set_uwf_status(self, current_status: str, next_boot_status: str):
        """Updates UWF status settings."""
        self.config.current_status = current_status
        self.config.next_boot_status = next_boot_status
        self.save_config()