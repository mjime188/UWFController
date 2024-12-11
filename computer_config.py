"""Created by Mark Jimenez, Bryan Arango Cruz, Francisco Cuello"""
"""CIS5370 Group 8 Final Project UWF Controller"""
"""UWF Controller"""
import json
import os
from dataclasses import dataclass, asdict
from typing import List, Optional
from datetime import datetime
import subprocess

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
    file_exclusions: List[str] = None
    registry_exclusions: List[str] = None
    last_updated: str = None

    def __post_init__(self):
        """Initializes default values for lists and timestamp."""
        if self.protected_volumes is None:
            self.protected_volumes = []
        if self.file_exclusions is None:
            self.file_exclusions = []
        if self.registry_exclusions is None:
            self.registry_exclusions = []
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
                self.config.file_exclusions = ["C:\\UWFConfiguration"]
                self.save_config()

            if os.path.exists(self.config_file):
                self.load_config()
            else:
                self.config.file_exclusions = ["C:\\UWFConfiguration"]
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

    def update_exclusions(self):
        """Updates exclusions from current system state."""
        try:
            result = subprocess.run([os.path.join("batch_scripts", "uwf_batch_scripts.bat"),
                                   "get_exclusions"],
                                  capture_output=True, text=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                file_exclusions = []
                registry_exclusions = []
                section = None

                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if "File/Folder Exclusions:" in line:
                        section = "file"
                    elif "Registry Exclusions:" in line:
                        section = "registry"
                    elif line and section == "file":
                        file_exclusions.append(line)
                    elif line and section == "registry":
                        registry_exclusions.append(line)

                self.config.file_exclusions = file_exclusions
                self.config.registry_exclusions = registry_exclusions
                self.save_config()
        except Exception as e:
            print(f"Failed to update exclusions: {str(e)}")

    def add_file_exclusion(self, path: str):
        """Adds a file/folder exclusion."""
        if path not in self.config.file_exclusions:
            self.config.file_exclusions.append(path)
            self.save_config()
            self.update_exclusions()

    def remove_file_exclusion(self, path: str):
        """Removes a file/folder exclusion."""
        if path in self.config.file_exclusions:
            self.config.file_exclusions.remove(path)
            self.save_config()
            self.update_exclusions()

    def add_registry_exclusion(self, key: str):
        """Adds a registry key exclusion."""
        if key not in self.config.registry_exclusions:
            self.config.registry_exclusions.append(key)
            self.save_config()
            self.update_exclusions()

    def remove_registry_exclusion(self, key: str):
        """Removes a registry key exclusion."""
        if key in self.config.registry_exclusions:
            self.config.registry_exclusions.remove(key)
            self.save_config()
            self.update_exclusions()