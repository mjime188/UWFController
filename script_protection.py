"""Created by Mark Jimenez, Bryan Arango Cruz, Francisco Cuello"""
"""CIS5370 Group 8 Final Project UWF Controller"""
"""UWF Controller"""
import hashlib
import os
from datetime import datetime


class ScriptIntegrityChecker:
    """Verifies the integrity of UWF batch scripts."""

    def __init__(self):
        """Initializes paths for script and hash file."""
        self.script_path = os.path.join("batch_scripts", "uwf_batch_scripts.bat")
        self.hash_path = os.path.join("batch_scripts", "script.hash")

    def calculate_hash(self) -> str:
        """Generates SHA-256 hash of the batch script."""
        with open(self.script_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def store_hash(self) -> None:
        """Saves current script hash with timestamp."""
        hash_value = self.calculate_hash()
        with open(self.hash_path, 'w') as f:
            f.write(f"{hash_value}\n{datetime.now().isoformat()}")

    def verify_integrity(self) -> bool:
        """Checks if current script hash matches stored hash."""
        if not os.path.exists(self.hash_path):
            return False

        with open(self.hash_path, 'r') as f:
            stored_hash = f.read().split('\n')[0].strip()

        current_hash = self.calculate_hash()
        return stored_hash == current_hash