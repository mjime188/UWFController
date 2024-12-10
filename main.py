import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import subprocess
import os
from datetime import datetime
import re
from typing import Optional, List, Dict, Tuple
from computer_config import ConfigManager
from script_protection import ScriptIntegrityChecker


class InputValidator:
    """Validates user input for UWF settings."""

    @staticmethod
    def validate_volume(volume: str) -> bool:
        """Checks if volume string matches drive letter format."""
        return bool(re.match(r'^[A-Za-z]:$', volume))

    @staticmethod
    def validate_size(size: str) -> bool:
        """Validates overlay size is within acceptable range."""
        try:
            value = int(size)
            return 0 < value <= 1024000
        except ValueError:
            return False

    @staticmethod
    def validate_threshold(threshold: str) -> bool:
        """Validates threshold is between 0 and 100 percent."""
        try:
            value = int(threshold)
            return 0 <= value <= 100
        except ValueError:
            return False


class UWFManager:
    """Manages UWF configuration and UI."""

    def __init__(self, master: tk.Tk):
        """Initializes UI components and configuration."""
        self.root = master
        self.root.title("UWF Controller")
        self.root.geometry("1024x600")

        self.config_manager = ConfigManager()
        self.startup_logs: List[Tuple[str, str]] = []

        self.script_checker = ScriptIntegrityChecker()
        if not os.path.exists(self.script_checker.hash_path):
            self.script_checker.store_hash()
            self.startup_log("Initial script integrity hash stored", "info")

        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)

        config = self.config_manager.get_config()
        self.current_status = config.current_status
        self.next_boot_status = config.next_boot_status
        self.protected_volumes = config.protected_volumes
        self.overlay_type = config.overlay_type
        self.overlay_size = config.overlay_size
        self.overlay_warning = config.warning_threshold
        self.overlay_critical = config.critical_threshold
        self.horm_enabled = config.horm_enabled

        self.setup_config_exclusion()

        self.create_sidebar()
        self.create_main_content()
        self.create_feedback_panel()
        self.create_exclusions_panel()

        for msg, msg_type in self.startup_logs:
            self.add_feedback(msg, msg_type)

        self.update_status()
        self.show_dashboard()

        self.status_update_interval = 30000
        self._schedule_status_update()

    def setup_config_exclusion(self) -> None:
        """Sets up UWF configuration folder exclusion."""
        try:
            if self.run_batch_script("initialize_exclusions"):
                self.startup_log("UWF Configuration folder exclusion initialized", "success")
            else:
                self.startup_log("Failed to initialize UWF Configuration folder exclusion", "error")
        except Exception as e:
            self.startup_log(f"Failed to set up UWF Configuration folder exclusion: {str(e)}", "error")

    def startup_log(self, message: str, message_type: str = "info") -> None:
        """Adds message to startup log queue."""
        self.startup_logs.append((message, message_type))

    def create_sidebar(self) -> None:
        """Creates navigation sidebar."""
        self.sidebar = ttk.Frame(self.main_container, style='Sidebar.TFrame')
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)

        title_label = ttk.Label(self.sidebar, text="UWF Controller",
                                style='SidebarTitle.TLabel')
        title_label.pack(pady=20, padx=20)

        self.create_nav_button("Dashboard", self.show_dashboard)
        self.create_nav_button("Status", self.show_status)
        self.create_nav_button("Settings", self.show_settings)

        ttk.Button(self.sidebar, text="Refresh Status",
                   command=self.update_status,
                   style='Sidebar.TButton',
                   width=20).pack(pady=20, padx=10)

        version_label = ttk.Label(self.sidebar, text="CIS5027 Group 8",
                                  style='Version.TLabel')
        version_label.pack(side=tk.BOTTOM, pady=10, padx=20)

    def create_nav_button(self, text: str, command: callable) -> None:
        """Creates navigation button with specified text and command."""
        btn = ttk.Button(self.sidebar, text=text, command=command,
                         style='Sidebar.TButton', width=20)
        btn.pack(pady=5, padx=10)

    def create_main_content(self) -> None:
        """Creates main content area frames."""
        self.main_content = ttk.Frame(self.main_container, style='Main.TFrame')
        self.main_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.dashboard_frame = ttk.Frame(self.main_content)
        self.status_frame = ttk.Frame(self.main_content)
        self.settings_frame = ttk.Frame(self.main_content)

    def create_feedback_panel(self) -> None:
        """Creates feedback panel for system messages."""
        self.feedback_frame = ttk.LabelFrame(self.main_container, text="System Messages")
        self.feedback_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=10, pady=10)

        self.feedback_text = tk.Text(self.feedback_frame, wrap=tk.WORD, width=40, height=30)
        self.feedback_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(self.feedback_frame, orient=tk.VERTICAL,
                                  command=self.feedback_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.feedback_text.configure(yscrollcommand=scrollbar.set)
        self.feedback_text.configure(state='disabled')

        self.feedback_text.tag_configure("success", foreground="green")
        self.feedback_text.tag_configure("error", foreground="red")
        self.feedback_text.tag_configure("info", foreground="black")

    def add_feedback(self, message: str, message_type: str = "info") -> None:
        """Adds message to feedback panel with timestamp."""
        if hasattr(self, 'feedback_text'):
            self.feedback_text.configure(state='normal')
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.feedback_text.insert(tk.END, f"[{timestamp}] ", "info")
            self.feedback_text.insert(tk.END, f"{message}\n", message_type)
            self.feedback_text.see(tk.END)
            self.feedback_text.configure(state='disabled')

    def run_batch_script(self, script_name: str, *args, return_output: bool = False) -> Optional[str]:
        """Executes UWF management batch script."""
        if not self.script_checker.verify_integrity():
            self.add_feedback("WARNING: Batch script has been modified! Command execution blocked.", "error")
            messagebox.showerror("Security Error",
                                 "The UWF control script has been modified and may be compromised.\n"
                                 "Command execution has been blocked for security.")
            return None

        ALLOWED_COMMANDS = {
            "enable_uwf", "disable_uwf", "get_uwf_status",
            "protect_volume", "unprotect_volume", "set_overlay_config",
            "initialize_exclusions", "get_exclusions", "add_file_exclusion",
            "remove_file_exclusion", "add_registry_exclusion", "remove_registry_exclusion"
        }

        if script_name not in ALLOWED_COMMANDS:
            self.add_feedback("Invalid command attempted", "error")
            return None

        sanitized_args = []
        for arg in args:
            if not isinstance(arg, str):
                self.add_feedback("Invalid argument type", "error")
                return None
            sanitized = ''.join(c for c in arg if c.isalnum() or c in '.:_-')
            sanitized_args.append(sanitized)

        script_path = os.path.join("batch_scripts", "uwf_batch_scripts.bat")
        try:
            cmd = [script_path, script_name] + sanitized_args
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)

            if return_output:
                return result.stdout

            if result.returncode == 0:
                self.add_feedback(f"{script_name}: {result.stdout}", "success")
                return True
            else:
                self.add_feedback(f"{script_name} Error: {result.stderr}", "error")
                return False

        except FileNotFoundError:
            self.add_feedback(f"File not found: {script_path}", "error")
            return False
        except Exception as e:
            self.add_feedback(f"Error executing {script_name}: {str(e)}", "error")
            return False

    def _schedule_status_update(self) -> None:
        """Schedules periodic status updates."""
        self.update_status()
        self.root.after(self.status_update_interval, self._schedule_status_update)

    def update_config_from_current_state(self) -> None:
        """Updates configuration with current UI state."""
        self.config_manager.update_config(
            current_status=self.current_status,
            next_boot_status=self.next_boot_status,
            horm_enabled=self.horm_enabled,
            overlay_type=self.overlay_type,
            overlay_size=self.overlay_size,
            warning_threshold=self.overlay_warning,
            critical_threshold=self.overlay_critical,
            protected_volumes=self.protected_volumes
        )

    def enable_uwf(self) -> None:
        """Enables UWF protection."""
        if messagebox.askyesno("Confirm Action",
                               "Are you sure you want to enable UWF?"):
            self._show_loading()
            if self.run_batch_script("enable_uwf"):
                self.current_status = "Enabled"
                self.next_boot_status = "Enabled"
                self.config_manager.set_uwf_status("Enabled", "Enabled")
                self.update_status()
            self._hide_loading()

    def disable_uwf(self) -> None:
        """Disables UWF protection."""
        if messagebox.askyesno("Confirm Action",
                               "Are you sure you want to disable UWF?"):
            self._show_loading()
            if self.run_batch_script("disable_uwf"):
                self.current_status = "Disabled"
                self.next_boot_status = "Disabled"
                self.config_manager.set_uwf_status("Disabled", "Disabled")
                self.update_status()
            self._hide_loading()

    def protect_volume(self, volume: str) -> None:
        """Adds volume to UWF protection."""
        drive = volume.split(" ")[0]
        if not InputValidator.validate_volume(drive):
            self.add_feedback(f"Invalid volume format: {drive}", "error")
            return

        if messagebox.askyesno("Confirm Action",
                               f"Are you sure you want to protect volume {drive}?"):
            self._show_loading()
            if self.run_batch_script("protect_volume", drive):
                if drive not in self.protected_volumes:
                    self.protected_volumes.append(drive)
                self.config_manager.add_protected_volume(drive)
                self.update_status()
            self._hide_loading()

    def unprotect_volume(self, volume: str) -> None:
        """Removes volume from UWF protection."""
        drive = volume.split(" ")[0]
        if not InputValidator.validate_volume(drive):
            self.add_feedback(f"Invalid volume format: {drive}", "error")
            return

        if messagebox.askyesno("Confirm Action",
                               f"Are you sure you want to unprotect volume {drive}?"):
            self._show_loading()
            if self.run_batch_script("unprotect_volume", drive):
                if drive in self.protected_volumes:
                    self.protected_volumes.remove(drive)
                self.config_manager.remove_protected_volume(drive)
                self.update_status()
            self._hide_loading()

    def apply_overlay_settings(self) -> None:
        """Applies overlay configuration changes."""
        try:
            overlay_type = self.overlay_type_var.get()
            max_size = self.max_size_entry.get()
            warning_threshold = self.warning_threshold_entry.get()
            critical_threshold = self.critical_threshold_entry.get()

            if not InputValidator.validate_size(max_size):
                raise ValueError("Invalid size value")
            if not InputValidator.validate_threshold(warning_threshold):
                raise ValueError("Invalid warning threshold")
            if not InputValidator.validate_threshold(critical_threshold):
                raise ValueError("Invalid critical threshold")

            max_size = int(max_size)
            warning_threshold = int(warning_threshold)
            critical_threshold = int(critical_threshold)

            if warning_threshold >= critical_threshold:
                raise ValueError("Warning threshold must be less than critical threshold")

            if messagebox.askyesno("Confirm Action",
                                   "Are you sure you want to apply these overlay settings?"):
                self._show_loading()
                if self.run_batch_script("set_overlay_config", overlay_type, str(max_size),
                                         str(warning_threshold), str(critical_threshold)):
                    self.config_manager.set_overlay_config(
                        overlay_type,
                        str(max_size),
                        str(warning_threshold),
                        str(critical_threshold)
                    )

                    self.overlay_type = overlay_type
                    self.overlay_size = str(max_size)
                    self.overlay_warning = str(warning_threshold)
                    self.overlay_critical = str(critical_threshold)

                    self.update_status()
                self._hide_loading()

        except ValueError as e:
            self.add_feedback(f"Invalid input: {str(e)}", "error")
            messagebox.showerror("Error", str(e))

    def update_status(self) -> None:
        """Updates UWF status from system."""
        try:
            result = self.run_batch_script("get_uwf_status", return_output=True)
            if isinstance(result, str):
                config_lines = result.split('\n')
                status_updated = False
                volumes_updated = False
                file_exclusions = []
                registry_exclusions = []
                current_section = ""

                for line in config_lines:
                    line = line.strip()
                    if "Current Status:" in line or "Filter Status:" in line:
                        new_status = "Enabled" if "Enabled" in line else "Disabled"
                        if self.current_status != new_status:
                            self.current_status = new_status
                            status_updated = True

                    elif "Next Boot Status:" in line:
                        new_boot_status = "Enabled" if "Enabled" in line else "Disabled"
                        if self.next_boot_status != new_boot_status:
                            self.next_boot_status = new_boot_status
                            status_updated = True

                    elif "Overlay Type:" in line:
                        self.overlay_type = line.split(':')[1].strip()
                    elif "Maximum Size:" in line:
                        size = line.split(':')[1].strip()
                        self.overlay_size = size.split()[0]
                    elif "Warning Threshold:" in line:
                        threshold = line.split(':')[1].strip()
                        self.overlay_warning = threshold.rstrip('%')
                    elif "Critical Threshold:" in line:
                        threshold = line.split(':')[1].strip()
                        self.overlay_critical = threshold.rstrip('%')
                    elif "HORM Status:" in line:
                        self.horm_enabled = "Yes" if "Enabled" in line else "No"
                        status_updated = True
                    elif "Protected Volumes:" in line:
                        current_section = "volumes"
                    elif "File Exclusions:" in line:
                        current_section = "file"
                    elif "Registry Exclusions:" in line:
                        current_section = "registry"
                    elif line and current_section == "volumes" and ":" in line:
                        if line.strip() not in self.protected_volumes:
                            self.protected_volumes.append(line.strip())
                            volumes_updated = True
                    elif line and current_section == "file":
                        file_exclusions.append(line)
                    elif line and current_section == "registry":
                        registry_exclusions.append(line)

                self.config_manager.update_config(
                    file_exclusions=file_exclusions,
                    registry_exclusions=registry_exclusions
                )

                if status_updated or volumes_updated:
                    self.update_config_from_current_state()

                if hasattr(self, 'status_frame') and self.status_frame.winfo_viewable():
                    self.show_status()
                if hasattr(self, 'dashboard_frame') and self.dashboard_frame.winfo_viewable():
                    self.show_dashboard()

                if status_updated or volumes_updated:
                    self.add_feedback("Status updated successfully", "info")
            else:
                self.add_feedback("Failed to get status: Invalid response", "error")

        except Exception as e:
            self.add_feedback(f"Failed to update status: {str(e)}", "error")

    def show_dashboard(self) -> None:
        """Displays dashboard view with current UWF status."""
        self.hide_all_frames()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        for widget in self.dashboard_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.dashboard_frame, text="Dashboard",
                  style='Title.TLabel').pack(anchor=tk.W, pady=(0, 20))

        status_frame = ttk.LabelFrame(self.dashboard_frame, text="UWF Status")
        status_frame.pack(fill=tk.X, pady=10)

        ttk.Label(status_frame, text="Current Status:").grid(row=0, column=0, padx=10, pady=5)
        status_label = ttk.Label(status_frame, text=self.current_status)
        status_label.grid(row=0, column=1, padx=10, pady=5)

        if self.current_status == "Enabled":
            status_label.configure(foreground="green")
        else:
            status_label.configure(foreground="red")

        button_frame = ttk.Frame(status_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Enable UWF",
                   command=self.enable_uwf).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Disable UWF",
                   command=self.disable_uwf).pack(side=tk.LEFT, padx=5)

        volumes_frame = ttk.LabelFrame(self.dashboard_frame, text="Protected Volumes")
        volumes_frame.pack(fill=tk.X, pady=10)

        if self.protected_volumes:
            for volume in self.protected_volumes:
                ttk.Label(volumes_frame, text=volume).pack(pady=2)
        else:
            ttk.Label(volumes_frame, text="No volumes protected").pack(pady=10)

    def show_status(self) -> None:
        """Displays detailed status view of UWF configuration."""
        self.hide_all_frames()
        self.status_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        for widget in self.status_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.status_frame, text="UWF Status",
                  style='Title.TLabel').pack(anchor=tk.W, pady=(0, 20))

        filter_frame = ttk.LabelFrame(self.status_frame, text="Filter Status")
        filter_frame.pack(fill=tk.X, pady=10)

        self.create_status_row(filter_frame, "Current Status:", self.current_status, 0)
        self.create_status_row(filter_frame, "Next Boot Status:", self.next_boot_status, 1)
        self.create_status_row(filter_frame, "HORM Enabled:", self.horm_enabled, 2)

        overlay_frame = ttk.LabelFrame(self.status_frame, text="Overlay Configuration")
        overlay_frame.pack(fill=tk.X, pady=10)

        self.create_status_row(overlay_frame, "Type:", self.overlay_type, 0)
        self.create_status_row(overlay_frame, "Maximum Size:", f"{self.overlay_size} MB", 1)
        self.create_status_row(overlay_frame, "Warning Threshold:", f"{self.overlay_warning}%", 2)
        self.create_status_row(overlay_frame, "Critical Threshold:", f"{self.overlay_critical}%", 3)

        volumes_frame = ttk.LabelFrame(self.status_frame, text="Protected Volumes")
        volumes_frame.pack(fill=tk.X, pady=10)

        if self.protected_volumes:
            canvas = tk.Canvas(volumes_frame, height=100)
            scrollbar = ttk.Scrollbar(volumes_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            for volume in self.protected_volumes:
                ttk.Label(scrollable_frame, text=volume).pack(pady=2)

            canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
            scrollbar.pack(side="right", fill="y")
        else:
            ttk.Label(volumes_frame, text="No volumes are currently protected.").pack(pady=10)

        exclusions_frame = ttk.LabelFrame(self.status_frame, text="Exclusions")
        exclusions_frame.pack(fill=tk.X, pady=10)

        config = self.config_manager.get_config()
        if config.file_exclusions or config.registry_exclusions:
            canvas = tk.Canvas(exclusions_frame, height=100)
            scrollbar = ttk.Scrollbar(exclusions_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            if config.file_exclusions:
                ttk.Label(scrollable_frame, text="File/Folder Exclusions:",
                          font=('Segoe UI', 9, 'bold')).pack(pady=2)
                for exclusion in config.file_exclusions:
                    ttk.Label(scrollable_frame, text=exclusion).pack(pady=1)

            if config.registry_exclusions:
                ttk.Label(scrollable_frame, text="Registry Exclusions:",
                          font=('Segoe UI', 9, 'bold')).pack(pady=2)
                for exclusion in config.registry_exclusions:
                    ttk.Label(scrollable_frame, text=exclusion).pack(pady=1)

            canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
            scrollbar.pack(side="right", fill="y")
        else:
            ttk.Label(exclusions_frame, text="No exclusions configured.").pack(pady=10)


    def show_settings(self) -> None:
        """Displays settings view for UWF configuration."""
        self.hide_all_frames()
        self.settings_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        for widget in self.settings_frame.winfo_children():
            widget.destroy()

        ttk.Label(self.settings_frame, text="Settings",
                  style='Title.TLabel').pack(anchor=tk.W, pady=(0, 20))

        volume_frame = ttk.LabelFrame(self.settings_frame, text="Volume Protection")
        volume_frame.pack(fill=tk.X, pady=10)

        volume_select_frame = ttk.Frame(volume_frame)
        volume_select_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(volume_select_frame, text="Select Volume:").pack(side=tk.LEFT)

        volumes = ["C: (System)", "D: (Data)"]
        volume_combo = ttk.Combobox(volume_select_frame, values=volumes, state="readonly")
        volume_combo.set(volumes[0])
        volume_combo.pack(side=tk.LEFT, padx=(10, 0))

        button_frame = ttk.Frame(volume_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(button_frame, text="Enable Protection",
                   command=lambda: self.protect_volume(volume_combo.get())).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Disable Protection",
                   command=lambda: self.unprotect_volume(volume_combo.get())).pack(side=tk.LEFT, padx=5)

        overlay_frame = ttk.LabelFrame(self.settings_frame, text="Overlay Configuration")
        overlay_frame.pack(fill=tk.X, pady=10)

        type_frame = ttk.Frame(overlay_frame)
        type_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(type_frame, text="Overlay Type:").pack(side=tk.LEFT)
        self.overlay_type_var = ttk.Combobox(type_frame, values=["RAM", "DISK"], state="readonly")
        self.overlay_type_var.set(self.overlay_type)
        self.overlay_type_var.pack(side=tk.LEFT, padx=(10, 0))

        self.max_size_entry = self.create_setting_entry(
            overlay_frame, "Maximum Size (MB):", self.overlay_size,
            "Maximum size of overlay in megabytes (MB)"
        )
        self.warning_threshold_entry = self.create_setting_entry(
            overlay_frame, "Warning Threshold (%):", self.overlay_warning,
            "Percentage at which to show warning (0-100)"
        )
        self.critical_threshold_entry = self.create_setting_entry(
            overlay_frame, "Critical Threshold (%):", self.overlay_critical,
            "Percentage at which overlay becomes critical (0-100)"
        )

        ttk.Button(overlay_frame, text="Apply Overlay Settings",
                   command=self.apply_overlay_settings).pack(pady=10)

        self.create_exclusions_panel()

    def create_status_row(self, parent: ttk.Frame, label_text: str, value_text: str, row: int) -> None:
        """Creates a row in the status display with label and value."""
        ttk.Label(parent, text=label_text).grid(row=row, column=0, padx=10, pady=5, sticky=tk.W)
        value_label = ttk.Label(parent, text=value_text)
        value_label.grid(row=row, column=1, padx=10, pady=5, sticky=tk.W)

        if label_text == "Current Status:" or label_text == "Next Boot Status:":
            if value_text == "Enabled":
                value_label.configure(foreground="green")
            else:
                value_label.configure(foreground="red")

    def create_setting_entry(self, parent: ttk.Frame, label_text: str, default_value: str,
                             tooltip_text: str = "") -> ttk.Entry:
        """Creates a settings entry field with label and optional tooltip."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(frame, text=label_text).pack(side=tk.LEFT)
        entry = ttk.Entry(frame)
        entry.insert(0, default_value)
        entry.pack(side=tk.LEFT, padx=(10, 0))

        if tooltip_text:
            self._create_tooltip(entry, tooltip_text)

        return entry

    def create_exclusions_panel(self) -> None:
        """Creates panels for managing file and registry exclusions."""
        # File Exclusions Frame
        file_frame = ttk.LabelFrame(self.settings_frame, text="File/Folder Exclusions")
        file_frame.pack(fill=tk.X, pady=10)

        # File Entry
        file_entry_frame = ttk.Frame(file_frame)
        file_entry_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(file_entry_frame, text="Path:").pack(side=tk.LEFT)
        self.file_exclusion_entry = ttk.Entry(file_entry_frame, width=50)
        self.file_exclusion_entry.pack(side=tk.LEFT, padx=(10, 0))

        ttk.Button(file_entry_frame, text="Browse",
                   command=self._browse_file).pack(side=tk.LEFT, padx=5)

        # File Exclusion Buttons
        button_frame = ttk.Frame(file_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(button_frame, text="Add Exclusion",
                   command=self.add_file_exclusion).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Exclusion",
                   command=self.remove_file_exclusion).pack(side=tk.LEFT, padx=5)

        # Registry Exclusions Frame
        reg_frame = ttk.LabelFrame(self.settings_frame, text="Registry Exclusions")
        reg_frame.pack(fill=tk.X, pady=10)

        # Registry Entry
        reg_entry_frame = ttk.Frame(reg_frame)
        reg_entry_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(reg_entry_frame, text="Key:").pack(side=tk.LEFT)
        self.registry_exclusion_entry = ttk.Entry(reg_entry_frame, width=50)
        self.registry_exclusion_entry.pack(side=tk.LEFT, padx=(10, 0))

        # Registry Exclusion Buttons
        reg_button_frame = ttk.Frame(reg_frame)
        reg_button_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(reg_button_frame, text="Add Exclusion",
                   command=self.add_registry_exclusion).pack(side=tk.LEFT, padx=5)
        ttk.Button(reg_button_frame, text="Remove Exclusion",
                   command=self.remove_registry_exclusion).pack(side=tk.LEFT, padx=5)

        # Display current exclusions
        self.update_exclusions_display()

    def _browse_file(self) -> None:
        """Opens file browser for selecting files/folders to exclude."""
        path = filedialog.askdirectory()
        if path:
            self.file_exclusion_entry.delete(0, tk.END)
            self.file_exclusion_entry.insert(0, path)

    def add_file_exclusion(self) -> None:
        """Adds file/folder exclusion."""
        path = self.file_exclusion_entry.get().strip()
        if not path:
            messagebox.showerror("Error", "Please enter a valid path")
            return

        if self.run_batch_script("add_file_exclusion", path):
            self.config_manager.add_file_exclusion(path)
            self.update_exclusions_display()
            self.file_exclusion_entry.delete(0, tk.END)

    def remove_file_exclusion(self) -> None:
        """Removes file/folder exclusion."""
        path = self.file_exclusion_entry.get().strip()
        if not path:
            messagebox.showerror("Error", "Please enter a valid path")
            return

        if self.run_batch_script("remove_file_exclusion", path):
            self.config_manager.remove_file_exclusion(path)
            self.update_exclusions_display()
            self.file_exclusion_entry.delete(0, tk.END)

    def add_registry_exclusion(self) -> None:
        """Adds registry key exclusion."""
        key = self.registry_exclusion_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please enter a valid registry key")
            return

        if self.run_batch_script("add_registry_exclusion", key):
            self.config_manager.add_registry_exclusion(key)
            self.update_exclusions_display()
            self.registry_exclusion_entry.delete(0, tk.END)

    def remove_registry_exclusion(self) -> None:
        """Removes registry key exclusion."""
        key = self.registry_exclusion_entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Please enter a valid registry key")
            return

        if self.run_batch_script("remove_registry_exclusion", key):
            self.config_manager.remove_registry_exclusion(key)
            self.update_exclusions_display()
            self.registry_exclusion_entry.delete(0, tk.END)

    def update_exclusions_display(self) -> None:
        """Updates the display of current exclusions."""
        config = self.config_manager.get_config()

        # Update file exclusions display
        result = self.run_batch_script("get_exclusions", return_output=True)
        if isinstance(result, str):
            # Parse and update the config with current exclusions
            file_section = False
            registry_section = False
            file_exclusions = []
            registry_exclusions = []

            for line in result.split('\n'):
                line = line.strip()
                if "File/Folder Exclusions:" in line:
                    file_section = True
                    registry_section = False
                    continue
                elif "Registry Exclusions:" in line:
                    file_section = False
                    registry_section = True
                    continue
                elif line:
                    if file_section:
                        file_exclusions.append(line)
                    elif registry_section:
                        registry_exclusions.append(line)

            config.file_exclusions = file_exclusions
            config.registry_exclusions = registry_exclusions
            self.config_manager.update_config(
                file_exclusions=file_exclusions,
                registry_exclusions=registry_exclusions
            )

    def _create_tooltip(self, widget: tk.Widget, text: str) -> None:
        """Creates a tooltip for a widget."""
        tooltip = tk.Label(widget.master, text=text, relief="solid", padx=5, pady=2)
        tooltip.place_forget()

        def enter(event):
            tooltip.lift()
            tooltip.place(x=widget.winfo_rootx() - widget.winfo_x(),
                          y=widget.winfo_rooty() - widget.winfo_y() + 25)

        def leave(event):
            tooltip.place_forget()

        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)

    def _show_loading(self) -> None:
        """Displays loading indicator."""
        self.loading_label = ttk.Label(self.main_container, text="Processing...")
        self.loading_label.place(relx=0.5, rely=0.5, anchor="center")
        self.root.update()

    def _hide_loading(self) -> None:
        """Hides loading indicator."""
        if hasattr(self, 'loading_label'):
            self.loading_label.destroy()

    def hide_all_frames(self) -> None:
        """Hides all main content frames."""
        self.dashboard_frame.pack_forget()
        self.status_frame.pack_forget()
        self.settings_frame.pack_forget()

    def __del__(self) -> None:
        """Saves configuration before object destruction."""
        try:
            self.update_config_from_current_state()
        except:
            pass


def setup_styles() -> None:
    """Configures application styles and themes."""
    style = ttk.Style()
    style.configure('Main.TFrame',
                    background='white')

    style.configure('Sidebar.TFrame',
                    background='#2B2B2B')

    style.configure('SidebarTitle.TLabel',
                    background='#2B2B2B',
                    foreground='white',
                    font=('Segoe UI', 14, 'bold'))

    style.configure('Sidebar.TButton',
                    background='#2B2B2B',
                    foreground='black',
                    font=('Segoe UI', 10))

    style.map('Sidebar.TButton',
              background=[('active', '#404040')],
              foreground=[('active', 'black')])

    style.configure('Version.TLabel',
                    background='#2B2B2B',
                    foreground='#CCCCCC',
                    font=('Segoe UI', 8))

    style.configure('Title.TLabel',
                    font=('Segoe UI', 16, 'bold'))


if __name__ == "__main__":
    root = tk.Tk()
    setup_styles()
    app = UWFManager(root)
    root.mainloop()