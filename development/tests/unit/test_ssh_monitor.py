"""
Unit tests for SSH monitor
Tests connection monitoring, retry logic, and error handling
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, call
import subprocess
import socket
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fold7_ssh_monitor import SSHMonitor


class TestSSHMonitorInit:
    """Test SSH monitor initialization"""

    def test_init_with_existing_config(self, tmp_path):
        """Test initialization with existing configuration file"""
        config_file = tmp_path / "test_config.json"
        config_data = {
            "device": {
                "name": "Test Device",
                "tailscale_hostname": "test-device",
                "ssh_port": 8022,
                "ssh_user": "testuser"
            },
            "monitoring": {
                "check_interval_seconds": 30,
                "connection_timeout_seconds": 10,
                "max_retry_attempts": 5,
                "exponential_backoff": True,
                "backoff_multiplier": 2,
                "max_backoff_seconds": 300
            },
            "reconnection": {
                "enabled": True,
                "restart_sshd_command": "sshd",
                "restart_tailscale_command": None
            },
            "notifications": {
                "log_to_file": True,
                "log_file": "test_monitor.log",
                "console_output": True,
                "notify_on_failure": True,
                "notify_on_recovery": True
            }
        }

        with open(config_file, 'w') as f:
            json.dump(config_data, f)

        monitor = SSHMonitor(str(config_file))

        assert monitor.config['device']['name'] == "Test Device"
        assert monitor.connection_failures == 0
        assert monitor.total_reconnects == 0
        assert monitor.last_success is None

    def test_init_creates_default_config(self, tmp_path):
        """Test that default config is created if missing"""
        config_file = tmp_path / "nonexistent_config.json"

        with pytest.raises(SystemExit):
            SSHMonitor(str(config_file))

        # Verify default config was created
        assert config_file.exists()

        with open(config_file, 'r') as f:
            config = json.load(f)

        assert 'device' in config
        assert 'monitoring' in config
        assert 'reconnection' in config
        assert 'notifications' in config


class TestTailscaleConnectivity:
    """Test Tailscale connectivity checking"""

    def test_check_tailscale_connectivity_success(self, tmp_path):
        """Test successful Tailscale connectivity check"""
        config_file = self._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        with patch('socket.gethostbyname', return_value='100.100.100.100'):
            result = monitor.check_tailscale_connectivity()
            assert result is True

    def test_check_tailscale_connectivity_failure(self, tmp_path):
        """Test failed Tailscale connectivity check"""
        config_file = self._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        with patch('socket.gethostbyname', side_effect=socket.gaierror("Name resolution failed")):
            result = monitor.check_tailscale_connectivity()
            assert result is False

    def test_check_tailscale_connectivity_timeout(self, tmp_path):
        """Test Tailscale connectivity timeout"""
        config_file = self._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        with patch('socket.gethostbyname', side_effect=socket.timeout("Connection timeout")):
            result = monitor.check_tailscale_connectivity()
            assert result is False

    @staticmethod
    def _create_test_config(tmp_path):
        """Helper to create test config file"""
        config_file = tmp_path / "test_config.json"
        config_data = {
            "device": {
                "name": "Test Device",
                "tailscale_hostname": "test-device",
                "ssh_port": 8022,
                "ssh_user": "testuser"
            },
            "monitoring": {
                "check_interval_seconds": 30,
                "connection_timeout_seconds": 10,
                "max_retry_attempts": 5,
                "exponential_backoff": True,
                "backoff_multiplier": 2,
                "max_backoff_seconds": 300
            },
            "reconnection": {
                "enabled": True,
                "restart_sshd_command": "sshd",
                "restart_tailscale_command": None
            },
            "notifications": {
                "log_to_file": False,
                "console_output": False,
                "notify_on_failure": True,
                "notify_on_recovery": True
            }
        }
        with open(config_file, 'w') as f:
            json.dump(config_data, f)
        return config_file


class TestSSHConnection:
    """Test SSH connection checking"""

    def test_check_ssh_connection_success(self, tmp_path):
        """Test successful SSH connection"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "connected"

        with patch('subprocess.run', return_value=mock_result):
            result = monitor.check_ssh_connection()
            assert result is True

    def test_check_ssh_connection_failure(self, tmp_path):
        """Test failed SSH connection"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        mock_result = Mock()
        mock_result.returncode = 255
        mock_result.stdout = ""

        with patch('subprocess.run', return_value=mock_result):
            result = monitor.check_ssh_connection()
            assert result is False

    def test_check_ssh_connection_timeout(self, tmp_path):
        """Test SSH connection timeout"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired("ssh", 15)):
            result = monitor.check_ssh_connection()
            assert result is False

    def test_check_ssh_connection_builds_correct_command(self, tmp_path):
        """Test that SSH command is built correctly"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "connected"

        with patch('subprocess.run', return_value=mock_result) as mock_run:
            monitor.check_ssh_connection()

            # Verify command structure
            args = mock_run.call_args[0][0]
            assert args[0] == 'ssh'
            assert '-p' in args
            assert '8022' in args
            assert 'testuser@test-device' in args


class TestExponentialBackoff:
    """Test exponential backoff calculation"""

    def test_calculate_backoff_delay_no_exponential(self, tmp_path):
        """Test backoff with exponential disabled"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))
        monitor.config['monitoring']['exponential_backoff'] = False

        delay1 = monitor.calculate_backoff_delay(1)
        delay2 = monitor.calculate_backoff_delay(5)

        assert delay1 == delay2
        assert delay1 == 30  # check_interval_seconds

    def test_calculate_backoff_delay_exponential(self, tmp_path):
        """Test exponential backoff calculation"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        delay1 = monitor.calculate_backoff_delay(1)
        delay2 = monitor.calculate_backoff_delay(2)
        delay3 = monitor.calculate_backoff_delay(3)

        assert delay1 == 30  # base_delay * (2 ** 0)
        assert delay2 == 60  # base_delay * (2 ** 1)
        assert delay3 == 120  # base_delay * (2 ** 2)

    def test_calculate_backoff_delay_max_limit(self, tmp_path):
        """Test backoff respects maximum delay"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        delay = monitor.calculate_backoff_delay(10)

        # Should not exceed max_backoff_seconds (300)
        assert delay <= 300


class TestConnectionFailureHandling:
    """Test connection failure handling logic"""

    def test_handle_connection_failure_increments_counter(self, tmp_path):
        """Test that failure counter increments"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        initial_failures = monitor.connection_failures
        monitor.handle_connection_failure()

        assert monitor.connection_failures == initial_failures + 1

    def test_handle_connection_failure_max_retries(self, tmp_path):
        """Test behavior when max retries reached"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        # Set to max retries
        monitor.connection_failures = 4

        with patch.object(monitor, 'check_tailscale_connectivity', return_value=True), \
             patch.object(monitor, 'restart_ssh_service', return_value=True):

            monitor.handle_connection_failure()

            # Counter should reset after reaching max
            assert monitor.connection_failures == 0
            assert monitor.total_reconnects == 1

    def test_handle_connection_failure_tailscale_down(self, tmp_path):
        """Test behavior when Tailscale is unreachable"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        monitor.connection_failures = 4

        with patch.object(monitor, 'check_tailscale_connectivity', return_value=False):
            monitor.handle_connection_failure()

            # Should reset counter to keep trying
            assert monitor.connection_failures == 0
            # Should NOT increment reconnect count
            assert monitor.total_reconnects == 0


class TestConnectionSuccess:
    """Test connection success handling"""

    def test_handle_connection_success_resets_failures(self, tmp_path):
        """Test that success resets failure counter"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        monitor.connection_failures = 3
        monitor.handle_connection_success()

        assert monitor.connection_failures == 0
        assert monitor.last_success is not None

    def test_handle_connection_success_tracks_recovery(self, tmp_path):
        """Test that recovery from downtime is tracked"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        from datetime import datetime, timedelta
        monitor.last_success = datetime.now() - timedelta(seconds=60)
        monitor.connection_failures = 3

        monitor.handle_connection_success()

        assert monitor.connection_failures == 0
        assert monitor.last_success is not None


class TestSSHServiceRestart:
    """Test SSH service restart logic"""

    def test_restart_ssh_service_disabled(self, tmp_path):
        """Test restart when reconnection disabled"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))
        monitor.config['reconnection']['enabled'] = False

        result = monitor.restart_ssh_service()
        assert result is False

    def test_restart_ssh_service_no_command(self, tmp_path):
        """Test restart when no command configured"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))
        monitor.config['reconnection']['restart_sshd_command'] = None

        result = monitor.restart_ssh_service()
        assert result is False

    def test_restart_ssh_service_success(self, tmp_path):
        """Test successful SSH service restart"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        with patch('subprocess.run') as mock_run, \
             patch('time.sleep'):

            result = monitor.restart_ssh_service()

            assert result is True
            mock_run.assert_called_once()

    def test_restart_ssh_service_failure(self, tmp_path):
        """Test failed SSH service restart"""
        config_file = TestTailscaleConnectivity._create_test_config(tmp_path)
        monitor = SSHMonitor(str(config_file))

        with patch('subprocess.run', side_effect=Exception("Restart failed")):
            result = monitor.restart_ssh_service()
            assert result is False


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
