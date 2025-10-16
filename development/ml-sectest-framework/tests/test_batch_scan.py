"""
Tests for batch scanning functionality.
"""
import pytest
import tempfile
import json
import csv
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import the MLSecTest class
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from ml_sectest import MLSecTest


class TestBatchFileParser:
    """Test batch file parsing functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = MLSecTest()

    def test_parse_txt_file(self):
        """Test parsing plain text file with URLs."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("http://example.com/api1\n")
            f.write("http://example.com/api2\n")
            f.write("# This is a comment\n")
            f.write("http://example.com/api3\n")
            f.write("\n")  # Empty line
            temp_path = f.name

        try:
            targets = self.app._parse_batch_file(temp_path)

            assert len(targets) == 3
            assert targets[0]['url'] == "http://example.com/api1"
            assert targets[0]['name'] == "target_1"
            assert targets[0]['agents'] is None
            assert targets[1]['url'] == "http://example.com/api2"
            assert targets[2]['url'] == "http://example.com/api3"
        finally:
            Path(temp_path).unlink()

    def test_parse_csv_file(self):
        """Test parsing CSV file with target configurations."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'name', 'agents'])
            writer.writeheader()
            writer.writerow({
                'url': 'http://example.com/api1',
                'name': 'API Endpoint 1',
                'agents': 'prompt_injection_001;model_inversion_001'
            })
            writer.writerow({
                'url': 'http://example.com/api2',
                'name': 'API Endpoint 2',
                'agents': ''
            })
            temp_path = f.name

        try:
            targets = self.app._parse_batch_file(temp_path)

            assert len(targets) == 2
            assert targets[0]['url'] == "http://example.com/api1"
            assert targets[0]['name'] == "API Endpoint 1"
            assert targets[0]['agents'] == ['prompt_injection_001', 'model_inversion_001']
            assert targets[1]['url'] == "http://example.com/api2"
            assert targets[1]['name'] == "API Endpoint 2"
            assert targets[1]['agents'] is None
        finally:
            Path(temp_path).unlink()

    def test_parse_json_file(self):
        """Test parsing JSON file with target configurations."""
        data = [
            {
                "url": "http://example.com/api1",
                "name": "Production API",
                "agents": ["prompt_injection_001"]
            },
            {
                "url": "http://example.com/api2",
                "name": "Staging API"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            targets = self.app._parse_batch_file(temp_path)

            assert len(targets) == 2
            assert targets[0]['url'] == "http://example.com/api1"
            assert targets[0]['name'] == "Production API"
            assert targets[0]['agents'] == ["prompt_injection_001"]
            assert targets[1]['url'] == "http://example.com/api2"
            assert targets[1]['name'] == "Staging API"
            assert targets[1]['agents'] is None
        finally:
            Path(temp_path).unlink()

    def test_parse_nonexistent_file(self):
        """Test error handling for missing file."""
        with pytest.raises(FileNotFoundError):
            self.app._parse_batch_file("/nonexistent/path/file.txt")

    def test_parse_unsupported_format(self):
        """Test error handling for unsupported file format."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write("<targets></targets>")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported file format"):
                self.app._parse_batch_file(temp_path)
        finally:
            Path(temp_path).unlink()


class TestSingleTargetScan:
    """Test single target scanning within batch context."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = MLSecTest()

    @patch('ml_sectest.SecurityOrchestrator')
    @patch('ml_sectest.ReportGenerator')
    def test_scan_single_target_success(self, mock_report_gen, mock_orch):
        """Test successful single target scan."""
        # Mock orchestrator result
        mock_result = Mock()
        mock_result.total_duration_seconds = 5.0
        mock_result.vulnerabilities_found = ['prompt_injection']
        mock_result.overall_status = 'vulnerable'

        self.app.orchestrator.execute_plan = Mock(return_value=mock_result)

        # Mock report generator
        self.app.report_generator.generate_html_report = Mock(return_value='report.html')
        self.app.report_generator.generate_json_report = Mock(return_value='report.json')

        target = {
            'url': 'http://example.com',
            'name': 'Test Target',
            'agents': None
        }

        result = self.app._scan_single_target(target, 1, 1)

        assert result['status'] == 'success'
        assert result['target'] == target
        assert result['result'] == mock_result
        assert 'html_report' in result
        assert 'json_report' in result

    def test_scan_single_target_failure(self):
        """Test single target scan with exception."""
        self.app.orchestrator.execute_plan = Mock(side_effect=Exception("Network error"))

        target = {
            'url': 'http://example.com',
            'name': 'Test Target',
            'agents': None
        }

        result = self.app._scan_single_target(target, 1, 1)

        assert result['status'] == 'failed'
        assert result['target'] == target
        assert result['result'] is None
        assert 'error' in result
        assert "Network error" in result['error']


class TestBatchScan:
    """Test batch scanning integration."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = MLSecTest()

    @patch('ml_sectest.MLSecTest._scan_single_target')
    def test_batch_scan_sequential(self, mock_scan):
        """Test sequential batch scanning."""
        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("http://example.com/api1\n")
            f.write("http://example.com/api2\n")
            temp_path = f.name

        # Mock scan results
        mock_scan.return_value = {
            'status': 'success',
            'target': {'url': 'http://example.com/api1', 'name': 'target_1'},
            'result': Mock(
                vulnerabilities_found=[],
                overall_status='secure',
                total_duration_seconds=1.0
            ),
            'html_report': 'report.html',
            'json_report': 'report.json'
        }

        try:
            # Execute batch scan with sequential execution
            self.app.batch_scan(temp_path, max_workers=1)

            # Verify scans were called
            assert mock_scan.call_count == 2
        finally:
            Path(temp_path).unlink()

    @patch('ml_sectest.MLSecTest._scan_single_target')
    def test_batch_scan_parallel(self, mock_scan):
        """Test parallel batch scanning."""
        # Create temp file with targets
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("http://example.com/api1\n")
            f.write("http://example.com/api2\n")
            f.write("http://example.com/api3\n")
            temp_path = f.name

        # Mock scan results
        mock_scan.return_value = {
            'status': 'success',
            'target': {'url': 'http://example.com/api1', 'name': 'target_1'},
            'result': Mock(
                vulnerabilities_found=[],
                overall_status='secure',
                total_duration_seconds=1.0
            ),
            'html_report': 'report.html',
            'json_report': 'report.json'
        }

        try:
            # Execute batch scan with parallel execution
            self.app.batch_scan(temp_path, max_workers=2)

            # Verify all scans were called
            assert mock_scan.call_count == 3
        finally:
            Path(temp_path).unlink()


class TestBatchSummary:
    """Test batch summary generation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.app = MLSecTest()

    def test_display_batch_summary(self, capsys):
        """Test batch summary display."""
        results = [
            {
                'status': 'success',
                'target': {'name': 'Target 1', 'url': 'http://example.com/1'},
                'result': Mock(
                    vulnerabilities_found=['prompt_injection', 'xss'],
                    overall_status='vulnerable'
                )
            },
            {
                'status': 'success',
                'target': {'name': 'Target 2', 'url': 'http://example.com/2'},
                'result': Mock(
                    vulnerabilities_found=[],
                    overall_status='secure'
                )
            },
            {
                'status': 'failed',
                'target': {'name': 'Target 3', 'url': 'http://example.com/3'},
                'result': None,
                'error': 'Connection timeout'
            }
        ]

        self.app._display_batch_summary(results, duration=10.5)

        captured = capsys.readouterr()
        assert "BATCH SCAN SUMMARY" in captured.out
        assert "Successful: 2/3" in captured.out
        assert "Failed: 1/3" in captured.out
        assert "Total Vulnerabilities: 2" in captured.out

    def test_save_batch_summary(self, tmp_path):
        """Test batch summary JSON export."""
        results = [
            {
                'status': 'success',
                'target': {'name': 'Target 1', 'url': 'http://example.com/1'},
                'result': Mock(
                    vulnerabilities_found=['prompt_injection'],
                    overall_status='vulnerable'
                ),
                'html_report': 'report1.html',
                'json_report': 'report1.json'
            }
        ]

        with patch('builtins.open', create=True) as mock_open:
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            self.app._save_batch_summary(results, 'targets.txt', 5.0)

            # Verify file was written
            mock_open.assert_called_once()
            call_args = str(mock_open.call_args)
            assert 'batch_summary_' in call_args
            assert '.json' in call_args


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
