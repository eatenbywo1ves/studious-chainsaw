"""
Shared utilities module for common operations across scripts.
Consolidates file I/O, error handling, logging, and configuration management.
"""

import os
import sys
import json
import yaml
import logging
import shutil
import glob
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from contextlib import contextmanager


@dataclass
class ProcessingResult:
    """Standard result object for processing operations"""
    success: bool
    message: str
    data: Optional[Any] = None
    errors: Optional[List[str]] = None


class FileManager:
    """Handles common file operations with proper error handling"""
    
    @staticmethod
    def ensure_directory(path: Union[str, Path]) -> ProcessingResult:
        """Create directory if it doesn't exist"""
        try:
            os.makedirs(path, exist_ok=True)
            return ProcessingResult(True, f"Directory ensured: {path}")
        except Exception as e:
            return ProcessingResult(False, f"Failed to create directory {path}: {str(e)}")
    
    @staticmethod
    def copy_file(source: Union[str, Path], destination: Union[str, Path]) -> ProcessingResult:
        """Copy file with error handling"""
        try:
            shutil.copy2(source, destination)
            return ProcessingResult(True, f"Copied: {source} -> {destination}")
        except FileNotFoundError:
            return ProcessingResult(False, f"Source file not found: {source}")
        except Exception as e:
            return ProcessingResult(False, f"Copy failed: {str(e)}")
    
    @staticmethod
    def read_text_file(file_path: Union[str, Path], encoding: str = 'utf-8') -> ProcessingResult:
        """Read text file with error handling"""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            return ProcessingResult(True, f"File read successfully: {file_path}", data=content)
        except FileNotFoundError:
            return ProcessingResult(False, f"File not found: {file_path}")
        except Exception as e:
            return ProcessingResult(False, f"Failed to read file {file_path}: {str(e)}")
    
    @staticmethod
    def write_text_file(file_path: Union[str, Path], content: str, encoding: str = 'utf-8') -> ProcessingResult:
        """Write text file with error handling"""
        try:
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            return ProcessingResult(True, f"File written successfully: {file_path}")
        except Exception as e:
            return ProcessingResult(False, f"Failed to write file {file_path}: {str(e)}")
    
    @staticmethod
    def find_files(pattern: str, directory: Union[str, Path] = ".") -> ProcessingResult:
        """Find files matching a pattern"""
        try:
            files = glob.glob(os.path.join(directory, pattern))
            return ProcessingResult(True, f"Found {len(files)} files matching {pattern}", data=files)
        except Exception as e:
            return ProcessingResult(False, f"Failed to find files: {str(e)}")
    
    @staticmethod
    def get_file_size_mb(file_path: Union[str, Path]) -> float:
        """Get file size in MB"""
        try:
            size_bytes = os.path.getsize(file_path)
            return size_bytes / (1024 * 1024)
        except:
            return 0.0


class ConfigManager:
    """Manages configuration loading and validation"""
    
    @staticmethod
    def load_json_config(config_path: Union[str, Path]) -> ProcessingResult:
        """Load JSON configuration file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            return ProcessingResult(True, f"Config loaded: {config_path}", data=config)
        except FileNotFoundError:
            return ProcessingResult(False, f"Config file not found: {config_path}")
        except json.JSONDecodeError as e:
            return ProcessingResult(False, f"Invalid JSON in {config_path}: {str(e)}")
        except Exception as e:
            return ProcessingResult(False, f"Failed to load config {config_path}: {str(e)}")
    
    @staticmethod
    def save_json_config(config: Dict[str, Any], config_path: Union[str, Path]) -> ProcessingResult:
        """Save configuration to JSON file"""
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            return ProcessingResult(True, f"Config saved: {config_path}")
        except Exception as e:
            return ProcessingResult(False, f"Failed to save config {config_path}: {str(e)}")
    
    @staticmethod
    def load_yaml_config(config_path: Union[str, Path]) -> ProcessingResult:
        """Load YAML configuration file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return ProcessingResult(True, f"Config loaded: {config_path}", data=config)
        except FileNotFoundError:
            return ProcessingResult(False, f"Config file not found: {config_path}")
        except yaml.YAMLError as e:
            return ProcessingResult(False, f"Invalid YAML in {config_path}: {str(e)}")
        except Exception as e:
            return ProcessingResult(False, f"Failed to load config {config_path}: {str(e)}")


class Logger:
    """Centralized logging setup and management"""
    
    @staticmethod
    def setup_logger(name: str, level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
        """Set up a logger with consistent formatting"""
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper()))
        
        # Clear existing handlers to avoid duplicates
        logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler (if specified)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger


class ArgumentParser:
    """Standardized command-line argument parsing"""
    
    @staticmethod
    def parse_file_args(description: str, required_extensions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Parse common file-related command line arguments"""
        import argparse
        
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument('input_file', nargs='?', help='Input file path')
        parser.add_argument('output_file', nargs='?', help='Output file path (optional)')
        parser.add_argument('--config', '-c', help='Configuration file path')
        parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
        parser.add_argument('--log-file', help='Log file path')
        
        args = parser.parse_args()
        
        # Validate file extensions if specified
        if required_extensions and args.input_file:
            file_ext = Path(args.input_file).suffix.lower()
            if file_ext not in required_extensions:
                parser.error(f"Input file must have one of these extensions: {required_extensions}")
        
        return vars(args)


class ProgressTracker:
    """Simple progress tracking for batch operations"""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.logger = Logger.setup_logger("progress")
    
    def update(self, increment: int = 1, message: Optional[str] = None):
        """Update progress"""
        self.current += increment
        progress_pct = (self.current / self.total) * 100 if self.total > 0 else 0
        
        status_msg = f"{self.description}: {self.current}/{self.total} ({progress_pct:.1f}%)"
        if message:
            status_msg += f" - {message}"
        
        self.logger.info(status_msg)
    
    def complete(self, final_message: Optional[str] = None):
        """Mark as complete"""
        message = final_message or f"{self.description} completed"
        self.logger.info(f"✓ {message} ({self.current}/{self.total})")


@contextmanager
def error_handler(operation_name: str, logger: Optional[logging.Logger] = None):
    """Context manager for consistent error handling"""
    if logger is None:
        logger = Logger.setup_logger("error_handler")
    
    try:
        logger.info(f"Starting: {operation_name}")
        yield
        logger.info(f"Completed: {operation_name}")
    except Exception as e:
        logger.error(f"Failed: {operation_name} - {str(e)}")
        raise


class BatchProcessor:
    """Generic batch processing utility"""
    
    def __init__(self, description: str = "Batch Processing"):
        self.description = description
        self.logger = Logger.setup_logger("batch_processor")
        self.results = []
    
    def process_files(self, file_list: List[str], process_func, **kwargs) -> List[ProcessingResult]:
        """Process a list of files with a given function"""
        tracker = ProgressTracker(len(file_list), self.description)
        
        for file_path in file_list:
            try:
                with error_handler(f"Processing {file_path}", self.logger):
                    result = process_func(file_path, **kwargs)
                    self.results.append(result)
                    tracker.update(message=f"Processed {file_path}")
            except Exception as e:
                error_result = ProcessingResult(False, f"Failed to process {file_path}: {str(e)}")
                self.results.append(error_result)
                tracker.update(message=f"Failed: {file_path}")
        
        tracker.complete()
        return self.results
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary of processing results"""
        successful = sum(1 for r in self.results if r.success)
        failed = len(self.results) - successful
        
        return {
            'total': len(self.results),
            'successful': successful,
            'failed': failed,
            'success_rate': (successful / len(self.results) * 100) if self.results else 0
        }


# Utility functions for common operations
def setup_script_environment(script_name: str, config_file: Optional[str] = None) -> Dict[str, Any]:
    """Set up common script environment (logging, config, etc.)"""
    # Parse command line arguments
    args = ArgumentParser.parse_file_args(f"{script_name} - Refactored with shared utilities")
    
    # Set up logging
    log_level = "DEBUG" if args.get('verbose') else "INFO"
    logger = Logger.setup_logger(script_name, log_level, args.get('log_file'))
    
    # Load configuration if specified
    config = {}
    config_path = args.get('config') or config_file
    if config_path and os.path.exists(config_path):
        result = ConfigManager.load_json_config(config_path)
        if result.success:
            config = result.data
            logger.info(f"Loaded configuration from {config_path}")
        else:
            logger.warning(f"Failed to load config: {result.message}")
    
    return {
        'args': args,
        'logger': logger,
        'config': config
    }


def print_summary(results: List[ProcessingResult], operation_name: str = "Operation"):
    """Print a summary of processing results"""
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    
    print("=" * 50)
    print(f"{operation_name} Summary:")
    print(f"Total: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")
    
    if failed:
        print("\nFailed operations:")
        for result in failed:
            print(f"  ❌ {result.message}")
    
    if successful:
        print(f"\n✅ {operation_name} completed successfully!")
    print("=" * 50)