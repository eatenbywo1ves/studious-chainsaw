# Shared Library

Reusable components and utilities for cross-project use.

## Structure

```
shared/
├── utilities/      # Common utility functions
│   ├── utils.py    # File management, processing results
│   └── utillogging.py  # Logging configuration
├── monitoring/     # (Future) Monitoring tools
└── pdf_tools/      # (Future) PDF processing utilities
```

## Usage

Add to your Python path:
```bash
export PYTHONPATH="/c/Users/Corbin/shared:$PYTHONPATH"
```

Or in your Python scripts:
```python
import sys
sys.path.insert(0, '/c/Users/Corbin/shared')

from utilities import FileManager, ProcessingResult
```

## Available Modules

### utilities.utils
- `FileManager`: File operations with error handling
- `ProcessingResult`: Standardized result objects
- `ConfigLoader`: YAML/JSON configuration management
- `ErrorHandler`: Common error handling patterns

### utilities.utillogging
- `setup_logger()`: Configure logging with rotation
- `LogContext`: Context manager for scoped logging
- `format_log_entry()`: Structured log formatting

## Development

When adding new modules:
1. Create appropriate directory structure
2. Add `__init__.py` with exports
3. Include docstrings and type hints
4. Update this README