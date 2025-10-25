#!/usr/bin/env python3
"""Apply Quality Fixes - Simple Version"""
import re
from pathlib import Path

repo_root = Path(__file__).parent.parent.parent
print("\n[*] Applying Quality Fixes...")
print(f"[*] Repository: {repo_root}\n")

# Fix 1: jwt_auth.py line 513
file1 = repo_root / "saas" / "auth" / "jwt_auth.py"
print("[1] Fixing jwt_auth.py permissions parameter...")
content1 = file1.read_text(encoding='utf-8')
content1 = re.sub(
    r'def generate_api_key\(tenant_id: str, name: str, permissions: list = None\)',
    'def generate_api_key(tenant_id: str, name: str, permissions: Optional[list[str]] = None)',
    content1
)
file1.write_text(content1, encoding='utf-8')
print("    [OK] Added Optional[list[str]] type hint")

# Fix 2: jwt_auth.py line 584
print("[2] Fixing jwt_auth.py _original_settings...")
content1 = file1.read_text(encoding='utf-8')
content1 = re.sub(
    r'(self\._original_settings) = \{\}',
    r'\1: dict[str, Any] = {}',
    content1,
    count=1
)
file1.write_text(content1, encoding='utf-8')
print("    [OK] Added dict[str, Any] annotation")

# Fix 3: validate_docs_links.py line 30
file2 = repo_root / "scripts" / "utilities" / "validate_docs_links.py"
print("[3] Fixing validate_docs_links.py bare except...")
content2 = file2.read_text(encoding='utf-8')
content2 = content2.replace(
    "except:\n        pass",
    "except (AttributeError, OSError):\n        pass"
)
file2.write_text(content2, encoding='utf-8')
print("    [OK] Fixed bare except clause")

print("\n[*] All fixes applied successfully!")
print("[*] Run validation: python -m mypy saas/auth/jwt_auth.py")
