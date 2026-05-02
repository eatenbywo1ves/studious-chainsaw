#!/usr/bin/env python3
"""Fix locustfile.py context manager issues"""


# Read the original file
with open('locustfile.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix 1: Fix the registration section (on_start method)
old_reg = '''        # Try to register (may fail if user exists, that's okay)
        try:
            response = self.client.post(
                ENDPOINTS["register"],
                json={
                    "email": self.user_email,
                    "password": self.user_password,
                    "company_name": company_name,
                },
                catch_response=True,
            )

            if response.status_code == 201:
                data = response.json()
                self.tenant_id = data.get("tenant_id")
                metrics.record_success()
            elif response.status_code == 409:
                # User already exists, that's fine
                pass
            else:
                metrics.record_client_error()

        except Exception as e:
            print(f"Registration error: {e}")
            metrics.record_connection_error()'''

new_reg = '''        # Try to register (may fail if user exists, that's okay)
        try:
            with self.client.post(
                ENDPOINTS["register"],
                json={
                    "email": self.user_email,
                    "password": self.user_password,
                    "company_name": company_name,
                },
                catch_response=True,
            ) as response:
                if response.status_code == 201:
                    data = response.json()
                    self.tenant_id = data.get("tenant_id")
                    metrics.record_success()
                    response.success()
                elif response.status_code == 409:
                    # User already exists, that's fine
                    response.success()
                else:
                    metrics.record_client_error()
                    response.failure(f"Registration failed: {response.status_code}")

        except Exception as e:
            print(f"Registration error: {e}")
            metrics.record_connection_error()'''

# Fix 2: Fix the perform_login method
old_login = '''    def perform_login(self):
        """Login and store JWT token"""
        try:
            response = self.client.post(
                ENDPOINTS["login"],
                json={"email": self.user_email, "password": self.user_password},
                catch_response=True,
            )

            if response.status_code == 200:
                data = response.json()
                self.token = data.get("access_token")
                if self.token:
                    self.headers["Authorization"] = f"Bearer {self.token}"
                    metrics.record_success()
                    response.success()
                else:
                    metrics.record_auth_failure()
                    response.failure("No access token received")
            else:
                metrics.record_auth_failure()
                response.failure(f"Login failed: {response.status_code}")

        except Exception as e:
            print(f"Login error: {e}")
            metrics.record_connection_error()'''

new_login = '''    def perform_login(self):
        """Login and store JWT token"""
        try:
            with self.client.post(
                ENDPOINTS["login"],
                json={"email": self.user_email, "password": self.user_password},
                catch_response=True,
            ) as response:
                if response.status_code == 200:
                    data = response.json()
                    self.token = data.get("access_token")
                    if self.token:
                        self.headers["Authorization"] = f"Bearer {self.token}"
                        metrics.record_success()
                        response.success()
                    else:
                        metrics.record_auth_failure()
                        response.failure("No access token received")
                else:
                    metrics.record_auth_failure()
                    response.failure(f"Login failed: {response.status_code}")

        except Exception as e:
            print(f"Login error: {e}")
            metrics.record_connection_error()'''

# Apply fixes
content = content.replace(old_reg, new_reg)
content = content.replace(old_login, new_login)

# Write the fixed file
with open('locustfile.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✓ Fixed context manager issues in locustfile.py")
print("  - Fixed registration section to use 'with' block")
print("  - Fixed perform_login method to use 'with' block")
