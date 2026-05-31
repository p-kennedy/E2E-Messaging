"""
Server-side integration tests for the /api/auth/register endpoint.
Client-side crypto (key generation, prekey bundle signing, local encryption)
is tested in tests/test_create_user.js.

Requires a running server and DB.  Set SERVER_URL env var if not localhost.
"""

import json
import os
import sys

import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server', 'database'))
from connection import init_pool
import crud

TEST_USERNAME = "test_user_create"
TEST_PASSWORD = "test_password_123"
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

# Minimal valid-shaped prekey bundle — field presence is what the server validates.
# Key bytes are stubs; crypto correctness is the JS unit test's responsibility.
STUB_BUNDLE = json.dumps({
    "ik_sign_pub": "AAAA",
    "ik_dh_pub": "AAAA",
    "spk_pub": "AAAA",
    "spk_signature": "AAAA",
    "opk_pubs": [{"id": i, "key": "AAAA"} for i in range(10)],
})


def run_tests():
    init_pool()
    failures = []
    user_id = None

    # Clean up any leftover state from a previous failed run
    existing = crud.get_user_by_username(TEST_USERNAME)
    if existing:
        crud.delete_user(existing['user_id'])

    # --- Test 1: registration returns expected fields ---
    try:
        resp = requests.post(
            f"{SERVER_URL}/api/auth/register",
            json={"username": TEST_USERNAME, "password": TEST_PASSWORD, "public_key": STUB_BUNDLE},
        )
        resp.raise_for_status()
        user = resp.json()
        assert user['username'] == TEST_USERNAME
        assert 'user_id' in user
        user_id = user['user_id']
        print(f"  PASS  user created with user_id={user_id}")
    except Exception as e:
        failures.append(f"  FAIL  registration: {e}")
        print(failures[-1])

    # --- Test 2: user is retrievable from the DB ---
    try:
        fetched = crud.get_user_by_username(TEST_USERNAME)
        assert fetched is not None, "user not found in DB after registration"
        assert fetched['username'] == TEST_USERNAME
        print("  PASS  user retrieved from DB")
    except Exception as e:
        failures.append(f"  FAIL  DB fetch: {e}")
        print(failures[-1])

    # --- Test 3: public_key field is valid prekey bundle JSON with required fields ---
    try:
        fetched = crud.get_user_by_username(TEST_USERNAME)
        bundle = json.loads(fetched['public_key'])
        for field in ('ik_sign_pub', 'ik_dh_pub', 'spk_pub', 'spk_signature', 'opk_pubs'):
            assert field in bundle, f"missing field: {field}"
        print(f"  PASS  prekey bundle has correct structure ({len(bundle['opk_pubs'])} OPKs)")
    except Exception as e:
        failures.append(f"  FAIL  prekey bundle validation: {e}")
        print(failures[-1])

    # --- Test 4: duplicate username is rejected ---
    try:
        requests.post(
            f"{SERVER_URL}/api/auth/register",
            json={"username": TEST_USERNAME, "password": TEST_PASSWORD, "public_key": "{}"},
        ).raise_for_status()
        failures.append("  FAIL  duplicate username should have raised an error")
        print(failures[-1])
    except Exception:
        print("  PASS  duplicate username correctly rejected")

    # --- Cleanup ---
    if user_id:
        crud.delete_user(user_id)

    print()
    if failures:
        print(f"FAILED — {len(failures)} test(s) failed")
        sys.exit(1)
    else:
        print("All tests passed.")


if __name__ == "__main__":
    run_tests()
