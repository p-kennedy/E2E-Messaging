import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server', 'database'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'User_Creation'))

from connection import init_pool
import crud
from user_create_modern import create_user

TEST_USERNAME = "test_user_create"
TEST_PASSWORD = "test_password_123"

def run_tests():
    init_pool()
    failures = []

    # Clean up any leftover state from a previous failed run
    existing = crud.get_user_by_username(TEST_USERNAME)
    if existing:
        crud.delete_user(existing['user_id'])

    # --- Test 1: user is created and returned ---
    user = None
    try:
        user = create_user(TEST_USERNAME, TEST_PASSWORD)
        assert user is not None, "create_user returned None"
        assert user['username'] == TEST_USERNAME
        assert 'user_id' in user
        print(f"  PASS  user created with user_id={user['user_id']}")
    except Exception as e:
        failures.append(f"  FAIL  user creation raised: {e}")
        print(failures[-1])

    # --- Test 2: user is retrievable from the DB ---
    try:
        fetched = crud.get_user_by_username(TEST_USERNAME)
        assert fetched is not None, "user not found in DB after creation"
        assert fetched['username'] == TEST_USERNAME
        print(f"  PASS  user retrieved from DB")
    except Exception as e:
        failures.append(f"  FAIL  DB fetch raised: {e}")
        print(failures[-1])

    # --- Test 3: public_key field is valid prekey bundle JSON ---
    try:
        fetched = crud.get_user_by_username(TEST_USERNAME)
        bundle = json.loads(fetched['public_key'])
        for field in ('ik_pub', 'spk_pub', 'spk_signature', 'opk_pubs'):
            assert field in bundle, f"missing field: {field}"
        assert len(bundle['opk_pubs']) == 10, f"expected 10 OPKs, got {len(bundle['opk_pubs'])}"
        print(f"  PASS  prekey bundle has correct structure ({len(bundle['opk_pubs'])} OPKs)")
    except Exception as e:
        failures.append(f"  FAIL  prekey bundle validation raised: {e}")
        print(failures[-1])

    # --- Test 4: duplicate username is rejected ---
    try:
        create_user(TEST_USERNAME, TEST_PASSWORD)
        failures.append("  FAIL  duplicate username should have raised an error")
        print(failures[-1])
    except Exception:
        print(f"  PASS  duplicate username correctly rejected")

    # # --- Cleanup ---
    # if user:
    #     crud.delete_user(user['user_id'])
    # for f in (f"{TEST_USERNAME}_private_keys.bin", f"{TEST_USERNAME}_local_salt.bin"):
    #     if os.path.exists(f):
    #         os.remove(f)

    print()
    if failures:
        print(f"FAILED — {len(failures)} test(s) failed")
        sys.exit(1)
    else:
        print("All tests passed.")

if __name__ == "__main__":
    run_tests()
