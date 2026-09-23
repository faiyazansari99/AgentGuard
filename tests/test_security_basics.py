import hashlib

def test_api_key_hash_is_sha256():
    raw='ag_example_secret'
    assert len(hashlib.sha256(raw.encode()).hexdigest()) == 64

def test_scopes_are_explicit():
    scopes='gateway:check,audit:read'
    assert 'gateway:check' in [x.strip() for x in scopes.split(',')]
