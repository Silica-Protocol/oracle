# Oracle E2E Tests

End-to-end tests for the Chert Oracle with Docker support.

## Quick Start

### With Docker (Recommended)

Run all tests with TigerBeetle and PostgreSQL:

```bash
cd oracle/tests
./run-tests.sh
```

Run only standalone tests (no TigerBeetle):

```bash
./run-tests.sh standalone
```

### Without Docker

Run standalone tests locally:

```bash
pip install -r requirements.txt
pytest tests/e2e/test_standalone.py -v
pytest tests/e2e/test_antigaming.py -v
```

## Test Types

| Test File | Description | Requires TigerBeetle |
|-----------|-------------|---------------------|
| `test_standalone.py` | Basic API tests | No |
| `test_antigaming.py` | Anti-gaming system tests | No |
| `test_basic.py` | Full integration tests | Yes |

## Docker Environment

### Services

| Service | Port | Purpose |
|---------|------|---------|
| TigerBeetle | 3000 | Financial accounting |
| PostgreSQL | 5432 | Persistent storage |
| test-runner | - | Test execution |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CHERT_TIGERBEETLE_ADDRESSES` | `tigerbeetle:3000` | TigerBeetle cluster addresses |
| `CHERT_POSTGRES_URL` | `postgresql://silica:silica_test_password@postgres:5432/nuw_oracle` | PostgreSQL connection |
| `CHERT_BOINC_MILKYWAY_AUTHENTICATOR` | `testauthfore2etests12345` | Test BOINC authenticator |
| `CHERT_ORACLE_API_KEY` | `testoracleapikey...` | Oracle API key |
| `CHERT_ADMIN_API_KEY` | `testadminkey...` | Admin API key |

## Test Coverage

### Anti-Gaming Tests

- Reputation score initialization
- Eligibility status (FullAccess, Restricted, TempBanned, PermBanned)
- Slash event recording
- Result replay detection
- Governance threshold updates

### API Tests

- Health endpoint
- Reputation endpoints
- BOINC proxy endpoints
- Threshold management

## Adding New Tests

1. Create test file in `tests/e2e/`
2. Use fixtures from `conftest.py`:
   - `standalone_client` - Client without TigerBeetle
   - `oracle_client` - Client with TigerBeetle
3. Add appropriate markers:
   - `@pytest.mark.e2e`
   - `@pytest.mark.antigaming`
   - `@pytest.mark.requires_tb` (for TigerBeetle tests)

## Troubleshooting

### TigerBeetle won't start

```bash
# Check logs
docker compose logs tigerbeetle

# Rebuild containers
./run-tests.sh --build
```

### PostgreSQL connection refused

```bash
# Check if PostgreSQL is running
docker compose ps postgres

# Check connection
docker compose exec postgres pg_isready -U silica
```

### Tests fail with 403 Forbidden

Check API keys match between environment and test client.

## CI/CD Integration

```yaml
# Example GitHub Actions
- name: Run E2E Tests
  run: |
    cd oracle/tests
    chmod +x run-tests.sh
    ./run-tests.sh
```
