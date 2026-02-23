#!/bin/bash
# Run Oracle E2E tests with Docker
#
# Usage:
#   ./run-tests.sh              # Run all tests
#   ./run-tests.sh standalone   # Run standalone tests only
#   ./run-tests.sh antigaming   # Run anti-gaming tests only
#   ./run-tests.sh --build      # Rebuild containers first
#   ./run-tests.sh --logs       # Show logs after tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse arguments
BUILD=false
SHOW_LOGS=false
TEST_PATTERN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --build|-b)
            BUILD=true
            shift
            ;;
        --logs|-l)
            SHOW_LOGS=true
            shift
            ;;
        standalone)
            TEST_PATTERN="tests/e2e/test_standalone.py"
            shift
            ;;
        antigaming)
            TEST_PATTERN="tests/e2e/test_antigaming.py"
            shift
            ;;
        basic)
            TEST_PATTERN="tests/e2e/test_basic.py"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [TEST_TYPE]"
            echo ""
            echo "Options:"
            echo "  --build, -b    Rebuild Docker containers before running tests"
            echo "  --logs, -l     Show container logs after tests complete"
            echo "  --help, -h     Show this help message"
            echo ""
            echo "Test types:"
            echo "  standalone     Run standalone tests (no TigerBeetle)"
            echo "  antigaming     Run anti-gaming tests"
            echo "  basic          Run basic tests (requires TigerBeetle)"
            echo ""
            echo "If no test type specified, runs all tests."
            exit 0
            ;;
        *)
            log_error "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Change to test directory
cd "$SCRIPT_DIR"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not installed. Please install Docker Compose."
    exit 1
fi

# Build containers if requested
if [ "$BUILD" = true ]; then
    log_info "Building Docker containers..."
    docker compose build --no-cache
fi

# Check if containers are already running
if docker compose ps -q 2>/dev/null | grep -q .; then
    log_info "Containers are already running"
else
    log_info "Starting containers..."
    docker compose up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to be ready..."
    
    # Wait for TigerBeetle
    for i in {1..30}; do
        if docker compose exec -T tigerbeetle tigerbeetle status 2>/dev/null | grep -q "replica 0: state: normal"; then
            log_success "TigerBeetle is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "TigerBeetle failed to start"
            docker compose logs tigerbeetle
            exit 1
        fi
        sleep 1
    done
    
    # Wait for PostgreSQL
    for i in {1..30}; do
        if docker compose exec -T postgres pg_isready -U silica -d nuw_oracle 2>/dev/null; then
            log_success "PostgreSQL is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "PostgreSQL failed to start"
            docker compose logs postgres
            exit 1
        fi
        sleep 1
    done
fi

# Run tests
log_info "Running tests..."

if [ -z "$TEST_PATTERN" ]; then
    TEST_PATTERN="tests/e2e/"
fi

# Run pytest inside the test-runner container
docker compose exec -T test-runner pytest $TEST_PATTERN -v --tb=short
TEST_EXIT_CODE=$?

# Show logs if requested
if [ "$SHOW_LOGS" = true ]; then
    log_info "Container logs:"
    docker compose logs
fi

# Report results
if [ $TEST_EXIT_CODE -eq 0 ]; then
    log_success "All tests passed!"
else
    log_error "Some tests failed. Exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
