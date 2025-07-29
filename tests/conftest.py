import pytest
import os


def pytest_addoption(parser):
    parser.addoption(
        "--test-master-key",
        action="store",
        default=None,
        help="Master key for encryption tests",
    )


@pytest.fixture
def test_master_key(request):
    key = request.config.getoption("--test-master-key")
    if key is not None:
        return key
    return os.environ.get("TEST_MASTER_KEY")
