import gc
import pytest


@pytest.fixture(autouse=True)
def force_garbage_collection():
    yield
    gc.collect()
