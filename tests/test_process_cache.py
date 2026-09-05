"""
Unit tests for ProcessCache resolution, caching, and fallback handling.
"""
import os
from src.core.process_cache import ProcessCache


def test_process_cache_resolution_current_process(process_cache):
    my_pid = os.getpid()
    info = process_cache.get(my_pid, fallback_comm="fallback_test")
    assert info.pid == my_pid
    assert len(info.comm) > 0


def test_process_cache_non_existent_process_fallback(process_cache):
    non_existent_pid = 99999999
    info = process_cache.get(non_existent_pid, fallback_comm="cached_kernel_comm")
    assert info.pid == non_existent_pid
    assert info.comm == "cached_kernel_comm"


def test_process_cache_invalidation(process_cache):
    my_pid = os.getpid()
    info1 = process_cache.get(my_pid)
    assert my_pid in process_cache._cache

    process_cache.invalidate(my_pid)
    assert my_pid not in process_cache._cache
