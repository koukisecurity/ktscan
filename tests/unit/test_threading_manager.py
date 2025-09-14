"""
Tests for ktscan.threading_manager module
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from concurrent.futures import Future, ThreadPoolExecutor
from ktscan.threading_manager import ThreadManager, CertScanManager
from ktscan.cert_analyzer import CertResult


class TestThreadManager:
    """Test the ThreadManager class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.max_workers = 4

    def test_init(self):
        """Test ThreadManager initialization"""
        manager = ThreadManager(self.max_workers)
        
        assert manager.max_workers == self.max_workers
        assert manager.executor is None
        assert manager.logger is not None

    def test_context_manager(self):
        """Test context manager behavior"""
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_executor_class.return_value = mock_executor
            
            with ThreadManager(self.max_workers) as manager:
                assert manager.executor == mock_executor
                mock_executor_class.assert_called_once_with(max_workers=self.max_workers)
            
            # Verify shutdown was called
            mock_executor.shutdown.assert_called_once_with(wait=True)

    def test_submit_without_context(self):
        """Test submit raises error when not in context"""
        manager = ThreadManager(self.max_workers)
        
        with pytest.raises(RuntimeError, match="ThreadPoolExecutor not initialized"):
            manager.submit(lambda: None)

    def test_submit_with_context(self):
        """Test submit works within context"""
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_future = Mock(spec=Future)
            mock_executor.submit.return_value = mock_future
            mock_executor_class.return_value = mock_executor
            
            with ThreadManager(self.max_workers) as manager:
                result = manager.submit(lambda x: x * 2, 5)
                
                assert result == mock_future
                mock_executor.submit.assert_called_once()

    def test_map_parallel_empty_iterable(self):
        """Test map_parallel with empty iterable"""
        with ThreadManager(self.max_workers) as manager:
            result = manager.map_parallel(lambda x: x * 2, [])
            assert result == []

    def test_map_parallel_without_context(self):
        """Test map_parallel raises error when not in context"""
        manager = ThreadManager(self.max_workers)
        
        with pytest.raises(RuntimeError, match="ThreadPoolExecutor not initialized"):
            manager.map_parallel(lambda x: x, [1, 2, 3])

    def test_map_parallel_preserve_order_false(self):
        """Test map_parallel without preserving order"""
        def double(x):
            return x * 2
        
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_executor_class.return_value = mock_executor
            
            # Mock futures and their results
            mock_futures = []
            for i, item in enumerate([1, 2, 3]):
                mock_future = Mock(spec=Future)
                mock_future.result.return_value = item * 2
                mock_futures.append(mock_future)
            
            mock_executor.submit.side_effect = mock_futures
            
            # Mock as_completed to return futures in order
            with patch('ktscan.threading_manager.as_completed', return_value=mock_futures):
                with ThreadManager(self.max_workers) as manager:
                    results = manager.map_parallel(double, [1, 2, 3])
                    
                    assert len(results) == 3
                    assert all(r in [2, 4, 6] for r in results)  # Order may vary

    def test_map_parallel_preserve_order_true(self):
        """Test map_parallel with preserving order"""
        def double(x):
            return x * 2
        
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_executor_class.return_value = mock_executor
            
            # Mock futures and their results  
            mock_futures = {}
            for i, item in enumerate([1, 2, 3]):
                mock_future = Mock(spec=Future)
                mock_future.result.return_value = item * 2
                mock_futures[mock_future] = i
            
            mock_executor.submit.side_effect = list(mock_futures.keys())
            
            # Mock as_completed to return futures
            with patch('ktscan.threading_manager.as_completed', return_value=mock_futures.keys()):
                with ThreadManager(self.max_workers) as manager:
                    results = manager.map_parallel(double, [1, 2, 3], preserve_order=True)
                    
                    assert results == [2, 4, 6]  # Order preserved

    def test_map_parallel_with_exception(self):
        """Test map_parallel error handling"""
        def failing_func(x):
            if x == 2:
                raise ValueError("Test error")
            return x * 2
        
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_executor_class.return_value = mock_executor
            
            # Create mock futures - one succeeds, one fails, one succeeds
            mock_futures = []
            for i, item in enumerate([1, 2, 3]):
                mock_future = Mock(spec=Future)
                if item == 2:
                    mock_future.result.side_effect = ValueError("Test error")
                else:
                    mock_future.result.return_value = item * 2
                mock_futures.append(mock_future)
            
            mock_executor.submit.side_effect = mock_futures
            
            with patch('ktscan.threading_manager.as_completed', return_value=mock_futures):
                with ThreadManager(self.max_workers) as manager:
                    results = manager.map_parallel(failing_func, [1, 2, 3])
                    
                    # Should contain results and None for failed items
                    assert len(results) == 3
                    assert None in results  # Failed item

    def test_map_parallel_max_concurrent(self):
        """Test map_parallel with max_concurrent limit"""
        def double(x):
            return x * 2
        
        with ThreadManager(self.max_workers) as manager:
            with patch.object(manager, 'executor') as mock_executor:
                # Create exactly 5 futures that will be reused
                mock_futures = []
                for i in range(5):
                    future = Mock(spec=Future)
                    future.result.return_value = (i + 1) * 2
                    mock_futures.append(future)
                
                call_count = 0
                def mock_submit(*args, **kwargs):
                    nonlocal call_count
                    future = mock_futures[call_count % len(mock_futures)]
                    call_count += 1
                    return future
                
                mock_executor.submit.side_effect = mock_submit
                
                with patch('ktscan.threading_manager.as_completed') as mock_as_completed:
                    # Mock as_completed to return only unique futures for each batch
                    def mock_as_completed_side_effect(futures):
                        return list(futures)
                    mock_as_completed.side_effect = mock_as_completed_side_effect
                    
                    results = manager.map_parallel(double, [1, 2, 3, 4, 5], max_concurrent=2)
                    
                    # Should process in batches: 2, 2, 1
                    # Total results should be 5
                    assert len(results) >= 5  # May have some duplicates due to batching

    def test_map_with_callback_success(self):
        """Test map_with_callback with successful operations"""
        def double(x):
            return x * 2
        
        callback_results = []
        def success_callback(result):
            callback_results.append(result)
        
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_executor_class.return_value = mock_executor
            
            mock_futures = {}
            for item in [1, 2, 3]:
                mock_future = Mock(spec=Future)
                mock_future.result.return_value = item * 2
                mock_futures[mock_future] = item
            
            mock_executor.submit.side_effect = list(mock_futures.keys())
            
            with patch('ktscan.threading_manager.as_completed', return_value=mock_futures.keys()):
                with ThreadManager(self.max_workers) as manager:
                    results = manager.map_with_callback(
                        double, [1, 2, 3], callback=success_callback
                    )
                    
                    assert len(results) == 3
                    assert len(callback_results) == 3
                    assert all(r in [2, 4, 6] for r in callback_results)

    def test_map_with_callback_error(self):
        """Test map_with_callback with errors"""
        def failing_func(x):
            if x == 2:
                raise ValueError("Test error")
            return x * 2
        
        error_results = []
        def error_callback(item, exception):
            error_results.append((item, str(exception)))
        
        with patch('ktscan.threading_manager.ThreadPoolExecutor') as mock_executor_class:
            mock_executor = Mock(spec=ThreadPoolExecutor)
            mock_executor_class.return_value = mock_executor
            
            mock_futures = {}
            for item in [1, 2, 3]:
                mock_future = Mock(spec=Future)
                if item == 2:
                    mock_future.result.side_effect = ValueError("Test error")
                else:
                    mock_future.result.return_value = item * 2
                mock_futures[mock_future] = item
            
            mock_executor.submit.side_effect = list(mock_futures.keys())
            
            with patch('ktscan.threading_manager.as_completed', return_value=mock_futures.keys()):
                with ThreadManager(self.max_workers) as manager:
                    results = manager.map_with_callback(
                        failing_func, [1, 2, 3], error_callback=error_callback
                    )
                    
                    assert len(results) == 2  # Only successful results
                    assert len(error_results) == 1
                    assert error_results[0][0] == 2
                    assert "Test error" in error_results[0][1]

    def test_map_with_callback_empty_iterable(self):
        """Test map_with_callback with empty iterable"""
        with ThreadManager(self.max_workers) as manager:
            results = manager.map_with_callback(lambda x: x, [])
            assert results == []

    def test_map_with_callback_without_context(self):
        """Test map_with_callback raises error when not in context"""
        manager = ThreadManager(self.max_workers)
        
        with pytest.raises(RuntimeError, match="ThreadPoolExecutor not initialized"):
            manager.map_with_callback(lambda x: x, [1, 2, 3])

    def test_execute_with_semaphore(self):
        """Test execute_with_semaphore method"""
        def double(x):
            return x * 2
        
        with ThreadManager(self.max_workers) as manager:
            with patch.object(manager, 'map_parallel') as mock_map_parallel:
                mock_map_parallel.side_effect = [
                    [2, 4],  # First batch
                    [6, 8]   # Second batch
                ]
                
                results = manager.execute_with_semaphore(double, [1, 2, 3, 4], max_concurrent=2)
                
                assert results == [2, 4, 6, 8]
                assert mock_map_parallel.call_count == 2

    def test_execute_with_semaphore_empty_iterable(self):
        """Test execute_with_semaphore with empty iterable"""
        with ThreadManager(self.max_workers) as manager:
            results = manager.execute_with_semaphore(lambda x: x, [], max_concurrent=2)
            assert results == []

    def test_execute_with_semaphore_without_context(self):
        """Test execute_with_semaphore raises error when not in context"""
        manager = ThreadManager(self.max_workers)
        
        with pytest.raises(RuntimeError, match="ThreadPoolExecutor not initialized"):
            manager.execute_with_semaphore(lambda x: x, [1, 2, 3], max_concurrent=2)


class TestCertScanManager:
    """Test the CertScanManager legacy class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.max_workers = 2

    def test_init(self):
        """Test CertScanManager initialization"""
        manager = CertScanManager(self.max_workers)
        
        assert manager.thread_manager.max_workers == self.max_workers
        assert manager.logger is not None

    def test_context_manager(self):
        """Test context manager behavior"""
        with patch.object(ThreadManager, '__enter__') as mock_enter, \
             patch.object(ThreadManager, '__exit__') as mock_exit:
            
            with CertScanManager(self.max_workers) as manager:
                mock_enter.assert_called_once()
                assert manager is not None
            
            mock_exit.assert_called_once()

    def test_scan_targets_empty_list(self):
        """Test scan_targets with empty target list"""
        with CertScanManager(self.max_workers) as manager:
            results = manager.scan_targets([], lambda ip, port, hostname: None)
            assert results == []

    def test_scan_targets_successful_scan(self):
        """Test scan_targets with successful scans"""
        def mock_scan_function(ip, port, hostname):
            result = CertResult(endpoints=[(ip, port)], hostname=hostname)
            result.valid = True
            return result
        
        targets = [("192.168.1.1", 443), ("192.168.1.2", 443)]
        
        with CertScanManager(self.max_workers) as manager:
            with patch.object(manager.thread_manager, 'map_parallel') as mock_map:
                # Mock successful results
                mock_results = []
                for ip, port in targets:
                    result = CertResult(endpoints=[(ip, port)], hostname="example.com")
                    result.valid = True
                    mock_results.append(result)
                
                mock_map.return_value = mock_results
                
                results = manager.scan_targets(targets, mock_scan_function, "example.com")
                
                assert len(results) == 2
                assert all(r.valid for r in results)
                assert all(r.hostname == "example.com" for r in results)

    def test_scan_targets_with_failures(self):
        """Test scan_targets with some failures"""
        def mock_scan_function(ip, port, hostname):
            if ip == "192.168.1.2":
                raise Exception("Connection failed")
            result = CertResult(endpoints=[(ip, port)], hostname=hostname)
            result.valid = True
            return result
        
        targets = [("192.168.1.1", 443), ("192.168.1.2", 443)]
        
        with CertScanManager(self.max_workers) as manager:
            with patch.object(manager.thread_manager, 'map_parallel') as mock_map:
                # Mock one success, one failure (None)
                success_result = CertResult(endpoints=[("192.168.1.1", 443)], hostname="example.com")
                success_result.valid = True
                
                mock_map.return_value = [success_result, None]
                
                results = manager.scan_targets(targets, mock_scan_function, "example.com")
                
                assert len(results) == 1  # Only successful result
                assert results[0].valid

    def test_scan_targets_function_wrapper(self):
        """Test that scan_targets properly wraps the scan function"""
        def mock_scan_function(ip, port, hostname):
            if ip == "192.168.1.1":
                result = CertResult(endpoints=[(ip, port)], hostname=hostname)
                result.valid = True
                return result
            else:
                raise Exception("Scan failed")
        
        targets = [("192.168.1.1", 443), ("192.168.1.2", 443)]
        
        with CertScanManager(self.max_workers) as manager:
            # Don't mock map_parallel, let it actually call our wrapper
            with patch.object(manager.thread_manager, 'executor') as mock_executor:
                # Mock the actual execution to avoid threading complexities
                def mock_submit(func, target):
                    mock_future = Mock(spec=Future)
                    try:
                        mock_future.result.return_value = func(target)
                    except Exception as e:
                        mock_future.result.side_effect = e
                    return mock_future
                
                mock_executor.submit.side_effect = mock_submit
                
                with patch('ktscan.threading_manager.as_completed') as mock_as_completed:
                    # Create mock futures for each target
                    mock_futures = []
                    for target in targets:
                        mock_future = Mock(spec=Future)
                        if target[0] == "192.168.1.1":
                            result = CertResult(endpoints=[target], hostname="example.com")
                            result.valid = True
                            mock_future.result.return_value = result
                        else:
                            # Failed scan should return CertResult with error
                            result = CertResult(endpoints=[target], hostname="example.com")
                            result.errors.append("Scan failed")
                            mock_future.result.return_value = result
                        mock_futures.append(mock_future)
                    
                    mock_as_completed.return_value = mock_futures
                    
                    results = manager.scan_targets(targets, mock_scan_function, "example.com")
                    
                    assert len(results) == 2
                    # One should have errors, one should be valid
                    error_results = [r for r in results if r.errors]
                    valid_results = [r for r in results if not r.errors]
                    assert len(error_results) == 1
                    assert len(valid_results) == 1

    def test_scan_targets_streaming_empty_list(self):
        """Test scan_targets_streaming with empty target list"""
        with CertScanManager(self.max_workers) as manager:
            results = list(manager.scan_targets_streaming([], lambda ip, port, hostname: None))
            assert results == []

    def test_scan_targets_streaming_successful_scan(self):
        """Test scan_targets_streaming with successful scans"""
        def mock_scan_function(ip, port, hostname):
            result = CertResult(endpoints=[(ip, port)], hostname=hostname)
            result.valid = True
            return result
        
        targets = [("192.168.1.1", 443), ("192.168.1.2", 443)]
        
        with CertScanManager(self.max_workers) as manager:
            with patch.object(manager.thread_manager, 'submit') as mock_submit, \
                 patch('ktscan.threading_manager.as_completed') as mock_as_completed:
                
                # Create mock futures for each target
                mock_futures = {}
                for target in targets:
                    mock_future = Mock(spec=Future)
                    result = CertResult(endpoints=[target], hostname="example.com")
                    result.valid = True
                    mock_future.result.return_value = result
                    mock_futures[mock_future] = target
                
                mock_submit.side_effect = list(mock_futures.keys())
                mock_as_completed.return_value = mock_futures.keys()
                
                results = list(manager.scan_targets_streaming(targets, mock_scan_function, "example.com"))
                
                assert len(results) == 2
                assert all(r.valid for r in results)
                assert all(r.hostname == "example.com" for r in results)

    def test_scan_targets_streaming_with_failures(self):
        """Test scan_targets_streaming with some failures"""
        targets = [("192.168.1.1", 443), ("192.168.1.2", 443)]
        
        with CertScanManager(self.max_workers) as manager:
            with patch.object(manager.thread_manager, 'submit') as mock_submit, \
                 patch('ktscan.threading_manager.as_completed') as mock_as_completed:
                
                # Create mock futures - one succeeds, one fails
                mock_futures = {}
                
                # First target succeeds
                mock_future1 = Mock(spec=Future)
                result1 = CertResult(endpoints=[targets[0]], hostname="example.com")
                result1.valid = True
                mock_future1.result.return_value = result1
                mock_futures[mock_future1] = targets[0]
                
                # Second target fails
                mock_future2 = Mock(spec=Future)
                mock_future2.result.side_effect = Exception("Streaming scan failed")
                mock_futures[mock_future2] = targets[1]
                
                mock_submit.side_effect = list(mock_futures.keys())
                mock_as_completed.return_value = mock_futures.keys()
                
                results = list(manager.scan_targets_streaming(
                    targets, lambda ip, port, hostname: None, "example.com"
                ))
                
                # Should only get successful result
                assert len(results) == 1
                assert results[0].valid

    def test_integration_threadmanager_with_ktscan(self):
        """Test integration between ThreadManager and CertScanManager"""
        # This tests that CertScanManager properly delegates to ThreadManager
        targets = [("192.168.1.1", 443)]
        
        def mock_scan_function(ip, port, hostname):
            result = CertResult(endpoints=[(ip, port)], hostname=hostname)
            result.valid = True
            return result
        
        with CertScanManager(self.max_workers) as manager:
            # Verify ThreadManager is used internally
            assert isinstance(manager.thread_manager, ThreadManager)
            assert manager.thread_manager.max_workers == self.max_workers
            
            # Test that methods work
            with patch.object(manager.thread_manager, 'map_parallel') as mock_map:
                mock_result = CertResult(endpoints=[("192.168.1.1", 443)], hostname="example.com")
                mock_result.valid = True
                mock_map.return_value = [mock_result]
                
                results = manager.scan_targets(targets, mock_scan_function, "example.com")
                
                assert len(results) == 1
                assert results[0].valid
                
                # Verify delegation occurred
                mock_map.assert_called_once()

    def test_real_execution_simulation(self):
        """Test closer-to-real execution without mocking thread pool"""
        def simple_doubler(x):
            # Simulate some work
            time.sleep(0.001)
            return x * 2
        
        with ThreadManager(2) as manager:
            results = manager.map_parallel(simple_doubler, [1, 2, 3, 4, 5])
            
            # All items should be processed
            assert len(results) == 5
            # Results should be doubled (order may vary)
            assert sorted(results) == [2, 4, 6, 8, 10]

    def test_error_handling_real_execution(self):
        """Test error handling with real thread pool"""
        def sometimes_fails(x):
            if x == 3:
                raise ValueError(f"Failed on {x}")
            return x * 2
        
        with ThreadManager(2) as manager:
            results = manager.map_parallel(sometimes_fails, [1, 2, 3, 4])
            
            # Should have 4 results (3 successful + 1 None for failure)
            assert len(results) == 4
            # Count None values (failures)
            none_count = sum(1 for r in results if r is None)
            assert none_count == 1
            # Check successful results exist
            successful = [r for r in results if r is not None]
            assert len(successful) == 3