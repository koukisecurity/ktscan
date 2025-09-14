import logging
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from typing import List, Callable, Any, Optional, Iterator


class ThreadManager:
    """Global thread pool manager that respects user's thread limit across all IO operations"""

    def __init__(self, max_workers: int) -> None:
        self.max_workers = max_workers
        self.logger = logging.getLogger(__name__)
        self.executor: Optional[ThreadPoolExecutor] = None

    def __enter__(self) -> "ThreadManager":
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.logger.info(f"Initialized thread pool with {self.max_workers} workers")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.executor:
            self.executor.shutdown(wait=True)

    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """Submit a task to the thread pool"""
        if not self.executor:
            raise RuntimeError(
                "ThreadPoolExecutor not initialized. Use as context manager."
            )
        return self.executor.submit(fn, *args, **kwargs)

    def map_parallel(
        self,
        func: Callable[[Any], Any],
        iterable: Iterator[Any],
        max_concurrent: Optional[int] = None,
        preserve_order: bool = False,
    ) -> List[Any]:
        """Execute function on iterable items in parallel, respecting thread limits

        Args:
            func: Function to execute on each item
            iterable: Items to process
            max_concurrent: Maximum number of concurrent operations (defaults to max_workers)
            preserve_order: If True, results maintain original order (slower)

        Returns:
            List of results (may contain None for failed operations)
        """
        if not self.executor:
            raise RuntimeError("ThreadPoolExecutor not initialized.")

        items = list(iterable)
        if not items:
            return []

        # Limit concurrent operations to not overwhelm the thread pool
        batch_size = min(len(items), max_concurrent or self.max_workers)
        results = [None] * len(items) if preserve_order else []

        if preserve_order:
            # Process all items but maintain order
            futures = {
                self.executor.submit(func, item): i for i, item in enumerate(items)
            }

            for future in as_completed(futures):
                item_index = futures[future]
                try:
                    result = future.result()
                    results[item_index] = result
                except Exception as e:
                    item = items[item_index]
                    self.logger.error(f"Task failed for {item}: {e}")
                    results[item_index] = None
        else:
            # Process in batches for better resource management
            for i in range(0, len(items), batch_size):
                batch = items[i : i + batch_size]
                futures = {self.executor.submit(func, item): item for item in batch}

                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        item = futures[future]
                        self.logger.error(f"Task failed for {item}: {e}")
                        results.append(None)

        return results

    def map_with_callback(
        self,
        func: Callable[[Any], Any],
        iterable: Iterator[Any],
        callback: Optional[Callable[[Any], None]] = None,
        error_callback: Optional[Callable[[Any, Exception], None]] = None,
        max_concurrent: Optional[int] = None,
    ) -> List[Any]:
        """Execute function in parallel with progress callbacks

        Args:
            func: Function to execute on each item
            iterable: Items to process
            callback: Called on each successful result
            error_callback: Called on each error (item, exception)
            max_concurrent: Maximum number of concurrent operations

        Returns:
            List of successful results (excludes failed operations)
        """
        if not self.executor:
            raise RuntimeError("ThreadPoolExecutor not initialized.")

        items = list(iterable)
        if not items:
            return []

        batch_size = min(len(items), max_concurrent or self.max_workers)
        results = []

        # Submit all tasks
        futures = {self.executor.submit(func, item): item for item in items}

        for future in as_completed(futures):
            item = futures[future]
            try:
                result = future.result()
                results.append(result)
                if callback:
                    callback(result)
            except Exception as e:
                self.logger.error(f"Task failed for {item}: {e}")
                if error_callback:
                    error_callback(item, e)

        return results

    def execute_with_semaphore(
        self, func: Callable[[Any], Any], iterable: Iterator[Any], max_concurrent: int
    ) -> List[Any]:
        """Execute function with explicit concurrency control using semaphore pattern

        Useful when you want to limit concurrency below the thread pool size
        for resource-intensive operations like HTTP requests.
        """
        if not self.executor:
            raise RuntimeError("ThreadPoolExecutor not initialized.")

        items = list(iterable)
        if not items:
            return []

        results = []
        # Process in controlled batches
        for i in range(0, len(items), max_concurrent):
            batch = items[i : i + max_concurrent]
            batch_results = self.map_parallel(
                func, batch, max_concurrent=max_concurrent
            )
            results.extend(batch_results)

        return results

