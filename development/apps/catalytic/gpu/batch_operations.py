"""
GPU Batch Operations - Vectorized operations for multiple lattices
Enables parallel processing of multiple lattices for 3-5x speedup
"""

import logging
import time
from typing import List, Optional, Dict, Any
import numpy as np

logger = logging.getLogger(__name__)


class BatchOperationError(Exception):
    """Raised when batch operation fails"""

    pass


class GPUBatchOperations:
    """
    Batch operations for GPU-accelerated lattice processing
    Processes multiple lattices in parallel for improved throughput
    """

    def __init__(self, device_id: int = 0, backend: str = "pytorch"):
        """
        Initialize batch operations

        Args:
            device_id: GPU device ID
            backend: Backend to use ("pytorch" or "cupy")
        """
        self.device_id = device_id
        self.backend = backend

        # Detect backend availability
        self.pytorch_available = False
        self.cupy_available = False
        self._detect_backends()

        # Statistics
        self._total_batch_ops = 0
        self._total_items_processed = 0
        self._total_time_ms = 0.0

        logger.info(f"GPUBatchOperations initialized: device={device_id}, backend={backend}")

    def _detect_backends(self):
        """Detect available GPU backends"""
        try:
            import torch

            if torch.cuda.is_available():
                self.pytorch_available = True
        except ImportError:
            pass

        try:
            import cupy as cp

            if cp.cuda.is_available():
                self.cupy_available = True
        except ImportError:
            pass

    def batch_xor_transform(
        self, data_list: List[np.ndarray], key_list: Optional[List[np.ndarray]] = None
    ) -> List[np.ndarray]:
        """
        Batch XOR transformation on multiple arrays

        Args:
            data_list: List of input arrays
            key_list: Optional list of keys (one per array)

        Returns:
            List of transformed arrays
        """
        if not data_list:
            return []

        start_time = time.time()

        if self.backend == "pytorch" and self.pytorch_available:
            results = self._batch_xor_pytorch(data_list, key_list)
        elif self.backend == "cupy" and self.cupy_available:
            results = self._batch_xor_cupy(data_list, key_list)
        else:
            # Fallback to sequential CPU
            results = self._batch_xor_cpu(data_list, key_list)

        elapsed_ms = (time.time() - start_time) * 1000
        self._record_stats(len(data_list), elapsed_ms)

        logger.debug(
            f"Batch XOR: {len(data_list)} arrays in {elapsed_ms:.2f}ms "
            f"({elapsed_ms / len(data_list):.2f}ms per array)"
        )

        return results

    def _batch_xor_pytorch(
        self, data_list: List[np.ndarray], key_list: Optional[List[np.ndarray]]
    ) -> List[np.ndarray]:
        """PyTorch implementation of batch XOR"""
        import torch

        device = torch.device(f"cuda:{self.device_id}")
        results = []

        try:
            # Process in batches if arrays are same size
            if self._arrays_same_size(data_list):
                # Stack into single tensor for parallel processing
                batch_data = np.stack([arr.astype(np.uint8) for arr in data_list])
                batch_tensor = torch.from_numpy(batch_data).to(device)

                if key_list:
                    batch_keys = np.stack([k.astype(np.uint8) for k in key_list])
                    keys_tensor = torch.from_numpy(batch_keys).to(device)
                else:
                    # Generate random keys for entire batch
                    keys_tensor = torch.randint(
                        0, 256, batch_tensor.shape, dtype=torch.uint8, device=device
                    )

                # Parallel XOR on entire batch
                result_tensor = torch.bitwise_xor(batch_tensor, keys_tensor)

                # Convert back to list of numpy arrays
                result_batch = result_tensor.cpu().numpy()
                results = [result_batch[i] for i in range(len(data_list))]

            else:
                # Process individually (different sizes)
                for i, data in enumerate(data_list):
                    data_uint = data.astype(np.uint8)
                    data_tensor = torch.from_numpy(data_uint).to(device)

                    if key_list and i < len(key_list):
                        key = key_list[i].astype(np.uint8)
                        key_tensor = torch.from_numpy(key).to(device)
                    else:
                        key_tensor = torch.randint(
                            0, 256, data_tensor.shape, dtype=torch.uint8, device=device
                        )

                    result = torch.bitwise_xor(data_tensor, key_tensor)
                    results.append(result.cpu().numpy())

        except Exception as e:
            logger.error(f"PyTorch batch XOR failed: {e}")
            raise BatchOperationError(f"Batch XOR failed: {e}")

        return results

    def _batch_xor_cupy(
        self, data_list: List[np.ndarray], key_list: Optional[List[np.ndarray]]
    ) -> List[np.ndarray]:
        """CuPy implementation of batch XOR"""
        import cupy as cp

        results = []

        try:
            for i, data in enumerate(data_list):
                data_uint = data.astype(np.uint8)
                data_gpu = cp.array(data_uint)

                if key_list and i < len(key_list):
                    key = key_list[i].astype(np.uint8)
                    key_gpu = cp.array(key)
                else:
                    key_gpu = cp.random.randint(0, 256, size=data.shape, dtype=cp.uint8)

                result_gpu = cp.bitwise_xor(data_gpu, key_gpu)
                results.append(cp.asnumpy(result_gpu))

        except Exception as e:
            logger.error(f"CuPy batch XOR failed: {e}")
            raise BatchOperationError(f"Batch XOR failed: {e}")

        return results

    def _batch_xor_cpu(
        self, data_list: List[np.ndarray], key_list: Optional[List[np.ndarray]]
    ) -> List[np.ndarray]:
        """CPU fallback for batch XOR"""
        results = []

        for i, data in enumerate(data_list):
            data_uint = data.astype(np.uint8)

            if key_list and i < len(key_list):
                key = key_list[i].astype(np.uint8)
            else:
                key = np.random.randint(0, 256, size=len(data), dtype=np.uint8)

            results.append(np.bitwise_xor(data_uint, key))

        return results

    def batch_matrix_multiply(
        self, a_list: List[np.ndarray], b_list: List[np.ndarray]
    ) -> List[np.ndarray]:
        """
        Batch matrix multiplication

        Args:
            a_list: List of left matrices
            b_list: List of right matrices

        Returns:
            List of result matrices
        """
        if len(a_list) != len(b_list):
            raise ValueError("Matrix lists must have same length")

        if not a_list:
            return []

        start_time = time.time()

        if self.backend == "pytorch" and self.pytorch_available:
            results = self._batch_matmul_pytorch(a_list, b_list)
        elif self.backend == "cupy" and self.cupy_available:
            results = self._batch_matmul_cupy(a_list, b_list)
        else:
            results = self._batch_matmul_cpu(a_list, b_list)

        elapsed_ms = (time.time() - start_time) * 1000
        self._record_stats(len(a_list), elapsed_ms)

        logger.debug(f"Batch MatMul: {len(a_list)} operations in {elapsed_ms:.2f}ms")

        return results

    def _batch_matmul_pytorch(
        self, a_list: List[np.ndarray], b_list: List[np.ndarray]
    ) -> List[np.ndarray]:
        """PyTorch batch matrix multiplication"""
        import torch

        device = torch.device(f"cuda:{self.device_id}")
        results = []

        try:
            # Check if all matrices are same size (can use bmm)
            if (
                self._arrays_same_size(a_list)
                and self._arrays_same_size(b_list)
                and len(a_list) > 1
            ):
                # Use batch matrix multiply (bmm) - much faster!
                a_batch = torch.from_numpy(np.stack(a_list)).float().to(device)
                b_batch = torch.from_numpy(np.stack(b_list)).float().to(device)

                result_batch = torch.bmm(a_batch, b_batch)
                result_np = result_batch.cpu().numpy()

                results = [result_np[i] for i in range(len(a_list))]

            else:
                # Different sizes - process individually
                for a, b in zip(a_list, b_list):
                    a_tensor = torch.from_numpy(a).float().to(device)
                    b_tensor = torch.from_numpy(b).float().to(device)
                    result = torch.mm(a_tensor, b_tensor)
                    results.append(result.cpu().numpy())

        except Exception as e:
            logger.error(f"PyTorch batch matmul failed: {e}")
            raise BatchOperationError(f"Batch matmul failed: {e}")

        return results

    def _batch_matmul_cupy(
        self, a_list: List[np.ndarray], b_list: List[np.ndarray]
    ) -> List[np.ndarray]:
        """CuPy batch matrix multiplication"""
        import cupy as cp

        results = []

        try:
            for a, b in zip(a_list, b_list):
                a_gpu = cp.array(a)
                b_gpu = cp.array(b)
                result_gpu = cp.dot(a_gpu, b_gpu)
                results.append(cp.asnumpy(result_gpu))

        except Exception as e:
            logger.error(f"CuPy batch matmul failed: {e}")
            raise BatchOperationError(f"Batch matmul failed: {e}")

        return results

    def _batch_matmul_cpu(
        self, a_list: List[np.ndarray], b_list: List[np.ndarray]
    ) -> List[np.ndarray]:
        """CPU fallback for batch matmul"""
        return [np.dot(a, b) for a, b in zip(a_list, b_list)]

    def batch_element_wise_op(
        self, arrays: List[np.ndarray], operation: str, scalar: Optional[float] = None
    ) -> List[np.ndarray]:
        """
        Batch element-wise operations

        Args:
            arrays: List of input arrays
            operation: Operation name ("add", "multiply", "square", etc.)
            scalar: Optional scalar value for binary operations

        Returns:
            List of result arrays
        """
        if not arrays:
            return []

        start_time = time.time()

        if self.backend == "pytorch" and self.pytorch_available:
            results = self._batch_elementwise_pytorch(arrays, operation, scalar)
        elif self.backend == "cupy" and self.cupy_available:
            results = self._batch_elementwise_cupy(arrays, operation, scalar)
        else:
            results = self._batch_elementwise_cpu(arrays, operation, scalar)

        elapsed_ms = (time.time() - start_time) * 1000
        self._record_stats(len(arrays), elapsed_ms)

        return results

    def _batch_elementwise_pytorch(
        self, arrays: List[np.ndarray], operation: str, scalar: Optional[float]
    ) -> List[np.ndarray]:
        """PyTorch batch element-wise operations"""
        import torch

        device = torch.device(f"cuda:{self.device_id}")
        results = []

        try:
            if self._arrays_same_size(arrays):
                # Stack and process in parallel
                batch = torch.from_numpy(np.stack(arrays)).float().to(device)

                if operation == "add" and scalar is not None:
                    result = batch + scalar
                elif operation == "multiply" and scalar is not None:
                    result = batch * scalar
                elif operation == "square":
                    result = batch**2
                elif operation == "sqrt":
                    result = torch.sqrt(batch)
                elif operation == "exp":
                    result = torch.exp(batch)
                else:
                    raise ValueError(f"Unknown operation: {operation}")

                result_np = result.cpu().numpy()
                results = [result_np[i] for i in range(len(arrays))]

            else:
                # Process individually
                for arr in arrays:
                    tensor = torch.from_numpy(arr).float().to(device)

                    if operation == "add" and scalar is not None:
                        result = tensor + scalar
                    elif operation == "multiply" and scalar is not None:
                        result = tensor * scalar
                    elif operation == "square":
                        result = tensor**2
                    elif operation == "sqrt":
                        result = torch.sqrt(tensor)
                    elif operation == "exp":
                        result = torch.exp(tensor)
                    else:
                        raise ValueError(f"Unknown operation: {operation}")

                    results.append(result.cpu().numpy())

        except Exception as e:
            logger.error(f"PyTorch batch element-wise failed: {e}")
            raise BatchOperationError(f"Batch element-wise failed: {e}")

        return results

    def _batch_elementwise_cupy(
        self, arrays: List[np.ndarray], operation: str, scalar: Optional[float]
    ) -> List[np.ndarray]:
        """CuPy batch element-wise operations"""
        import cupy as cp

        results = []

        try:
            for arr in arrays:
                arr_gpu = cp.array(arr)

                if operation == "add" and scalar is not None:
                    result = arr_gpu + scalar
                elif operation == "multiply" and scalar is not None:
                    result = arr_gpu * scalar
                elif operation == "square":
                    result = arr_gpu**2
                elif operation == "sqrt":
                    result = cp.sqrt(arr_gpu)
                elif operation == "exp":
                    result = cp.exp(arr_gpu)
                else:
                    raise ValueError(f"Unknown operation: {operation}")

                results.append(cp.asnumpy(result))

        except Exception as e:
            logger.error(f"CuPy batch element-wise failed: {e}")
            raise BatchOperationError(f"Batch element-wise failed: {e}")

        return results

    def _batch_elementwise_cpu(
        self, arrays: List[np.ndarray], operation: str, scalar: Optional[float]
    ) -> List[np.ndarray]:
        """CPU fallback for batch element-wise"""
        results = []

        for arr in arrays:
            if operation == "add" and scalar is not None:
                result = arr + scalar
            elif operation == "multiply" and scalar is not None:
                result = arr * scalar
            elif operation == "square":
                result = arr**2
            elif operation == "sqrt":
                result = np.sqrt(arr)
            elif operation == "exp":
                result = np.exp(arr)
            else:
                raise ValueError(f"Unknown operation: {operation}")

            results.append(result)

        return results

    def _arrays_same_size(self, arrays: List[np.ndarray]) -> bool:
        """Check if all arrays have the same shape"""
        if not arrays:
            return False

        first_shape = arrays[0].shape
        return all(arr.shape == first_shape for arr in arrays)

    def _record_stats(self, batch_size: int, elapsed_ms: float):
        """Record batch operation statistics"""
        self._total_batch_ops += 1
        self._total_items_processed += batch_size
        self._total_time_ms += elapsed_ms

    def get_stats(self) -> Dict[str, Any]:
        """Get batch operation statistics"""
        if self._total_batch_ops == 0:
            avg_batch_size = 0
            avg_time_ms = 0
            avg_per_item_ms = 0
        else:
            avg_batch_size = self._total_items_processed / self._total_batch_ops
            avg_time_ms = self._total_time_ms / self._total_batch_ops
            avg_per_item_ms = (
                self._total_time_ms / self._total_items_processed
                if self._total_items_processed > 0
                else 0
            )

        return {
            "total_batch_ops": self._total_batch_ops,
            "total_items_processed": self._total_items_processed,
            "avg_batch_size": avg_batch_size,
            "avg_time_ms": avg_time_ms,
            "avg_per_item_ms": avg_per_item_ms,
            "total_time_ms": self._total_time_ms,
        }

    def reset_stats(self):
        """Reset statistics"""
        self._total_batch_ops = 0
        self._total_items_processed = 0
        self._total_time_ms = 0.0
