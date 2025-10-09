"""
Unit tests for CUDA initialization module
Tests initialization logic, error handling, and state management
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch
import os

# Add development directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from libs.gpu.cuda_init import (
    initialize_cuda_environment,
    is_cuda_available,
    get_cuda_lib_path,
    get_cuda_info,
    validate_cupy_curand,
)


class TestCudaInitialization:
    """Test CUDA environment initialization"""

    def setup_method(self):
        """Reset global state before each test"""
        import libs.gpu.cuda_init as cuda_module

        cuda_module._cuda_initialized = False
        cuda_module._cuda_available = False
        cuda_module._torch_cuda_lib_path = None

    def test_initialize_cuda_idempotent(self):
        """Verify initialization can be called multiple times safely"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            # Create mock lib directory with CUDA DLLs
            Path(__file__).parent / "torch" / "lib"
            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path("cuda_runtime.dll")]),
            ):
                result1 = initialize_cuda_environment(verbose=False)
                result2 = initialize_cuda_environment(verbose=False)

                assert result1 == result2
                assert result1 is True

    def test_initialize_cuda_force_reinit(self):
        """Verify force flag re-initializes CUDA"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path("cuda_runtime.dll")]),
            ):
                # First initialization
                initialize_cuda_environment(verbose=False)

                # Force re-initialization
                result = initialize_cuda_environment(force=True, verbose=False)
                assert result is True

    def test_initialize_cuda_no_torch(self):
        """Test behavior when PyTorch is not available"""
        with patch("libs.gpu.cuda_init.torch", side_effect=ImportError("No module named 'torch'")):
            result = initialize_cuda_environment(verbose=False)
            assert result is False

    def test_initialize_cuda_no_cuda_support(self):
        """Test behavior when CUDA is not available"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = False

            result = initialize_cuda_environment(verbose=False)
            assert result is False

    def test_initialize_cuda_missing_lib_directory(self):
        """Test behavior when torch lib directory doesn't exist"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            with patch("pathlib.Path.exists", return_value=False):
                result = initialize_cuda_environment(verbose=False)
                assert result is False

    def test_initialize_cuda_no_cuda_dlls(self):
        """Test behavior when no CUDA DLLs are found"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[]),
            ):
                result = initialize_cuda_environment(verbose=False)
                assert result is False

    def test_initialize_cuda_sets_environment_variables(self):
        """Test that environment variables are set correctly"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            mock_lib_path = Path(__file__).parent / "torch" / "lib"
            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path("cuda_runtime.dll")]),
                patch("pathlib.Path.absolute", return_value=mock_lib_path),
            ):
                # Clear environment
                os.environ.pop("CUDA_PATH", None)
                os.environ.pop("CUDA_HOME", None)

                result = initialize_cuda_environment(verbose=False)

                assert result is True
                assert "CUDA_PATH" in os.environ
                assert "CUDA_HOME" in os.environ

    def test_is_cuda_available_auto_init(self):
        """Test that is_cuda_available auto-initializes"""
        with patch("libs.gpu.cuda_init.initialize_cuda_environment") as mock_init:
            mock_init.return_value = True

            is_cuda_available()

            mock_init.assert_called_once_with(verbose=False)

    def test_get_cuda_lib_path_returns_path(self):
        """Test get_cuda_lib_path returns valid path"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path("cuda_runtime.dll")]),
            ):
                initialize_cuda_environment(verbose=False)
                path = get_cuda_lib_path()

                assert path is not None
                assert isinstance(path, Path)

    def test_get_cuda_info_returns_dict(self):
        """Test get_cuda_info returns complete information"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "NVIDIA GTX 1080"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            Path(__file__).parent / "torch" / "lib"
            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path(f"cuda_{i}.dll") for i in range(37)]),
            ):
                initialize_cuda_environment(verbose=False)
                available, info = get_cuda_info()

                assert available is True
                assert info["available"] is True
                assert info["initialized"] is True
                assert info["version"] == "12.1"
                assert info["device_name"] == "NVIDIA GTX 1080"
                assert info["dll_count"] == 37
                assert info["lib_path"] is not None


class TestCupyValidation:
    """Test CuPy CURAND validation"""

    def setup_method(self):
        """Reset global state before each test"""
        import libs.gpu.cuda_init as cuda_module

        cuda_module._cuda_initialized = False
        cuda_module._cuda_available = False
        cuda_module._torch_cuda_lib_path = None

    def test_validate_cupy_curand_no_cuda(self):
        """Test CURAND validation when CUDA unavailable"""
        with patch("libs.gpu.cuda_init.is_cuda_available", return_value=False):
            result = validate_cupy_curand()
            assert result is False

    def test_validate_cupy_curand_success(self):
        """Test successful CURAND validation"""
        with (
            patch("libs.gpu.cuda_init.is_cuda_available", return_value=True),
            patch("libs.gpu.cuda_init.cp") as mock_cp,
        ):
            # Mock CuPy random array generation
            mock_array = Mock()
            mock_array.shape = (10,)
            mock_cp.random.randn.return_value = mock_array

            result = validate_cupy_curand()
            assert result is True

    def test_validate_cupy_curand_import_error(self):
        """Test CURAND validation when CuPy not available"""
        with (
            patch("libs.gpu.cuda_init.is_cuda_available", return_value=True),
            patch("libs.gpu.cuda_init.cp", side_effect=ImportError("No module named 'cupy'")),
        ):
            result = validate_cupy_curand()
            assert result is False

    def test_validate_cupy_curand_runtime_error(self):
        """Test CURAND validation with runtime error"""
        with (
            patch("libs.gpu.cuda_init.is_cuda_available", return_value=True),
            patch("libs.gpu.cuda_init.cp") as mock_cp,
        ):
            mock_cp.random.randn.side_effect = RuntimeError("CURAND_STATUS_INITIALIZATION_FAILED")

            result = validate_cupy_curand()
            assert result is False


class TestEnvironmentVariables:
    """Test environment variable handling"""

    def test_auto_init_cuda_env_var(self):
        """Test AUTO_INIT_CUDA environment variable"""
        with (
            patch.dict(os.environ, {"AUTO_INIT_CUDA": "1"}),
            patch("libs.gpu.cuda_init.initialize_cuda_environment"),
        ):
            # Reload module to trigger auto-init
            import importlib
            import libs.gpu.cuda_init as cuda_module

            importlib.reload(cuda_module)

    def test_path_environment_prepending(self):
        """Test that torch lib is prepended to PATH"""
        os.environ.get("PATH", "")

        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            mock_lib_str = str(Path(__file__).parent / "torch" / "lib")
            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path("cuda_runtime.dll")]),
                patch("pathlib.Path.absolute", return_value=Path(mock_lib_str)),
            ):
                initialize_cuda_environment(verbose=False)

                new_path = os.environ.get("PATH", "")
                assert new_path.startswith(mock_lib_str)


class TestErrorCases:
    """Test error handling and edge cases"""

    def setup_method(self):
        """Reset global state before each test"""
        import libs.gpu.cuda_init as cuda_module

        cuda_module._cuda_initialized = False
        cuda_module._cuda_available = False
        cuda_module._torch_cuda_lib_path = None

    def test_generic_exception_handling(self):
        """Test handling of unexpected exceptions"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.side_effect = Exception("Unexpected error")

            result = initialize_cuda_environment(verbose=False)
            assert result is False

    def test_add_dll_directory_failure(self):
        """Test handling when add_dll_directory fails"""
        with patch("libs.gpu.cuda_init.torch") as mock_torch:
            mock_torch.cuda.is_available.return_value = True
            mock_torch.__version__ = "2.5.1+cu121"
            mock_torch.version.cuda = "12.1"
            mock_torch.cuda.get_device_name.return_value = "Test GPU"
            mock_torch.__file__ = str(Path(__file__).parent / "torch" / "__init__.py")

            with (
                patch("pathlib.Path.exists", return_value=True),
                patch("pathlib.Path.glob", return_value=[Path("cuda_runtime.dll")]),
                patch("os.add_dll_directory", side_effect=OSError("Access denied")),
            ):
                # Should succeed despite add_dll_directory failure
                result = initialize_cuda_environment(verbose=False)
                assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
