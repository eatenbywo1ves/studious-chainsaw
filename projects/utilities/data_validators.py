"""
Data Validation System
Comprehensive validation functions for random output data
"""

import numpy as np
from typing import Any, Dict, List, Tuple, Union, Optional
from dataclasses import dataclass
from collections import OrderedDict


@dataclass
class ValidationResult:
    """Result of a validation check"""
    name: str
    passed: bool
    message: str
    value: Optional[Any] = None
    expected: Optional[Any] = None
    severity: str = "ERROR"  # ERROR, WARNING, INFO


class DataValidator:
    """Comprehensive data validation system"""

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.validation_results: List[ValidationResult] = []
        self.tolerances = {
            'float_precision': 1e-10,
            'statistical_significance': 0.05,
            'outlier_threshold': 3.0  # standard deviations
        }

    def validate_numerical_data(self, data: Dict[str, Any]) -> List[ValidationResult]:
        """Validate numerical data integrity"""
        results = []

        for key, values in data.items():
            if values is None:
                results.append(ValidationResult(
                    name=f"null_check_{key}",
                    passed=False,
                    message=f"Data for {key} is None",
                    severity="ERROR"
                ))
                continue

            # Type validation
            if isinstance(values, (list, tuple, np.ndarray)):
                # Check if numeric
                numeric_check = self._validate_numeric_types(key, values)
                results.append(numeric_check)

                if numeric_check.passed:
                    # Range validation
                    range_check = self._validate_numeric_ranges(key, values)
                    results.append(range_check)

                    # Sorting validation (if supposed to be sorted)
                    if 'sorted' in key or 'ordered' in key:
                        sort_check = self._validate_sorted_order(key, values)
                        results.append(sort_check)

                    # Statistical validation
                    stats_check = self._validate_statistical_properties(
                        key, values)
                    results.append(stats_check)

        return results

    def _validate_numeric_types(self, key: str, values: Union[List, Tuple, np.ndarray]) -> ValidationResult:
        """Validate that all values are numeric"""
        try:
            numeric_values = [float(v) for v in values]
            return ValidationResult(
                name=f"numeric_type_{key}",
                passed=True,
                message=f"All values in {key} are numeric",
                value=len(numeric_values)
            )
        except (ValueError, TypeError) as e:
            return ValidationResult(
                name=f"numeric_type_{key}",
                passed=False,
                message=f"Non-numeric values found in {key}: {str(e)}"
            )

    def _validate_numeric_ranges(self, key: str, values: Union[List, Tuple, np.ndarray]) -> ValidationResult:
        """Validate numeric values are within reasonable ranges"""
        try:
            values_array = np.array(values, dtype=float)

            # Check for infinities and NaN
            if np.any(np.isinf(values_array)) or np.any(np.isnan(values_array)):
                return ValidationResult(
                    name=f"range_check_{key}",
                    passed=False,
                    message=f"Invalid values (inf/nan) found in {key}"
                )

            # Check for reasonable ranges based on key name
            range_valid = True
            range_message = f"Values in {key} are within expected ranges"

            if 'temperature' in key.lower():
                if (np.any(values_array < -100) or
                        np.any(values_array > 100)):
                    range_valid = False
                    range_message = ("Temperature values outside "
                                     "reasonable range (-100, 100)")
            elif 'pressure' in key.lower():
                if np.any(values_array < 0) or np.any(values_array > 2000):
                    range_valid = False
                    range_message = ("Pressure values outside "
                                     "reasonable range (0, 2000)")
            elif 'humidity' in key.lower() or 'percent' in key.lower():
                if np.any(values_array < 0) or np.any(values_array > 100):
                    range_valid = False
                    range_message = "Percentage values outside range (0, 100)"
            elif 'ph' in key.lower():
                if np.any(values_array < 0) or np.any(values_array > 14):
                    range_valid = False
                    range_message = "pH values outside range (0, 14)"

            return ValidationResult(
                name=f"range_check_{key}",
                passed=range_valid,
                message=range_message,
                value=f"min: {np.min(values_array):.3f}, "
                      f"max: {np.max(values_array):.3f}"
            )

        except Exception as e:
            return ValidationResult(
                name=f"range_check_{key}",
                passed=False,
                message=f"Range validation failed for {key}: {str(e)}"
            )

    def _validate_sorted_order(self, key: str, values: Union[List, Tuple, np.ndarray]) -> ValidationResult:
        """Validate that values are properly sorted"""
        try:
            values_array = np.array(values, dtype=float)
            is_sorted = np.all(values_array[:-1] <= values_array[1:])

            return ValidationResult(
                name=f"sort_order_{key}",
                passed=is_sorted,
                message=f"Values in {key} are "
                        f"{'properly' if is_sorted else 'NOT properly'} "
                        f"sorted",
                value=f"sorted: {is_sorted}"
            )

        except Exception as e:
            return ValidationResult(
                name=f"sort_order_{key}",
                passed=False,
                message=f"Sort validation failed for {key}: {str(e)}"
            )

    def _validate_statistical_properties(self, key: str, values: Union[List, Tuple, np.ndarray]) -> ValidationResult:
        """Validate statistical properties of the data"""
        try:
            values_array = np.array(values, dtype=float)

            if len(values_array) < 2:
                return ValidationResult(
                    name=f"stats_check_{key}",
                    passed=True,
                    message=f"Insufficient data for statistical "
                            f"validation in {key}",
                    severity="INFO"
                )

            mean_val = np.mean(values_array)
            std_val = np.std(values_array)

            # Check for outliers (values beyond 3 standard deviations)
            if std_val > 0:
                z_scores = np.abs((values_array - mean_val) / std_val)
                outliers = np.sum(
                    z_scores > self.tolerances['outlier_threshold'])
                outlier_ratio = outliers / len(values_array)

                # More than 5% outliers might indicate an issue
                outliers_ok = outlier_ratio <= 0.05

                return ValidationResult(
                    name=f"stats_check_{key}",
                    passed=outliers_ok,
                    message=f"Statistical check for {key}: "
                            f"{outliers} outliers ({outlier_ratio:.1%})",
                    value=f"mean: {mean_val:.3f}, std: {std_val:.3f}, "
                          f"outliers: {outliers}",
                    severity="WARNING" if not outliers_ok else "INFO"
                )
            else:
                return ValidationResult(
                    name=f"stats_check_{key}",
                    passed=True,
                    message=f"Statistical check for {key}: "
                            f"zero variance (constant values)",
                    value=f"constant value: {mean_val:.3f}",
                    severity="INFO"
                )

        except Exception as e:
            return ValidationResult(
                name=f"stats_check_{key}",
                passed=False,
                message=f"Statistical validation failed for {key}: {str(e)}"
            )

    def validate_text_data(self, data: Dict[str, Any]) -> List[ValidationResult]:
        """Validate text data integrity"""
        results = []

        for key, values in data.items():
            if values is None:
                results.append(ValidationResult(
                    name=f"text_null_check_{key}",
                    passed=False,
                    message=f"Text data for {key} is None"
                ))
                continue

            # Type validation
            if isinstance(values, (list, tuple)):
                # Check if all are strings
                string_check = self._validate_string_types(key, values)
                results.append(string_check)

                if string_check.passed:
                    # Length validation
                    length_check = self._validate_string_lengths(key, values)
                    results.append(length_check)

                    # Character validation
                    char_check = self._validate_string_characters(
                        key, values)
                    results.append(char_check)

                    # Sorting validation (if supposed to be sorted)
                    if ('sorted' in key or 'ordered' in key or
                            'alphabetic' in key):
                        alpha_sort_check = self._validate_alphabetic_order(
                            key, values)
                        results.append(alpha_sort_check)

            elif isinstance(values, str):
                # Single string validation
                single_string_check = self._validate_single_string(
                    key, values)
                results.append(single_string_check)

        return results

    def _validate_string_types(self, key: str, values: Union[List, Tuple]) -> ValidationResult:
        """Validate that all values are strings"""
        try:
            string_count = sum(1 for v in values if isinstance(v, str))
            total_count = len(values)

            return ValidationResult(
                name=f"string_type_{key}",
                passed=string_count == total_count,
                message=f"String validation for {key}: "
                        f"{string_count}/{total_count} are strings",
                value=f"{string_count}/{total_count}"
            )

        except Exception as e:
            return ValidationResult(
                name=f"string_type_{key}",
                passed=False,
                message=f"String type validation failed for {key}: {str(e)}"
            )

    def _validate_string_lengths(self, key: str, values: Union[List, Tuple]) -> ValidationResult:
        """Validate string lengths are reasonable"""
        try:
            lengths = [len(str(v)) for v in values]
            avg_length = np.mean(lengths)
            max_length = max(lengths)
            min_length = min(lengths)

            # Check for reasonable lengths (not too short or too long)
            length_ok = min_length >= 1 and max_length <= 1000

            return ValidationResult(
                name=f"string_length_{key}",
                passed=length_ok,
                message=f"String length validation for {key}",
                value=f"min: {min_length}, max: {max_length}, "
                      f"avg: {avg_length:.1f}",
                severity="WARNING" if not length_ok else "INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"string_length_{key}",
                passed=False,
                message=f"String length validation failed for {key}: {str(e)}"
            )

    def _validate_string_characters(self, key: str, values: Union[List, Tuple]) -> ValidationResult:
        """Validate string characters are appropriate"""
        try:
            # Check for non-printable characters
            printable_count = 0
            total_chars = 0

            for value in values:
                str_val = str(value)
                total_chars += len(str_val)
                printable_count += sum(
                    1 for c in str_val if c.isprintable())

            printable_ratio = printable_count / max(total_chars, 1)

            return ValidationResult(
                name=f"string_chars_{key}",
                passed=printable_ratio >= 0.95,  # At least 95% printable
                message=f"Character validation for {key}: "
                        f"{printable_ratio:.1%} printable",
                value=f"printable ratio: {printable_ratio:.3f}",
                severity="WARNING" if printable_ratio < 0.95 else "INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"string_chars_{key}",
                passed=False,
                message=f"Character validation failed for {key}: {str(e)}"
            )

    def _validate_alphabetic_order(self, key: str, values: Union[List, Tuple]) -> ValidationResult:
        """Validate alphabetic ordering"""
        try:
            str_values = [str(v) for v in values]
            is_sorted = str_values == sorted(str_values)

            return ValidationResult(
                name=f"alpha_order_{key}",
                passed=is_sorted,
                message=f"Alphabetic order validation for {key}: "
                        f"{'PASSED' if is_sorted else 'FAILED'}",
                value=f"alphabetically sorted: {is_sorted}"
            )

        except Exception as e:
            return ValidationResult(
                name=f"alpha_order_{key}",
                passed=False,
                message=f"Alphabetic order validation failed for "
                        f"{key}: {str(e)}"
            )

    def _validate_single_string(self, key: str, value: str) -> ValidationResult:
        """Validate a single string value"""
        try:
            length = len(value)
            printable_chars = sum(1 for c in value if c.isprintable())
            printable_ratio = printable_chars / max(length, 1)

            valid = (length > 0 and length < 10000 and
                     printable_ratio >= 0.95)

            return ValidationResult(
                name=f"single_string_{key}",
                passed=valid,
                message=f"Single string validation for {key}",
                value=f"length: {length}, printable: {printable_ratio:.1%}"
            )

        except Exception as e:
            return ValidationResult(
                name=f"single_string_{key}",
                passed=False,
                message=f"Single string validation failed for "
                        f"{key}: {str(e)}"
            )

    def validate_matrix_data(self, matrices: Dict[str, np.ndarray]) -> List[ValidationResult]:
        """Validate matrix data integrity"""
        results = []

        for name, matrix in matrices.items():
            if matrix is None:
                results.append(ValidationResult(
                    name=f"matrix_null_{name}",
                    passed=False,
                    message=f"Matrix {name} is None"
                ))
                continue

            # Shape validation
            shape_check = self._validate_matrix_shape(name, matrix)
            results.append(shape_check)

            # Data type validation
            dtype_check = self._validate_matrix_dtype(name, matrix)
            results.append(dtype_check)

            # Value validation
            value_check = self._validate_matrix_values(name, matrix)
            results.append(value_check)

            # Properties validation
            props_check = self._validate_matrix_properties(name, matrix)
            results.append(props_check)

        return results

    def _validate_matrix_shape(self, name: str, matrix: np.ndarray) -> ValidationResult:
        """Validate matrix shape"""
        try:
            shape = matrix.shape

            # Check if it's actually a 2D matrix
            is_2d = len(shape) == 2

            # Check if dimensions match name (e.g., "matrix_3x3")
            expected_shape = None
            if 'x' in name:
                try:
                    dims = name.split('_')[-1].split('x')
                    if len(dims) == 2:
                        expected_shape = (int(dims[0]), int(dims[1]))
                except Exception:
                    pass

            shape_matches = expected_shape is None or shape == expected_shape

            return ValidationResult(
                name=f"matrix_shape_{name}",
                passed=is_2d and shape_matches,
                message=f"Shape validation for {name}",
                value=f"shape: {shape}, expected: {expected_shape}",
                expected=expected_shape
            )

        except Exception as e:
            return ValidationResult(
                name=f"matrix_shape_{name}",
                passed=False,
                message=f"Matrix shape validation failed for "
                        f"{name}: {str(e)}"
            )

    def _validate_matrix_dtype(self, name: str, matrix: np.ndarray) -> ValidationResult:
        """Validate matrix data type"""
        try:
            dtype = matrix.dtype
            is_numeric = np.issubdtype(dtype, np.number)

            return ValidationResult(
                name=f"matrix_dtype_{name}",
                passed=is_numeric,
                message=f"Data type validation for {name}",
                value=f"dtype: {dtype}, numeric: {is_numeric}"
            )

        except Exception as e:
            return ValidationResult(
                name=f"matrix_dtype_{name}",
                passed=False,
                message=f"Matrix dtype validation failed for "
                        f"{name}: {str(e)}"
            )

    def _validate_matrix_values(self, name: str, matrix: np.ndarray) -> ValidationResult:
        """Validate matrix values"""
        try:
            # Check for invalid values
            has_inf = np.any(np.isinf(matrix))
            has_nan = np.any(np.isnan(matrix))

            # Check value ranges
            min_val = np.min(matrix)
            max_val = np.max(matrix)

            values_ok = not has_inf and not has_nan

            return ValidationResult(
                name=f"matrix_values_{name}",
                passed=values_ok,
                message=f"Value validation for {name}",
                value=f"range: [{min_val}, {max_val}], "
                      f"inf: {has_inf}, nan: {has_nan}",
                severity="ERROR" if not values_ok else "INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"matrix_values_{name}",
                passed=False,
                message=f"Matrix value validation failed for "
                        f"{name}: {str(e)}"
            )

    def _validate_matrix_properties(self, name: str, matrix: np.ndarray) -> ValidationResult:
        """Validate matrix mathematical properties"""
        try:
            properties = []

            # Check if square
            if matrix.shape[0] == matrix.shape[1]:
                properties.append("square")

                # Check if symmetric
                if np.allclose(
                        matrix, matrix.T,
                        rtol=self.tolerances['float_precision']):
                    properties.append("symmetric")

                # Check if diagonal
                if np.allclose(matrix - np.diag(np.diag(matrix)), 0):
                    properties.append("diagonal")

            # Check if sorted (rows sorted internally)
            rows_sorted = all(np.all(row[:-1] <= row[1:]) for row in matrix)
            if rows_sorted:
                properties.append("rows_sorted")

            return ValidationResult(
                name=f"matrix_props_{name}",
                passed=True,
                message=f"Matrix properties for {name}",
                value=f"properties: {properties}",
                severity="INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"matrix_props_{name}",
                passed=False,
                message=f"Matrix properties validation failed for "
                        f"{name}: {str(e)}"
            )

    def validate_structured_data(self, data: Dict[str, Any]) -> List[ValidationResult]:
        """Validate structured/nested data integrity"""
        results = []

        def validate_nested(key_path: str, value: Any, depth: int = 0) -> None:
            if depth > 10:  # Prevent infinite recursion
                results.append(ValidationResult(
                    name=f"depth_limit_{key_path}",
                    passed=False,
                    message=f"Maximum nesting depth exceeded at {key_path}"
                ))
                return

            if isinstance(value, dict):
                # Validate dictionary structure
                dict_check = self._validate_dict_structure(key_path, value)
                results.append(dict_check)

                # Recursively validate nested values
                for k, v in value.items():
                    validate_nested(f"{key_path}.{k}", v, depth + 1)

            elif isinstance(value, (list, tuple)):
                # Validate list/tuple structure
                list_check = self._validate_list_structure(key_path, value)
                results.append(list_check)

                # Check individual items if they're complex types
                for i, item in enumerate(value):
                    if isinstance(item, (dict, list, tuple)):
                        validate_nested(f"{key_path}[{i}]", item, depth + 1)

            else:
                # Validate individual values
                value_check = self._validate_individual_value(key_path, value)
                results.append(value_check)

        # Start validation
        for key, value in data.items():
            validate_nested(key, value)

        return results

    def _validate_dict_structure(self, key_path: str, value: dict) -> ValidationResult:
        """Validate dictionary structure"""
        try:
            key_count = len(value.keys())
            empty_values = sum(
                1 for v in value.values()
                if v is None or (hasattr(v, '__len__') and len(v) == 0))

            structure_ok = key_count > 0 and empty_values / key_count < 0.5

            return ValidationResult(
                name=f"dict_structure_{key_path.replace('.', '_')}",
                passed=structure_ok,
                message=f"Dictionary structure validation for {key_path}",
                value=f"keys: {key_count}, empty_values: {empty_values}",
                severity="WARNING" if not structure_ok else "INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"dict_structure_{key_path.replace('.', '_')}",
                passed=False,
                message=f"Dictionary structure validation failed for "
                        f"{key_path}: {str(e)}"
            )

    def _validate_list_structure(self, key_path: str, value: Union[list, tuple]) -> ValidationResult:
        """Validate list/tuple structure"""
        try:
            length = len(value)
            none_count = sum(1 for item in value if item is None)

            structure_ok = length > 0 and none_count / length < 0.5

            # Check type consistency
            types = set(type(item).__name__ for item in value
                        if item is not None)
            type_consistent = len(types) <= 2  # Allow for some type variation

            clean_key_path = (key_path.replace('.', '_')
                              .replace('[', '_').replace(']', '_'))

            return ValidationResult(
                name=f"list_structure_{clean_key_path}",
                passed=structure_ok and type_consistent,
                message=f"List structure validation for {key_path}",
                value=f"length: {length}, none_count: {none_count}, "
                      f"types: {types}",
                severity="INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"list_structure_{key_path.replace('.', '_')}",
                passed=False,
                message=f"List structure validation failed for "
                        f"{key_path}: {str(e)}"
            )

    def _validate_individual_value(self, key_path: str, value: Any) -> ValidationResult:
        """Validate individual values"""
        try:
            value_type = type(value).__name__

            # Basic validation - not None and reasonable type
            valid_types = {'int', 'float', 'str', 'bool', 'NoneType'}
            type_ok = value_type in valid_types

            return ValidationResult(
                name=f"individual_value_{key_path.replace('.', '_')}",
                passed=type_ok,
                message=f"Individual value validation for {key_path}",
                value=f"type: {value_type}, value: {str(value)[:50]}",
                severity="INFO"
            )

        except Exception as e:
            return ValidationResult(
                name=f"individual_value_{key_path.replace('.', '_')}",
                passed=False,
                message=f"Individual value validation failed for "
                        f"{key_path}: {str(e)}"
            )

    def generate_validation_report(self, all_results: List[ValidationResult]) -> Dict[str, Any]:
        """Generate comprehensive validation report"""

        # Categorize results
        passed = [r for r in all_results if r.passed]
        failed = [r for r in all_results if not r.passed]
        errors = [r for r in all_results
                  if r.severity == "ERROR" and not r.passed]
        warnings = [r for r in all_results
                    if r.severity == "WARNING" and not r.passed]

        # Calculate statistics
        total_checks = len(all_results)
        pass_rate = len(passed) / max(total_checks, 1)

        report = OrderedDict([
            ('total_validations', total_checks),
            ('passed', len(passed)),
            ('failed', len(failed)),
            ('errors', len(errors)),
            ('warnings', len(warnings)),
            ('pass_rate', round(pass_rate, 3)),
            ('overall_status', 'PASS' if len(errors) == 0 else 'FAIL'),
            ('details', {
                'error_details': [{'name': r.name, 'message': r.message}
                                  for r in errors],
                'warning_details': [{'name': r.name, 'message': r.message}
                                    for r in warnings],
                'passed_checks': [r.name for r in passed]
            })
        ])

        return report
