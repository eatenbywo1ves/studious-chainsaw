"""
Knowledge Base and Pattern Library for KA Lattice
Manages persistent knowledge storage and pattern recognition
"""

import json
import sqlite3
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
import numpy as np
import pickle
import logging

logger = logging.getLogger(__name__)


@dataclass
class Pattern:
    """Computational pattern in the knowledge base"""
    id: str
    operation: str
    input_shape: Tuple[int, ...]
    input_stats: Dict[str, float]  # mean, std, min, max
    output_shape: Tuple[int, ...]
    execution_time_ms: float
    memory_mb: float
    confidence: float
    created_at: datetime
    last_used: datetime
    usage_count: int = 0
    success_count: int = 0


class KnowledgeStore:
    """
    Persistent knowledge storage for KA Lattice
    Uses SQLite for metadata and file system for large patterns
    """

    def __init__(self, storage_path: Path):
        """
        Initialize knowledge store

        Args:
            storage_path: Path for storing knowledge base
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.db_path = self.storage_path / "knowledge.db"
        self.patterns_path = self.storage_path / "patterns"
        self.patterns_path.mkdir(exist_ok=True)

        # Initialize database
        self._init_database()

        # Cache for frequently accessed patterns
        self.pattern_cache: Dict[str, Pattern] = {}
        self.cache_size = 100

        logger.info(f"Knowledge store initialized at {self.storage_path}")

    def _init_database(self):
        """Initialize SQLite database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create patterns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS patterns (
                    id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    input_shape TEXT NOT NULL,
                    input_stats TEXT NOT NULL,
                    output_shape TEXT NOT NULL,
                    execution_time_ms REAL NOT NULL,
                    memory_mb REAL NOT NULL,
                    confidence REAL NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used TEXT NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0
                )
            """)

            # Create indexes
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation
                ON patterns(operation)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_confidence
                ON patterns(confidence DESC)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_usage
                ON patterns(usage_count DESC)
            """)

            # Create performance history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS performance_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    execution_time_ms REAL NOT NULL,
                    memory_mb REAL NOT NULL,
                    success BOOLEAN NOT NULL,
                    FOREIGN KEY (pattern_id) REFERENCES patterns(id)
                )
            """)

            conn.commit()

    def store_pattern(self, pattern: Pattern, result_data: Optional[Any] = None):
        """
        Store a pattern in the knowledge base

        Args:
            pattern: Pattern to store
            result_data: Optional result data to cache
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Store pattern metadata
            cursor.execute("""
                INSERT OR REPLACE INTO patterns
                (id, operation, input_shape, input_stats, output_shape,
                 execution_time_ms, memory_mb, confidence, created_at,
                 last_used, usage_count, success_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pattern.id,
                pattern.operation,
                json.dumps(pattern.input_shape),
                json.dumps(pattern.input_stats),
                json.dumps(pattern.output_shape),
                pattern.execution_time_ms,
                pattern.memory_mb,
                pattern.confidence,
                pattern.created_at.isoformat(),
                pattern.last_used.isoformat(),
                pattern.usage_count,
                pattern.success_count
            ))

            conn.commit()

        # Store result data if provided and small enough
        if result_data is not None and pattern.memory_mb < 10:
            pattern_file = self.patterns_path / f"{pattern.id}.pkl"
            with open(pattern_file, 'wb') as f:
                pickle.dump(result_data, f)

        # Update cache
        self.pattern_cache[pattern.id] = pattern
        self._maintain_cache_size()

        logger.debug(f"Stored pattern {pattern.id}")

    def retrieve_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """
        Retrieve a pattern by ID

        Args:
            pattern_id: Pattern ID

        Returns:
            Pattern if found, None otherwise
        """
        # Check cache first
        if pattern_id in self.pattern_cache:
            return self.pattern_cache[pattern_id]

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM patterns WHERE id = ?
            """, (pattern_id,))

            row = cursor.fetchone()
            if row:
                pattern = self._row_to_pattern(row)
                self.pattern_cache[pattern_id] = pattern
                return pattern

        return None

    def find_similar_patterns(
        self,
        operation: str,
        input_shape: Tuple[int, ...],
        input_stats: Dict[str, float],
        max_results: int = 5
    ) -> List[Pattern]:
        """
        Find similar patterns based on operation and input characteristics

        Args:
            operation: Operation type
            input_shape: Input data shape
            input_stats: Input statistics
            max_results: Maximum number of results

        Returns:
            List of similar patterns
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # First, find patterns with same operation
            cursor.execute("""
                SELECT * FROM patterns
                WHERE operation = ?
                ORDER BY confidence DESC, usage_count DESC
                LIMIT ?
            """, (operation, max_results * 2))

            candidates = [self._row_to_pattern(row) for row in cursor.fetchall()]

        # Calculate similarity scores
        similar_patterns = []
        for pattern in candidates:
            score = self._calculate_similarity(
                input_shape, input_stats,
                pattern.input_shape, pattern.input_stats
            )

            if score > 0.7:  # Similarity threshold
                similar_patterns.append((score, pattern))

        # Sort by similarity and return top results
        similar_patterns.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in similar_patterns[:max_results]]

    def _calculate_similarity(
        self,
        shape1: Tuple[int, ...],
        stats1: Dict[str, float],
        shape2: Tuple[int, ...],
        stats2: Dict[str, float]
    ) -> float:
        """Calculate similarity between two patterns"""
        score = 0.0

        # Shape similarity
        if shape1 == shape2:
            score += 0.5
        elif len(shape1) == len(shape2):
            score += 0.3

        # Statistical similarity
        stat_similarity = 0.0
        common_stats = set(stats1.keys()) & set(stats2.keys())

        for stat in common_stats:
            if stats1[stat] != 0:
                diff = abs(stats1[stat] - stats2[stat]) / abs(stats1[stat])
                stat_similarity += max(0, 1 - diff)

        if common_stats:
            score += (stat_similarity / len(common_stats)) * 0.5

        return score

    def update_pattern_performance(
        self,
        pattern_id: str,
        execution_time_ms: float,
        memory_mb: float,
        success: bool
    ):
        """Update pattern performance metrics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Update pattern statistics
            if success:
                cursor.execute("""
                    UPDATE patterns
                    SET usage_count = usage_count + 1,
                        success_count = success_count + 1,
                        last_used = ?
                    WHERE id = ?
                """, (datetime.now().isoformat(), pattern_id))
            else:
                cursor.execute("""
                    UPDATE patterns
                    SET usage_count = usage_count + 1,
                        last_used = ?
                    WHERE id = ?
                """, (datetime.now().isoformat(), pattern_id))

            # Record performance history
            cursor.execute("""
                INSERT INTO performance_history
                (pattern_id, timestamp, execution_time_ms, memory_mb, success)
                VALUES (?, ?, ?, ?, ?)
            """, (
                pattern_id,
                datetime.now().isoformat(),
                execution_time_ms,
                memory_mb,
                success
            ))

            conn.commit()

    def get_top_patterns(self, limit: int = 10) -> List[Pattern]:
        """Get top patterns by usage and confidence"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM patterns
                ORDER BY
                    (confidence * 0.4 +
                     (CAST(success_count AS REAL) / MAX(usage_count, 1)) * 0.3 +
                     MIN(usage_count / 100.0, 1.0) * 0.3) DESC
                LIMIT ?
            """, (limit,))

            return [self._row_to_pattern(row) for row in cursor.fetchall()]

    def cleanup_old_patterns(self, days: int = 30):
        """Remove patterns not used in specified days"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Get patterns to delete
            cursor.execute("""
                SELECT id FROM patterns
                WHERE last_used < ? AND usage_count < 5
            """, (cutoff_date,))

            patterns_to_delete = [row[0] for row in cursor.fetchall()]

            # Delete patterns
            cursor.execute("""
                DELETE FROM patterns
                WHERE last_used < ? AND usage_count < 5
            """, (cutoff_date,))

            # Delete performance history
            cursor.execute("""
                DELETE FROM performance_history
                WHERE pattern_id IN ({})
            """.format(','.join('?' * len(patterns_to_delete))), patterns_to_delete)

            conn.commit()

        # Delete cached files
        for pattern_id in patterns_to_delete:
            pattern_file = self.patterns_path / f"{pattern_id}.pkl"
            if pattern_file.exists():
                pattern_file.unlink()

        logger.info(f"Cleaned up {len(patterns_to_delete)} old patterns")

    def _row_to_pattern(self, row) -> Pattern:
        """Convert database row to Pattern object"""
        return Pattern(
            id=row[0],
            operation=row[1],
            input_shape=tuple(json.loads(row[2])),
            input_stats=json.loads(row[3]),
            output_shape=tuple(json.loads(row[4])),
            execution_time_ms=row[5],
            memory_mb=row[6],
            confidence=row[7],
            created_at=datetime.fromisoformat(row[8]),
            last_used=datetime.fromisoformat(row[9]),
            usage_count=row[10],
            success_count=row[11]
        )

    def _maintain_cache_size(self):
        """Maintain cache size limit"""
        if len(self.pattern_cache) > self.cache_size:
            # Remove least recently used patterns
            sorted_patterns = sorted(
                self.pattern_cache.items(),
                key=lambda x: x[1].last_used
            )
            for pattern_id, _ in sorted_patterns[:-self.cache_size]:
                del self.pattern_cache[pattern_id]

    def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge store statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM patterns")
            total_patterns = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM performance_history")
            total_history = cursor.fetchone()[0]

            cursor.execute("""
                SELECT AVG(confidence), AVG(usage_count), AVG(success_count)
                FROM patterns
            """)
            avg_stats = cursor.fetchone()

        return {
            'total_patterns': total_patterns,
            'total_history_records': total_history,
            'average_confidence': avg_stats[0] or 0,
            'average_usage': avg_stats[1] or 0,
            'average_success': avg_stats[2] or 0,
            'cache_size': len(self.pattern_cache),
            'storage_size_mb': sum(
                f.stat().st_size for f in self.patterns_path.glob('*.pkl')
            ) / (1024 * 1024)
        }


class PatternLibrary:
    """
    Pre-defined pattern library for common computational patterns
    Provides optimized implementations for known patterns
    """

    def __init__(self):
        """Initialize pattern library with common patterns"""
        self.patterns = {
            'matrix_multiply': self._pattern_matrix_multiply,
            'fourier_transform': self._pattern_fft,
            'convolution': self._pattern_convolution,
            'graph_traversal': self._pattern_graph_traversal,
            'optimization': self._pattern_optimization
        }

    def _pattern_matrix_multiply(self, A: np.ndarray, B: np.ndarray) -> np.ndarray:
        """Optimized matrix multiplication pattern"""
        return np.matmul(A, B)

    def _pattern_fft(self, signal: np.ndarray) -> np.ndarray:
        """Fast Fourier Transform pattern"""
        return np.fft.fft(signal)

    def _pattern_convolution(self, data: np.ndarray, kernel: np.ndarray) -> np.ndarray:
        """Convolution pattern"""
        from scipy import signal
        return signal.convolve(data, kernel, mode='same')

    def _pattern_graph_traversal(self, adjacency: np.ndarray, start: int) -> List[int]:
        """Graph traversal pattern (BFS)"""
        n = adjacency.shape[0]
        visited = np.zeros(n, dtype=bool)
        queue = [start]
        path = []

        while queue:
            node = queue.pop(0)
            if not visited[node]:
                visited[node] = True
                path.append(node)
                neighbors = np.where(adjacency[node] > 0)[0]
                queue.extend(neighbors)

        return path

    def _pattern_optimization(self, func, x0: np.ndarray) -> np.ndarray:
        """Optimization pattern (gradient descent)"""
        from scipy import optimize
        result = optimize.minimize(func, x0, method='BFGS')
        return result.x

    def match_pattern(self, operation: str, input_data: Any) -> Optional[str]:
        """Match input to known pattern"""
        # Simple pattern matching based on operation name
        for pattern_name in self.patterns:
            if pattern_name in operation.lower():
                return pattern_name
        return None

    def execute_pattern(self, pattern_name: str, *args, **kwargs) -> Any:
        """Execute a known pattern"""
        if pattern_name not in self.patterns:
            raise ValueError(f"Unknown pattern: {pattern_name}")

        return self.patterns[pattern_name](*args, **kwargs)
