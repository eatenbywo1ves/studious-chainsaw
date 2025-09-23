"""
OLAP Engine and Data Warehousing

Enterprise-grade OLAP (Online Analytical Processing) engine with:
- Multi-dimensional data cubes
- Star and snowflake schema support
- Real-time data aggregation
- Drill-down and roll-up operations
- Multi-tenant data isolation
- In-memory and persistent storage
- Query optimization and caching
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import aioredis
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine


class DimensionType(Enum):
    TIME = "time"
    TENANT = "tenant"
    AGENT = "agent"
    USER = "user"
    RESOURCE = "resource"
    GEOGRAPHIC = "geographic"
    PRODUCT = "product"
    CUSTOM = "custom"


class AggregationType(Enum):
    SUM = "sum"
    COUNT = "count"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    STDDEV = "stddev"
    DISTINCT_COUNT = "distinct_count"
    PERCENTILE = "percentile"


class StorageMode(Enum):
    IN_MEMORY = "in_memory"
    PERSISTENT = "persistent"
    HYBRID = "hybrid"


@dataclass
class Dimension:
    """OLAP dimension definition"""

    name: str
    type: DimensionType
    levels: List[str]
    hierarchy: Optional[List[str]] = None
    attributes: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.hierarchy:
            self.hierarchy = self.levels.copy()


@dataclass
class Measure:
    """OLAP measure definition"""

    name: str
    aggregation_type: AggregationType
    source_column: str
    data_type: str = "float"
    format_string: str = "{:.2f}"

    def format_value(self, value: Any) -> str:
        """Format measure value for display"""
        try:
            if value is None:
                return "N/A"
            return self.format_string.format(value)
        except Exception:
            return str(value)


@dataclass
class CubeSchema:
    """OLAP cube schema definition"""

    name: str
    dimensions: List[Dimension]
    measures: List[Measure]
    fact_table: str
    storage_mode: StorageMode = StorageMode.HYBRID
    partition_dimension: Optional[str] = None
    retention_days: int = 365

    def get_dimension(self, name: str) -> Optional[Dimension]:
        """Get dimension by name"""
        return next((d for d in self.dimensions if d.name == name), None)

    def get_measure(self, name: str) -> Optional[Measure]:
        """Get measure by name"""
        return next((m for m in self.measures if m.name == name), None)


@dataclass
class CubeQuery:
    """OLAP cube query specification"""

    cube_name: str
    dimensions: List[str]
    measures: List[str]
    filters: Dict[str, Any] = field(default_factory=dict)
    drill_down: Optional[Dict[str, str]] = None
    roll_up: Optional[Dict[str, str]] = None
    top_n: Optional[int] = None
    tenant_id: Optional[str] = None

    def validate(self, schema: CubeSchema) -> List[str]:
        """Validate query against schema"""
        errors = []

        # Check dimensions
        schema_dims = {d.name for d in schema.dimensions}
        for dim in self.dimensions:
            if dim not in schema_dims:
                errors.append(f"Unknown dimension: {dim}")

        # Check measures
        schema_measures = {m.name for m in schema.measures}
        for measure in self.measures:
            if measure not in schema_measures:
                errors.append(f"Unknown measure: {measure}")

        return errors


class OLAPEngine:
    """High-performance OLAP engine with multi-dimensional analytics"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_engine = None
        self.redis_client: Optional[aioredis.Redis] = None

        self.cube_schemas: Dict[str, CubeSchema] = {}
        self.cube_data: Dict[str, pd.DataFrame] = {}  # In-memory cubes
        self.query_cache: Dict[str, Any] = {}

        self.metrics = {
            "queries_executed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_query_time_ms": 0,
            "active_cubes": 0,
        }

        self.logger = logging.getLogger(__name__)

    async def initialize(self):
        """Initialize OLAP engine"""
        try:
            # Initialize database connection
            db_url = self.config.get(
                "database_url", "postgresql+asyncpg://user:pass@localhost/olap"
            )
            self.db_engine = create_async_engine(db_url, echo=False)

            # Initialize Redis for caching
            redis_url = self.config.get("redis_url", "redis://localhost:6379")
            self.redis_client = aioredis.from_url(redis_url)

            # Create default cube schemas
            await self._create_default_schemas()

            self.logger.info("OLAP engine initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize OLAP engine: {e}")
            raise

    async def _create_default_schemas(self):
        """Create default OLAP cube schemas"""

        # Agent Performance Cube
        agent_cube = CubeSchema(
            name="agent_performance",
            dimensions=[
                Dimension(
                    "time",
                    DimensionType.TIME,
                    ["year", "quarter", "month", "week", "day", "hour"],
                ),
                Dimension("tenant", DimensionType.TENANT, ["tenant_id", "tenant_plan"]),
                Dimension(
                    "agent",
                    DimensionType.AGENT,
                    ["agent_id", "agent_type", "agent_version"],
                ),
                Dimension(
                    "geography",
                    DimensionType.GEOGRAPHIC,
                    ["continent", "country", "region", "city"],
                ),
            ],
            measures=[
                Measure("request_count", AggregationType.COUNT, "requests"),
                Measure("avg_response_time", AggregationType.AVG, "response_time_ms"),
                Measure("error_rate", AggregationType.AVG, "error_rate"),
                Measure("throughput", AggregationType.SUM, "requests_per_second"),
                Measure("cpu_usage", AggregationType.AVG, "cpu_percent"),
                Measure("memory_usage", AggregationType.AVG, "memory_mb"),
            ],
            fact_table="agent_performance_facts",
            storage_mode=StorageMode.HYBRID,
            partition_dimension="tenant",
        )

        await self.register_cube_schema(agent_cube)

        # User Activity Cube
        user_cube = CubeSchema(
            name="user_activity",
            dimensions=[
                Dimension(
                    "time",
                    DimensionType.TIME,
                    ["year", "quarter", "month", "week", "day", "hour"],
                ),
                Dimension("tenant", DimensionType.TENANT, ["tenant_id", "tenant_plan"]),
                Dimension(
                    "user",
                    DimensionType.USER,
                    ["user_id", "user_role", "user_department"],
                ),
                Dimension(
                    "resource",
                    DimensionType.RESOURCE,
                    ["resource_type", "resource_category"],
                ),
            ],
            measures=[
                Measure("session_count", AggregationType.COUNT, "sessions"),
                Measure("session_duration", AggregationType.AVG, "duration_minutes"),
                Measure("action_count", AggregationType.SUM, "actions"),
                Measure("unique_users", AggregationType.DISTINCT_COUNT, "user_id"),
                Measure("conversion_rate", AggregationType.AVG, "conversion_rate"),
            ],
            fact_table="user_activity_facts",
            storage_mode=StorageMode.PERSISTENT,
            partition_dimension="tenant",
        )

        await self.register_cube_schema(user_cube)

        # Financial Analytics Cube
        financial_cube = CubeSchema(
            name="financial_analytics",
            dimensions=[
                Dimension(
                    "time",
                    DimensionType.TIME,
                    ["year", "quarter", "month", "week", "day"],
                ),
                Dimension(
                    "tenant",
                    DimensionType.TENANT,
                    ["tenant_id", "tenant_plan", "billing_cycle"],
                ),
                Dimension(
                    "product",
                    DimensionType.PRODUCT,
                    ["product_id", "product_category", "pricing_tier"],
                ),
            ],
            measures=[
                Measure(
                    "revenue",
                    AggregationType.SUM,
                    "revenue_usd",
                    format_string="${:.2f}",
                ),
                Measure(
                    "cost", AggregationType.SUM, "cost_usd", format_string="${:.2f}"
                ),
                Measure(
                    "profit", AggregationType.SUM, "profit_usd", format_string="${:.2f}"
                ),
                Measure(
                    "margin_percent",
                    AggregationType.AVG,
                    "margin_percent",
                    format_string="{:.1f}%",
                ),
                Measure(
                    "customer_count", AggregationType.DISTINCT_COUNT, "customer_id"
                ),
                Measure(
                    "churn_rate",
                    AggregationType.AVG,
                    "churn_rate",
                    format_string="{:.2f}%",
                ),
            ],
            fact_table="financial_facts",
            storage_mode=StorageMode.PERSISTENT,
            partition_dimension="tenant",
        )

        await self.register_cube_schema(financial_cube)

    async def register_cube_schema(self, schema: CubeSchema):
        """Register a new cube schema"""
        self.cube_schemas[schema.name] = schema

        # Create fact table if it doesn't exist
        await self._create_fact_table(schema)

        # Initialize in-memory storage if needed
        if schema.storage_mode in [StorageMode.IN_MEMORY, StorageMode.HYBRID]:
            self.cube_data[schema.name] = pd.DataFrame()

        self.logger.info(f"Registered cube schema: {schema.name}")

    async def _create_fact_table(self, schema: CubeSchema):
        """Create fact table for cube schema"""
        try:
            async with self.db_engine.begin() as conn:
                # Generate CREATE TABLE SQL
                columns = []

                # Add dimension foreign keys
                for dim in schema.dimensions:
                    for level in dim.levels:
                        columns.append(f"{level} VARCHAR(255)")

                # Add measure columns
                for measure in schema.measures:
                    columns.append(f"{measure.source_column} FLOAT")

                # Add standard columns
                columns.extend(
                    [
                        "id SERIAL PRIMARY KEY",
                        "tenant_id VARCHAR(255) NOT NULL",
                        "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                        "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                    ]
                )

                create_sql = f"""
                CREATE TABLE IF NOT EXISTS {schema.fact_table} (
                    {', '.join(columns)}
                );

                CREATE INDEX IF NOT EXISTS idx_{schema.fact_table}_tenant
                ON {schema.fact_table}(tenant_id);

                CREATE INDEX IF NOT EXISTS idx_{schema.fact_table}_created
                ON {schema.fact_table}(created_at);
                """

                await conn.execute(create_sql)

        except Exception as e:
            self.logger.error(f"Failed to create fact table: {e}")

    async def load_cube_data(
        self,
        cube_name: str,
        data: List[Dict[str, Any]],
        tenant_id: Optional[str] = None,
    ):
        """Load data into OLAP cube"""
        if cube_name not in self.cube_schemas:
            raise ValueError(f"Unknown cube: {cube_name}")

        schema = self.cube_schemas[cube_name]

        # Convert to DataFrame
        df = pd.DataFrame(data)

        # Add tenant isolation
        if tenant_id:
            df["tenant_id"] = tenant_id

        # Store based on storage mode
        if schema.storage_mode == StorageMode.IN_MEMORY:
            await self._store_in_memory(cube_name, df)
        elif schema.storage_mode == StorageMode.PERSISTENT:
            await self._store_in_database(cube_name, df, schema)
        else:  # HYBRID
            await self._store_in_memory(cube_name, df)
            await self._store_in_database(cube_name, df, schema)

        self.metrics["active_cubes"] = len(self.cube_data)
        self.logger.info(f"Loaded {len(data)} records into cube: {cube_name}")

    async def _store_in_memory(self, cube_name: str, df: pd.DataFrame):
        """Store data in memory"""
        if cube_name not in self.cube_data:
            self.cube_data[cube_name] = df
        else:
            self.cube_data[cube_name] = pd.concat(
                [self.cube_data[cube_name], df], ignore_index=True
            )

    async def _store_in_database(
        self, cube_name: str, df: pd.DataFrame, schema: CubeSchema
    ):
        """Store data in database"""
        try:
            # Use pandas to_sql for bulk insert
            engine = create_engine(str(self.db_engine.url).replace("+asyncpg", ""))
            df.to_sql(schema.fact_table, engine, if_exists="append", index=False)

        except Exception as e:
            self.logger.error(f"Failed to store data in database: {e}")

    async def execute_query(self, query: CubeQuery) -> Dict[str, Any]:
        """Execute OLAP query"""
        start_time = datetime.utcnow()

        try:
            # Validate query
            schema = self.cube_schemas.get(query.cube_name)
            if not schema:
                raise ValueError(f"Unknown cube: {query.cube_name}")

            errors = query.validate(schema)
            if errors:
                raise ValueError(f"Query validation errors: {errors}")

            # Check cache
            cache_key = self._get_cache_key(query)
            cached_result = await self._get_from_cache(cache_key)
            if cached_result:
                self.metrics["cache_hits"] += 1
                return cached_result

            # Execute query
            if schema.storage_mode == StorageMode.IN_MEMORY:
                result = await self._execute_in_memory_query(query, schema)
            elif schema.storage_mode == StorageMode.PERSISTENT:
                result = await self._execute_database_query(query, schema)
            else:  # HYBRID - try memory first, fallback to database
                try:
                    result = await self._execute_in_memory_query(query, schema)
                except Exception:
                    result = await self._execute_database_query(query, schema)

            # Cache result
            await self._store_in_cache(cache_key, result)

            # Update metrics
            query_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self.metrics["queries_executed"] += 1
            self.metrics["cache_misses"] += 1
            self.metrics["avg_query_time_ms"] = (
                self.metrics["avg_query_time_ms"] + query_time
            ) / 2

            return result

        except Exception as e:
            self.logger.error(f"Query execution error: {e}")
            raise

    async def _execute_in_memory_query(
        self, query: CubeQuery, schema: CubeSchema
    ) -> Dict[str, Any]:
        """Execute query against in-memory data"""
        if query.cube_name not in self.cube_data:
            raise ValueError(f"No in-memory data for cube: {query.cube_name}")

        df = self.cube_data[query.cube_name].copy()

        # Apply tenant filter
        if query.tenant_id:
            df = df[df["tenant_id"] == query.tenant_id]

        # Apply filters
        for column, value in query.filters.items():
            if isinstance(value, list):
                df = df[df[column].isin(value)]
            else:
                df = df[df[column] == value]

        # Group by dimensions and aggregate measures
        if query.dimensions:
            grouped = df.groupby(query.dimensions)

            aggregations = {}
            for measure_name in query.measures:
                measure = schema.get_measure(measure_name)
                if measure:
                    if measure.aggregation_type == AggregationType.COUNT:
                        aggregations[measure_name] = (measure.source_column, "count")
                    elif measure.aggregation_type == AggregationType.SUM:
                        aggregations[measure_name] = (measure.source_column, "sum")
                    elif measure.aggregation_type == AggregationType.AVG:
                        aggregations[measure_name] = (measure.source_column, "mean")
                    elif measure.aggregation_type == AggregationType.MIN:
                        aggregations[measure_name] = (measure.source_column, "min")
                    elif measure.aggregation_type == AggregationType.MAX:
                        aggregations[measure_name] = (measure.source_column, "max")
                    elif measure.aggregation_type == AggregationType.STDDEV:
                        aggregations[measure_name] = (measure.source_column, "std")
                    elif measure.aggregation_type == AggregationType.DISTINCT_COUNT:
                        aggregations[measure_name] = (measure.source_column, "nunique")

            result_df = grouped.agg(**aggregations).reset_index()
        else:
            # No grouping, just aggregate everything
            result_df = df[query.measures].agg("sum").to_frame().T

        # Apply top-N limit
        if query.top_n:
            result_df = result_df.head(query.top_n)

        # Convert to result format
        return {
            "cube_name": query.cube_name,
            "dimensions": query.dimensions,
            "measures": query.measures,
            "data": result_df.to_dict("records"),
            "row_count": len(result_df),
            "execution_time_ms": 0,  # Will be set by caller
        }

    async def _execute_database_query(
        self, query: CubeQuery, schema: CubeSchema
    ) -> Dict[str, Any]:
        """Execute query against database"""
        # Build SQL query
        select_columns = query.dimensions.copy()

        aggregations = []
        for measure_name in query.measures:
            measure = schema.get_measure(measure_name)
            if measure:
                if measure.aggregation_type == AggregationType.COUNT:
                    aggregations.append(
                        f"COUNT({measure.source_column}) AS {measure_name}"
                    )
                elif measure.aggregation_type == AggregationType.SUM:
                    aggregations.append(
                        f"SUM({measure.source_column}) AS {measure_name}"
                    )
                elif measure.aggregation_type == AggregationType.AVG:
                    aggregations.append(
                        f"AVG({measure.source_column}) AS {measure_name}"
                    )
                elif measure.aggregation_type == AggregationType.MIN:
                    aggregations.append(
                        f"MIN({measure.source_column}) AS {measure_name}"
                    )
                elif measure.aggregation_type == AggregationType.MAX:
                    aggregations.append(
                        f"MAX({measure.source_column}) AS {measure_name}"
                    )
                elif measure.aggregation_type == AggregationType.STDDEV:
                    aggregations.append(
                        f"STDDEV({measure.source_column}) AS {measure_name}"
                    )
                elif measure.aggregation_type == AggregationType.DISTINCT_COUNT:
                    aggregations.append(
                        f"COUNT(DISTINCT {measure.source_column}) AS {measure_name}"
                    )

        select_clause = ", ".join(select_columns + aggregations)

        where_conditions = []
        if query.tenant_id:
            where_conditions.append(f"tenant_id = '{query.tenant_id}'")

        for column, value in query.filters.items():
            if isinstance(value, list):
                values = "', '".join(str(v) for v in value)
                where_conditions.append(f"{column} IN ('{values}')")
            else:
                where_conditions.append(f"{column} = '{value}'")

        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
        group_clause = ", ".join(query.dimensions) if query.dimensions else ""
        limit_clause = f"LIMIT {query.top_n}" if query.top_n else ""

        sql = f"""
        SELECT {select_clause}
        FROM {schema.fact_table}
        WHERE {where_clause}
        {f'GROUP BY {group_clause}' if group_clause else ''}
        {limit_clause}
        """

        # Execute query
        async with self.db_engine.begin() as conn:
            result = await conn.execute(sql)
            rows = result.fetchall()
            columns = result.keys()

        # Convert to result format
        data = [dict(zip(columns, row)) for row in rows]

        return {
            "cube_name": query.cube_name,
            "dimensions": query.dimensions,
            "measures": query.measures,
            "data": data,
            "row_count": len(data),
            "sql": sql,
        }

    def _get_cache_key(self, query: CubeQuery) -> str:
        """Generate cache key for query"""
        query_hash = hash(
            json.dumps(
                {
                    "cube_name": query.cube_name,
                    "dimensions": sorted(query.dimensions),
                    "measures": sorted(query.measures),
                    "filters": query.filters,
                    "tenant_id": query.tenant_id,
                    "top_n": query.top_n,
                },
                sort_keys=True,
            )
        )

        return f"olap_query:{query_hash}"

    async def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get result from cache"""
        try:
            cached_data = await self.redis_client.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
        except Exception:
            pass
        return None

    async def _store_in_cache(
        self, cache_key: str, result: Dict[str, Any], ttl: int = 3600
    ):
        """Store result in cache"""
        try:
            await self.redis_client.setex(
                cache_key, ttl, json.dumps(result, default=str)
            )
        except Exception:
            pass

    async def drill_down(
        self, query: CubeQuery, dimension: str, level: str
    ) -> Dict[str, Any]:
        """Drill down to more detailed level"""
        schema = self.cube_schemas.get(query.cube_name)
        if not schema:
            raise ValueError(f"Unknown cube: {query.cube_name}")

        dim = schema.get_dimension(dimension)
        if not dim:
            raise ValueError(f"Unknown dimension: {dimension}")

        if level not in dim.levels:
            raise ValueError(f"Invalid level {level} for dimension {dimension}")

        # Create new query with additional dimension level
        drill_query = CubeQuery(
            cube_name=query.cube_name,
            dimensions=query.dimensions + [level],
            measures=query.measures,
            filters=query.filters,
            tenant_id=query.tenant_id,
            top_n=query.top_n,
        )

        return await self.execute_query(drill_query)

    async def roll_up(self, query: CubeQuery, dimension: str) -> Dict[str, Any]:
        """Roll up to higher level"""
        # Remove the most detailed level of the dimension
        new_dimensions = query.dimensions.copy()

        # Find and remove the dimension to roll up
        if dimension in new_dimensions:
            new_dimensions.remove(dimension)

        roll_query = CubeQuery(
            cube_name=query.cube_name,
            dimensions=new_dimensions,
            measures=query.measures,
            filters=query.filters,
            tenant_id=query.tenant_id,
            top_n=query.top_n,
        )

        return await self.execute_query(roll_query)

    async def get_cube_metadata(self, cube_name: str) -> Dict[str, Any]:
        """Get cube schema metadata"""
        schema = self.cube_schemas.get(cube_name)
        if not schema:
            raise ValueError(f"Unknown cube: {cube_name}")

        return {
            "name": schema.name,
            "dimensions": [
                {
                    "name": dim.name,
                    "type": dim.type.value,
                    "levels": dim.levels,
                    "hierarchy": dim.hierarchy,
                }
                for dim in schema.dimensions
            ],
            "measures": [
                {
                    "name": measure.name,
                    "aggregation_type": measure.aggregation_type.value,
                    "data_type": measure.data_type,
                }
                for measure in schema.measures
            ],
            "storage_mode": schema.storage_mode.value,
            "fact_table": schema.fact_table,
        }

    async def get_metrics(self) -> Dict[str, Any]:
        """Get engine metrics"""
        return self.metrics.copy()

    async def clear_cache(self, cube_name: Optional[str] = None):
        """Clear query cache"""
        if cube_name:
            pattern = f"olap_query:*{cube_name}*"
        else:
            pattern = "olap_query:*"

        try:
            keys = await self.redis_client.keys(pattern)
            if keys:
                await self.redis_client.delete(*keys)
            self.logger.info(f"Cleared {len(keys)} cache entries")
        except Exception as e:
            self.logger.error(f"Failed to clear cache: {e}")

    async def shutdown(self):
        """Shutdown OLAP engine"""
        try:
            if self.db_engine:
                await self.db_engine.dispose()

            if self.redis_client:
                await self.redis_client.close()

            self.logger.info("OLAP engine shutdown complete")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
