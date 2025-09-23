"""
Workflow Engine Test Suite
Tests workflow orchestration, task scheduling, and execution
"""

from libraries.workflow_engine import (
    WorkflowEngine,
    Task,
    TaskHandler,
    TaskResult,
    TaskStatus,
    WorkflowStatus,
    PythonFunctionHandler,
)
import asyncio
from datetime import datetime
import sys
from pathlib import Path

# Add shared libraries to path
sys.path.append(str(Path(__file__).parent.parent))


# Test task handlers
class TestTaskHandler(TaskHandler):
    """Simple test task handler"""

    async def execute(self, task: Task) -> TaskResult:
        """Execute test task"""
        start_time = datetime.now()

        # Simulate work
        duration = task.params.get("duration", 0.1)
        await asyncio.sleep(duration)

        # Simulate failure if requested
        if task.params.get("should_fail", False):
            raise Exception(f"Task {task.name} intentionally failed")

        result = {
            "message": f"Task {task.name} completed successfully",
            "params": task.params,
        }

        return TaskResult(
            task_id=task.id,
            status=TaskStatus.COMPLETED,
            result=result,
            execution_time=duration,
            start_time=start_time,
            end_time=datetime.now(),
        )


async def test_basic_workflow():
    """Test basic workflow creation and execution"""
    print("Testing basic workflow...")

    engine = WorkflowEngine(max_concurrent_tasks=2)
    test_handler = TestTaskHandler()
    engine.register_handler("test", test_handler)

    # Create workflow
    workflow = engine.create_workflow("Basic Test Workflow", "Simple test workflow")

    # Add tasks
    ___task1 = engine.add_task_to_workflow(
        workflow.id, "Task 1", "test", {"duration": 0.2, "data": "first task"}
    )

    ___task2 = engine.add_task_to_workflow(
        workflow.id, "Task 2", "test", {"duration": 0.1, "data": "second task"}
    )

    # Execute workflow
    success = await engine.execute_workflow(workflow.id)

    if success and workflow.status == WorkflowStatus.COMPLETED:
        print("PASS: Basic workflow executed successfully")
        return True
    else:
        print(f"FAIL: Workflow failed - status: {workflow.status}")
        return False


async def test_dependency_workflow():
    """Test workflow with task dependencies"""
    print("Testing workflow with dependencies...")

    engine = WorkflowEngine()
    test_handler = TestTaskHandler()
    engine.register_handler("test", test_handler)

    # Create workflow
    workflow = engine.create_workflow("Dependency Test", "Test task dependencies")

    # Add tasks with dependencies
    task1 = engine.add_task_to_workflow(
        workflow.id,
        "Independent Task",
        "test",
        {"duration": 0.1, "data": "independent"},
    )

    task2 = engine.add_task_to_workflow(
        workflow.id,
        "Dependent Task",
        "test",
        {"duration": 0.1, "data": "dependent"},
        dependencies=[task1.id],
    )

    task3 = engine.add_task_to_workflow(
        workflow.id,
        "Final Task",
        "test",
        {"duration": 0.1, "data": "final"},
        dependencies=[task2.id],
    )

    # Execute workflow
    datetime.now()
    success = await engine.execute_workflow(workflow.id)
    datetime.now()

    if success:
        # Verify execution order
        if task1.completed_at < task2.completed_at < task3.completed_at:
            print("PASS: Dependencies respected")
            return True
        else:
            print("FAIL: Dependencies not respected")
            return False
    else:
        print("FAIL: Dependency workflow failed")
        return False


async def test_parallel_execution():
    """Test parallel task execution"""
    print("Testing parallel execution...")

    engine = WorkflowEngine(max_concurrent_tasks=3)
    test_handler = TestTaskHandler()
    engine.register_handler("test", test_handler)

    # Create workflow with parallel tasks
    workflow = engine.create_workflow("Parallel Test", "Test parallel execution")

    task_duration = 0.2
    parallel_tasks = []

    for i in range(3):
        task = engine.add_task_to_workflow(
            workflow.id,
            f"Parallel Task {i + 1}",
            "test",
            {"duration": task_duration, "data": f"parallel_{i}"},
        )
        parallel_tasks.append(task)

    # Execute workflow and measure time
    start_time = datetime.now()
    success = await engine.execute_workflow(workflow.id)
    end_time = datetime.now()

    total_time = (end_time - start_time).total_seconds()

    if success:
        # Should complete in roughly task_duration time (parallel) not 3*task_duration (sequential)
        if total_time < (task_duration * 2):  # Allow some overhead
            print(f"PASS: Parallel execution completed in {total_time:.2f}s")
            return True
        else:
            print(f"FAIL: Execution took too long: {total_time:.2f}s")
            return False
    else:
        print("FAIL: Parallel workflow failed")
        return False


async def test_error_handling():
    """Test error handling and retries"""
    print("Testing error handling...")

    engine = WorkflowEngine()
    test_handler = TestTaskHandler()
    engine.register_handler("test", test_handler)

    # Create workflow with failing task
    workflow = engine.create_workflow("Error Test", "Test error handling")

    ___success_task = engine.add_task_to_workflow(
        workflow.id, "Success Task", "test", {"duration": 0.1, "data": "success"}
    )

    fail_task = engine.add_task_to_workflow(
        workflow.id,
        "Fail Task",
        "test",
        {"should_fail": True, "duration": 0.1},
        max_retries=2,
    )

    # Execute workflow
    success = await engine.execute_workflow(workflow.id)

    if not success and workflow.status == WorkflowStatus.FAILED:
        if fail_task.retry_count == 2:  # Should have retried max_retries times
            print("PASS: Error handling and retries working")
            return True
        else:
            print(f"FAIL: Unexpected retry count: {fail_task.retry_count}")
            return False
    else:
        print("FAIL: Expected workflow to fail")
        return False


async def test_python_function_handler():
    """Test Python function handler"""
    print("Testing Python function handler...")

    engine = WorkflowEngine()

    # Define test functions
    def sync_function(x, y):
        return x + y

    async def async_function(message):
        await asyncio.sleep(0.1)
        return f"Processed: {message}"

    # Register handlers
    sync_handler = PythonFunctionHandler(sync_function)
    async_handler = PythonFunctionHandler(async_function)

    engine.register_handler("sync_math", sync_handler)
    engine.register_handler("async_process", async_handler)

    # Create workflow
    workflow = engine.create_workflow("Python Function Test")

    task1 = engine.add_task_to_workflow(
        workflow.id, "Math Task", "sync_math", {"x": 5, "y": 3}
    )

    task2 = engine.add_task_to_workflow(
        workflow.id, "Async Task", "async_process", {"message": "Hello World"}
    )

    # Execute workflow
    success = await engine.execute_workflow(workflow.id)

    if success:
        # Check results
        math_result = task1.result.result if task1.result else None
        async_result = task2.result.result if task2.result else None

        if math_result == 8 and async_result == "Processed: Hello World":
            print("PASS: Python function handlers working")
            return True
        else:
            print(
                f"FAIL: Unexpected results - math: {math_result}, async: {async_result}"
            )
            return False
    else:
        print("FAIL: Python function workflow failed")
        return False


async def test_workflow_statistics():
    """Test workflow statistics and monitoring"""
    print("Testing workflow statistics...")

    engine = WorkflowEngine()
    test_handler = TestTaskHandler()
    engine.register_handler("test", test_handler)

    # Execute a few workflows
    for i in range(3):
        workflow = engine.create_workflow(f"Stats Test {i + 1}")

        engine.add_task_to_workflow(
            workflow.id, f"Task {i + 1}", "test", {"duration": 0.05}
        )

        await engine.execute_workflow(workflow.id)

    # Get statistics
    stats = engine.get_statistics()

    expected_values = {
        "workflows_completed": 3,
        "tasks_completed": 3,
        "workflows_failed": 0,
        "tasks_failed": 0,
    }

    all_correct = all(stats.get(key) == value for key, value in expected_values.items())

    if all_correct:
        print("PASS: Statistics tracking working")
        print(f"  Workflows completed: {stats['workflows_completed']}")
        print(f"  Tasks completed: {stats['tasks_completed']}")
        print(f"  Total execution time: {stats['total_execution_time']:.2f}s")
        return True
    else:
        print("FAIL: Incorrect statistics")
        print(f"  Expected: {expected_values}")
        print(f"  Actual: {stats}")
        return False


async def test_workflow_cancellation():
    """Test workflow cancellation"""
    print("Testing workflow cancellation...")

    engine = WorkflowEngine()
    test_handler = TestTaskHandler()
    engine.register_handler("test", test_handler)

    # Create long-running workflow
    workflow = engine.create_workflow("Cancellation Test")

    for i in range(3):
        engine.add_task_to_workflow(
            workflow.id, f"Long Task {i + 1}", "test", {"duration": 2.0}
        )  # Long duration

    # Start execution
    execution_task = asyncio.create_task(engine.execute_workflow(workflow.id))

    # Wait a bit then cancel
    await asyncio.sleep(0.2)
    cancelled = engine.cancel_workflow(workflow.id)

    # Wait for execution to complete
    await execution_task

    if cancelled and workflow.status == WorkflowStatus.CANCELLED:
        print("PASS: Workflow cancellation working")
        return True
    else:
        print("FAIL: Workflow cancellation failed")
        return False


async def run_all_tests():
    """Run all workflow engine tests"""
    print("=== Workflow Engine Test Suite ===")
    print(f"Started at: {datetime.now()}")
    print()

    tests = [
        test_basic_workflow,
        test_dependency_workflow,
        test_parallel_execution,
        test_error_handling,
        test_python_function_handler,
        test_workflow_statistics,
        test_workflow_cancellation,
    ]

    results = []

    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"FAIL: Test {test.__name__} crashed: {e}")
            results.append(False)
        print()

    # Summary
    passed = sum(results)
    total = len(results)

    print("=" * 50)
    print(f"Test Results: {passed}/{total} passed")

    if passed == total:
        print("SUCCESS: All workflow engine tests passed!")
    else:
        print(f"WARNING: {total - passed} test(s) failed")

    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(run_all_tests())
