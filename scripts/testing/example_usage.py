"""
Example usage of the Remote Work Logger utility
"""

from utillogging import RemoteWorkLogger, ActivityType
import time

def main():
    # Initialize the logger
    logger = RemoteWorkLogger(
        log_dir="./work_logs",  # Custom log directory
        console_output=True,     # Show logs in console
        file_output=True,        # Save logs to file
        auto_save=True          # Auto-save sessions
    )
    
    print("\n" + "="*60)
    print("REMOTE WORK LOGGER - EXAMPLE USAGE")
    print("="*60 + "\n")
    
    # Example 1: Start a work session
    print("1. Starting a new work session...")
    session_id = logger.start_session(
        project="Web Development",
        notes="Working on user authentication feature",
        tags=["backend", "security", "python"]
    )
    print(f"   Session ID: {session_id}\n")
    
    # Example 2: Log different activities
    print("2. Logging various activities...")
    
    # Coding activity
    logger.start_activity(
        ActivityType.CODING,
        "Implementing JWT authentication",
        tags=["auth", "jwt"]
    )
    print("   - Started coding activity")
    time.sleep(2)  # Simulate work
    logger.end_activity("Basic JWT implementation complete")
    
    # Research activity
    logger.start_activity(
        ActivityType.RESEARCH,
        "Researching OAuth2 best practices",
        tags=["oauth", "security"]
    )
    print("   - Started research activity")
    time.sleep(1)
    logger.end_activity()
    
    # Example 3: Take a break
    print("\n3. Taking a break...")
    logger.take_break("Lunch break", duration_minutes=30)
    time.sleep(1)  # Simulate break
    logger.end_break()
    print("   Break logged!\n")
    
    # Example 4: Log a milestone
    print("4. Logging a milestone...")
    logger.log_milestone(
        "Completed authentication module",
        impact="Users can now securely login and register"
    )
    print("   Milestone recorded!\n")
    
    # Example 5: More activities
    print("5. More work activities...")
    logger.start_activity(
        ActivityType.TESTING,
        "Writing unit tests for auth module",
        tags=["testing", "pytest"]
    )
    time.sleep(1)
    logger.end_activity()
    
    logger.start_activity(
        ActivityType.DOCUMENTATION,
        "Updating API documentation",
        tags=["docs", "api"]
    )
    time.sleep(1)
    logger.end_activity("Added authentication endpoints to docs")
    
    # Example 6: End the session
    print("\n6. Ending the work session...")
    summary = logger.end_session("Authentication feature complete and tested")
    
    print("\n" + "="*60)
    print("SESSION SUMMARY")
    print("="*60)
    print(f"Total Duration: {summary['total_duration']}")
    print(f"Active Time: {summary['active_time']}")
    print(f"Break Time: {summary['break_time']}")
    print(f"Activities Completed: {summary['num_activities']}")
    print("\nActivity Breakdown:")
    for activity_type, duration in summary['activity_breakdown'].items():
        print(f"  - {activity_type}: {duration}")
    
    # Example 7: Get daily summary
    print("\n" + "="*60)
    print("TODAY'S WORK SUMMARY")
    print("="*60)
    daily = logger.get_daily_summary()
    print(f"Total Sessions: {daily['total_sessions']}")
    print(f"Total Work Time: {daily['total_work_time']}")
    print(f"Total Activities: {daily['total_activities']}")
    
    # Example 8: Export logs
    print("\n7. Exporting logs...")
    import datetime
    today = datetime.date.today()
    
    # Export as JSON
    json_file = logger.export_logs(
        start_date=today,
        end_date=today,
        format="json",
        output_file="./work_logs/daily_export.json"
    )
    print(f"   Exported to JSON: {json_file}")
    
    # Export as Markdown
    md_file = logger.export_logs(
        start_date=today,
        end_date=today,
        format="markdown",
        output_file="./work_logs/daily_report.md"
    )
    print(f"   Exported to Markdown: {md_file}")
    
    print("\n" + "="*60)
    print("EXAMPLE COMPLETE!")
    print("="*60)
    print("\nCheck the following locations:")
    print(f"  - Log files: ./work_logs/")
    print(f"  - Database: ./work_logs/work_tracking.db")
    print(f"  - Exports: ./work_logs/daily_export.json and daily_report.md")

if __name__ == "__main__":
    main()