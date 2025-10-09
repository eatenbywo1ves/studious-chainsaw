#!/usr/bin/env python3
"""Quick test with 100 users to verify setup"""

import asyncio
import aiohttp
import time
import statistics

BASE_URL = "http://localhost:8002"


async def make_request(session):
    start = time.time()
    try:
        async with session.post(
            f"{BASE_URL}/auth/login",
            json={"email": "test@example.com", "password": "testpass"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            latency = time.time() - start
            return response.status == 200, latency
    except Exception:
        return False, time.time() - start


async def user(session, requests_per_user=10):
    results = []
    for _ in range(requests_per_user):
        success, latency = await make_request(session)
        results.append((success, latency))
        await asyncio.sleep(0.1)
    return results


async def main():
    users = 100
    requests_per_user = 10

    print("=" * 60)
    print(f"QUICK TEST - {users} users, {requests_per_user} requests each")
    print("=" * 60)

    connector = aiohttp.TCPConnector(limit=users)
    start_time = time.time()

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [user(session, requests_per_user) for _ in range(users)]
        all_results = await asyncio.gather(*tasks)

    duration = time.time() - start_time

    # Flatten results
    flat_results = [r for user_results in all_results for r in user_results]
    successful = sum(1 for success, _ in flat_results if success)
    total = len(flat_results)
    latencies = [lat * 1000 for success, lat in flat_results if success]

    if latencies:
        sorted_lat = sorted(latencies)
        p95 = sorted_lat[int(len(sorted_lat) * 0.95)]
        avg_lat = statistics.mean(latencies)
    else:
        p95 = avg_lat = 0

    print("\nResults:")
    print(f"  Total Requests:  {total}")
    print(f"  Successful:      {successful}")
    print(f"  Failed:          {total - successful}")
    print(f"  Success Rate:    {successful / total * 100:.2f}%")
    print(f"  Duration:        {duration:.2f}s")
    print(f"  Throughput:      {total / duration:.2f} req/s")
    print(f"  Avg Latency:     {avg_lat:.2f}ms")
    print(f"  p95 Latency:     {p95:.2f}ms")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
