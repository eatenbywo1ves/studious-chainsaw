#!/bin/bash
# Run all reactive programming tests

cd "$(dirname "$0")"

echo "Running marble diagram tests..."
pytest tests/ -v --tb=short

echo ""
echo "Running advanced operator demos..."
python patterns/advanced_operators.py

echo ""
echo "Running hot/cold observable demos..."
python patterns/hot_cold_observables.py
