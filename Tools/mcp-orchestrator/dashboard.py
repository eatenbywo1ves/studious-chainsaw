#!/usr/bin/env python3
"""
MCP Server Monitoring Dashboard

Web-based dashboard for monitoring MCP server status using Flask
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import threading
import time

# Add orchestrator to path
sys.path.insert(0, 'C:\\Users\\Corbin\\Tools\\mcp-orchestrator')
from mcp_orchestrator import MCPOrchestrator

app = Flask(__name__)
CORS(app)

# Global orchestrator instance
orchestrator = None


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/status')
def get_status():
    """Get current status of all servers"""
    if orchestrator:
        status = orchestrator.get_status()
        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'servers': status
        })
    return jsonify({'success': False, 'error': 'Orchestrator not initialized'})


@app.route('/api/server/<name>/start', methods=['POST'])
def start_server(name):
    """Start a specific server"""
    if orchestrator:
        success = orchestrator.start_server(name)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Orchestrator not initialized'})


@app.route('/api/server/<name>/stop', methods=['POST'])
def stop_server(name):
    """Stop a specific server"""
    if orchestrator:
        success = orchestrator.stop_server(name)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Orchestrator not initialized'})


@app.route('/api/server/<name>/restart', methods=['POST'])
def restart_server(name):
    """Restart a specific server"""
    if orchestrator:
        success = orchestrator.restart_server(name)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Orchestrator not initialized'})


@app.route('/api/logs')
def get_logs():
    """Get recent orchestrator logs"""
    log_file = Path('Tools/mcp-orchestrator/orchestrator.log')
    if log_file.exists():
        with open(log_file, 'r') as f:
            lines = f.readlines()[-100:]  # Last 100 lines
        return jsonify({'success': True, 'logs': lines})
    return jsonify({'success': False, 'error': 'Log file not found'})


def run_dashboard(host='127.0.0.1', port=5000):
    """Run the dashboard server"""
    global orchestrator

    # Initialize orchestrator
    os.chdir('C:\\Users\\Corbin')
    orchestrator = MCPOrchestrator()

    # Start orchestrator in background thread
    monitor_thread = threading.Thread(target=orchestrator.start_all, daemon=True)
    monitor_thread.start()

    # Run Flask app
    app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    run_dashboard()