// WebSocket connection
let ws = null;
let reconnectInterval = null;
let currentProfile = 'default';
let stats = {
    totalEvents: 0,
    successfulEvents: 0,
    failedEvents: 0,
    activeWorkflows: new Map(),
    webhooks: new Map()
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    connectWebSocket();
    initializeVisualizer();
});

function connectWebSocket() {
    const wsUrl = `ws://localhost:3001`;
    
    try {
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            console.log('WebSocket connected');
            updateConnectionStatus(true);
            clearInterval(reconnectInterval);
        };
        
        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleWebSocketMessage(data);
            } catch (error) {
                console.error('Error parsing message:', error);
            }
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateConnectionStatus(false);
        };
        
        ws.onclose = () => {
            console.log('WebSocket disconnected');
            updateConnectionStatus(false);
            attemptReconnect();
        };
    } catch (error) {
        console.error('Failed to connect:', error);
        updateConnectionStatus(false);
        attemptReconnect();
    }
}

function attemptReconnect() {
    if (!reconnectInterval) {
        reconnectInterval = setInterval(() => {
            console.log('Attempting to reconnect...');
            connectWebSocket();
        }, 5000);
    }
}

function updateConnectionStatus(connected) {
    const statusDot = document.getElementById('wsStatus');
    const statusText = document.getElementById('connectionStatus');
    
    if (connected) {
        statusDot.className = 'status-dot connected';
        statusText.textContent = 'Connected';
    } else {
        statusDot.className = 'status-dot disconnected';
        statusText.textContent = 'Disconnected';
    }
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'initial_state':
            initializeState(data);
            break;
        case 'webhook_event':
            handleWebhookEvent(data);
            break;
        case 'workflow_step':
            handleWorkflowStep(data);
            break;
        default:
            console.log('Unknown message type:', data.type);
    }
}

function initializeState(data) {
    // Initialize webhooks
    if (data.webhooks) {
        data.webhooks.forEach(([id, webhook]) => {
            stats.webhooks.set(id, webhook);
        });
        updateWebhookList();
    }
    
    // Initialize workflows
    if (data.workflows) {
        data.workflows.forEach(([id, workflow]) => {
            stats.activeWorkflows.set(id, workflow);
        });
        updateWorkflowList();
    }
    
    updateStats();
}

function handleWebhookEvent(data) {
    stats.totalEvents++;
    
    // Add to event log
    addEventToLog({
        type: 'webhook',
        endpoint: data.endpoint.name,
        timestamp: new Date().toLocaleTimeString(),
        status: determineEventStatus(data.event)
    });
    
    // Trigger visual feedback
    triggerVisualFeedback(data.endpoint.audioProfile);
    
    // Update stats
    if (determineEventStatus(data.event) === 'success') {
        stats.successfulEvents++;
    } else if (determineEventStatus(data.event) === 'error') {
        stats.failedEvents++;
    }
    
    updateStats();
    showNotification(`Webhook received: ${data.endpoint.name}`);
}

function handleWorkflowStep(data) {
    const workflow = stats.activeWorkflows.get(data.workflowId);
    if (!workflow) return;
    
    // Update workflow state
    const step = workflow.steps.find(s => s.name === data.stepName);
    if (step) {
        step.status = data.status;
    }
    
    // Update UI
    updateWorkflowProgress(data.workflowId);
    
    // Add to event log
    addEventToLog({
        type: 'workflow',
        workflow: workflow.name,
        step: data.stepName,
        status: data.status,
        timestamp: new Date().toLocaleTimeString()
    });
    
    // Trigger visual feedback
    triggerVisualFeedback('workflow');
}

function registerWebhook() {
    const name = prompt('Enter webhook name:');
    if (!name) return;
    
    const profiles = ['default', 'workflow', 'alert', 'development', 'monitoring', 'communication'];
    const profile = prompt(`Enter audio profile (${profiles.join(', ')}):`, 'default');
    
    fetch('http://localhost:3000/webhook/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: name,
            description: `Webhook for ${name}`,
            audioProfile: profile || 'default'
        })
    })
    .then(response => response.json())
    .then(data => {
        showNotification(`Webhook registered: ${data.url}`);
        
        // Create a display element for the webhook URL
        const webhookItem = document.createElement('div');
        webhookItem.className = 'webhook-item';
        webhookItem.innerHTML = `
            <div>
                <strong>${name}</strong>
                <div class="webhook-endpoint">${data.url}</div>
            </div>
            <button onclick="testWebhook('${data.endpointId}')">Test</button>
        `;
        
        document.getElementById('webhookList').appendChild(webhookItem);
        stats.webhooks.set(data.endpointId, { name, url: data.url });
        updateStats();
    })
    .catch(error => {
        console.error('Error registering webhook:', error);
        showNotification('Failed to register webhook', 'error');
    });
}

function startWorkflow() {
    const name = prompt('Enter workflow name:');
    if (!name) return;
    
    const stepsInput = prompt('Enter workflow steps (comma-separated):', 'Initialize,Process,Validate,Complete');
    const steps = stepsInput ? stepsInput.split(',').map(s => s.trim()) : [];
    
    fetch('http://localhost:3000/workflow/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: name,
            steps: steps,
            audioProfile: 'workflow'
        })
    })
    .then(response => response.json())
    .then(data => {
        showNotification(`Workflow started: ${name}`);
        stats.activeWorkflows.set(data.workflowId, data.workflow);
        updateWorkflowList();
        updateStats();
    })
    .catch(error => {
        console.error('Error starting workflow:', error);
        showNotification('Failed to start workflow', 'error');
    });
}

function updateWorkflowList() {
    const container = document.getElementById('workflowList');
    container.innerHTML = '';
    
    stats.activeWorkflows.forEach((workflow, id) => {
        const item = document.createElement('div');
        item.className = 'workflow-item';
        item.innerHTML = `
            <div>
                <strong>${workflow.name}</strong>
                <div class="workflow-progress">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${calculateProgress(workflow)}%"></div>
                    </div>
                    <div class="step-indicators">
                        ${workflow.steps.map((step, i) => `
                            <div class="step-dot ${step.status}" title="${step.name || step}">
                                ${i + 1}
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
            <button onclick="simulateWorkflowStep('${id}')">Next Step</button>
        `;
        container.appendChild(item);
    });
}

function updateWebhookList() {
    const container = document.getElementById('webhookList');
    container.innerHTML = '';
    
    stats.webhooks.forEach((webhook, id) => {
        const item = document.createElement('div');
        item.className = 'webhook-item';
        item.innerHTML = `
            <div>
                <strong>${webhook.name}</strong>
                <div class="webhook-endpoint">
                    ${webhook.url || `http://localhost:3000/webhook/${id}`}
                </div>
            </div>
            <button onclick="testWebhook('${id}')">Test</button>
        `;
        container.appendChild(item);
    });
}

function calculateProgress(workflow) {
    if (!workflow.steps || workflow.steps.length === 0) return 0;
    
    const completedSteps = workflow.steps.filter(s => 
        (typeof s === 'object' && s.status === 'completed') || s === 'completed'
    ).length;
    
    return (completedSteps / workflow.steps.length) * 100;
}

function updateWorkflowProgress(workflowId) {
    const workflow = stats.activeWorkflows.get(workflowId);
    if (!workflow) return;
    
    updateWorkflowList();
}

function testWebhook(endpointId) {
    fetch(`http://localhost:3000/webhook/${endpointId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            type: 'test',
            timestamp: new Date().toISOString(),
            data: { message: 'Test webhook event' }
        })
    })
    .then(response => response.json())
    .then(data => {
        showNotification('Test webhook sent successfully');
    })
    .catch(error => {
        console.error('Error testing webhook:', error);
        showNotification('Failed to send test webhook', 'error');
    });
}

function simulateWorkflowStep(workflowId) {
    const workflow = stats.activeWorkflows.get(workflowId);
    if (!workflow) return;
    
    // Find next pending step
    const nextStep = workflow.steps.find(s => 
        (typeof s === 'object' && s.status === 'pending') || 
        (typeof s === 'string')
    );
    
    if (!nextStep) {
        showNotification('Workflow already completed');
        return;
    }
    
    const stepName = typeof nextStep === 'object' ? nextStep.name : nextStep;
    
    fetch(`http://localhost:3000/workflow/${workflowId}/step`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            stepName: stepName,
            status: 'completed',
            data: { simulatedAt: new Date().toISOString() }
        })
    })
    .then(response => response.json())
    .then(data => {
        showNotification(`Step completed: ${stepName}`);
    })
    .catch(error => {
        console.error('Error updating workflow step:', error);
        showNotification('Failed to update workflow step', 'error');
    });
}

function testAudio() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'test_audio',
            soundType: 'test',
            profile: currentProfile
        }));
        triggerVisualFeedback(currentProfile);
        showNotification('Testing audio with ' + currentProfile + ' profile');
    } else {
        showNotification('WebSocket not connected', 'error');
    }
}

function toggleMute() {
    const muted = document.getElementById('muteToggle').checked;
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'mute',
            muted: muted
        }));
    }
}

function updateVolume() {
    const volume = document.getElementById('volumeSlider').value / 100;
    // This would need backend support to actually change volume
    console.log('Volume set to:', volume);
}

function clearLogs() {
    document.getElementById('eventLog').innerHTML = '';
    showNotification('Event log cleared');
}

function addEventToLog(event) {
    const logContainer = document.getElementById('eventLog');
    const eventItem = document.createElement('div');
    eventItem.className = 'event-item';
    
    let icon = '📨';
    if (event.type === 'workflow') {
        icon = event.status === 'completed' ? '✅' : 
               event.status === 'failed' ? '❌' : '⏳';
    } else if (event.status === 'error') {
        icon = '⚠️';
    }
    
    eventItem.innerHTML = `
        <span>${icon} ${event.timestamp}</span>
        <span>${event.type === 'workflow' ? 
            `${event.workflow} - ${event.step}: ${event.status}` : 
            `${event.endpoint || 'Unknown'} - ${event.status || 'received'}`}</span>
    `;
    
    // Add to top of log
    logContainer.insertBefore(eventItem, logContainer.firstChild);
    
    // Keep only last 50 events
    while (logContainer.children.length > 50) {
        logContainer.removeChild(logContainer.lastChild);
    }
}

function updateStats() {
    document.getElementById('totalEvents').textContent = stats.totalEvents;
    document.getElementById('webhookCount').textContent = stats.webhooks.size;
    document.getElementById('workflowCount').textContent = stats.activeWorkflows.size;
    
    // Calculate success rate
    const total = stats.successfulEvents + stats.failedEvents;
    const successRate = total > 0 ? 
        Math.round((stats.successfulEvents / total) * 100) : 0;
    document.getElementById('successRate').textContent = successRate + '%';
    
    // Count active steps
    let activeSteps = 0;
    stats.activeWorkflows.forEach(workflow => {
        if (workflow.steps) {
            activeSteps += workflow.steps.filter(s => 
                (typeof s === 'object' && s.status === 'in_progress')
            ).length;
        }
    });
    document.getElementById('activeSteps').textContent = activeSteps;
}

function determineEventStatus(event) {
    if (event.body) {
        if (event.body.status === 'success' || event.body.success === true) {
            return 'success';
        } else if (event.body.status === 'error' || event.body.error) {
            return 'error';
        }
    }
    return 'received';
}

function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    
    if (type === 'error') {
        notification.style.background = 'rgba(248, 113, 113, 0.9)';
    }
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

function selectProfile(profile) {
    currentProfile = profile;
    
    // Update UI
    document.querySelectorAll('.profile-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    showNotification(`Audio profile switched to: ${profile}`);
}

// Visual feedback for audio events
function initializeVisualizer() {
    const visualizer = document.getElementById('visualizer');
    
    // Create frequency bars
    for (let i = 0; i < 20; i++) {
        const bar = document.createElement('div');
        bar.className = 'freq-bar';
        bar.style.height = '10px';
        visualizer.appendChild(bar);
    }
}

function triggerVisualFeedback(profile) {
    const bars = document.querySelectorAll('.freq-bar');
    
    // Animate bars based on profile
    bars.forEach((bar, i) => {
        const delay = i * 20;
        const height = Math.random() * 80 + 20;
        
        setTimeout(() => {
            bar.style.height = height + 'px';
            setTimeout(() => {
                bar.style.height = '10px';
            }, 300);
        }, delay);
    });
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
        switch(e.key) {
            case 'w':
                e.preventDefault();
                registerWebhook();
                break;
            case 'f':
                e.preventDefault();
                startWorkflow();
                break;
            case 't':
                e.preventDefault();
                testAudio();
                break;
            case 'l':
                e.preventDefault();
                clearLogs();
                break;
        }
    }
});