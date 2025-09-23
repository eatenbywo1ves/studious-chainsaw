#!/usr/bin/env node
/**
 * Build Monitor Utility
 * Monitors build processes and reports metrics
 */

const fs = require('fs').promises;
const path = require('path');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');

class BuildMonitor extends EventEmitter {
    constructor(monitoringSystem = null) {
        super();
        this.monitoringSystem = monitoringSystem;
        this.activeBuild = null;
        this.buildHistory = [];
    }

    async runBuild(projectPath, buildCommand, options = {}) {
        const buildId = `build_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
        const startTime = Date.now();
        
        const buildInfo = {
            id: buildId,
            projectPath,
            command: buildCommand,
            startTime,
            projectName: options.projectName || path.basename(projectPath),
            buildType: options.buildType || 'default',
            status: 'running'
        };

        this.activeBuild = buildInfo;
        this.emit('build_started', buildInfo);

        console.log(`Starting build: ${buildInfo.projectName} (${buildInfo.buildType})`);
        console.log(`Command: ${buildCommand}`);
        console.log(`Project: ${projectPath}\n`);

        try {
            const result = await this.executeBuild(projectPath, buildCommand, buildInfo);
            
            buildInfo.endTime = Date.now();
            buildInfo.duration = buildInfo.endTime - buildInfo.startTime;
            buildInfo.status = result.success ? 'success' : 'failed';
            buildInfo.output = result.output;
            buildInfo.errors = result.errors;
            buildInfo.exitCode = result.exitCode;

            this.buildHistory.push(buildInfo);
            this.activeBuild = null;

            // Report to monitoring system
            if (this.monitoringSystem) {
                await this.monitoringSystem.trackBuild(
                    buildInfo.projectName,
                    buildInfo.buildType,
                    buildInfo.startTime,
                    buildInfo.status === 'success'
                );
            }

            this.emit('build_completed', buildInfo);
            this.displayBuildResult(buildInfo);

            return buildInfo;

        } catch (error) {
            buildInfo.endTime = Date.now();
            buildInfo.duration = buildInfo.endTime - buildInfo.startTime;
            buildInfo.status = 'error';
            buildInfo.error = error.message;

            this.buildHistory.push(buildInfo);
            this.activeBuild = null;

            this.emit('build_error', buildInfo);
            console.error(`Build failed with error: ${error.message}`);

            return buildInfo;
        }
    }

    async executeBuild(projectPath, command, buildInfo) {
        return new Promise((resolve) => {
            const [cmd, ...args] = command.split(' ');
            const child = spawn(cmd, args, {
                cwd: projectPath,
                stdio: ['pipe', 'pipe', 'pipe'],
                shell: true
            });

            let output = '';
            let errors = '';

            child.stdout.on('data', (data) => {
                const text = data.toString();
                output += text;
                process.stdout.write(text);
                this.emit('build_output', { buildId: buildInfo.id, text, type: 'stdout' });
            });

            child.stderr.on('data', (data) => {
                const text = data.toString();
                errors += text;
                process.stderr.write(text);
                this.emit('build_output', { buildId: buildInfo.id, text, type: 'stderr' });
            });

            child.on('close', (code) => {
                resolve({
                    success: code === 0,
                    exitCode: code,
                    output,
                    errors
                });
            });

            child.on('error', (error) => {
                resolve({
                    success: false,
                    exitCode: -1,
                    output,
                    errors: errors + error.message
                });
            });
        });
    }

    displayBuildResult(buildInfo) {
        const status = buildInfo.status === 'success' ? '✅ SUCCESS' : '❌ FAILED';
        const duration = `${buildInfo.duration}ms`;
        
        console.log('\n' + '='.repeat(60));
        console.log(`Build Result: ${status}`);
        console.log(`Project: ${buildInfo.projectName}`);
        console.log(`Duration: ${duration}`);
        console.log(`Exit Code: ${buildInfo.exitCode}`);
        
        if (buildInfo.status !== 'success' && buildInfo.errors) {
            console.log('\nErrors:');
            console.log(buildInfo.errors);
        }
        
        console.log('='.repeat(60) + '\n');
    }

    async runTests(projectPath, testCommand, options = {}) {
        const testId = `test_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
        const startTime = Date.now();
        
        const testInfo = {
            id: testId,
            projectPath,
            command: testCommand,
            startTime,
            projectName: options.projectName || path.basename(projectPath),
            testSuite: options.testSuite || 'default',
            status: 'running'
        };

        this.emit('test_started', testInfo);

        console.log(`Starting tests: ${testInfo.projectName} (${testInfo.testSuite})`);
        console.log(`Command: ${testCommand}`);
        console.log(`Project: ${projectPath}\n`);

        try {
            const result = await this.executeBuild(projectPath, testCommand, testInfo);
            
            testInfo.endTime = Date.now();
            testInfo.duration = testInfo.endTime - testInfo.startTime;
            testInfo.status = result.success ? 'success' : 'failed';
            testInfo.output = result.output;
            testInfo.errors = result.errors;
            testInfo.exitCode = result.exitCode;

            // Parse test results
            const testResults = this.parseTestResults(result.output);
            testInfo.passed = testResults.passed;
            testInfo.failed = testResults.failed;
            testInfo.skipped = testResults.skipped;

            // Report to monitoring system
            if (this.monitoringSystem) {
                await this.monitoringSystem.trackTest(
                    testInfo.projectName,
                    testInfo.testSuite,
                    testInfo.startTime,
                    testInfo.passed,
                    testInfo.failed,
                    testInfo.skipped
                );
            }

            this.emit('test_completed', testInfo);
            this.displayTestResult(testInfo);

            return testInfo;

        } catch (error) {
            testInfo.endTime = Date.now();
            testInfo.duration = testInfo.endTime - testInfo.startTime;
            testInfo.status = 'error';
            testInfo.error = error.message;

            this.emit('test_error', testInfo);
            console.error(`Tests failed with error: ${error.message}`);

            return testInfo;
        }
    }

    parseTestResults(output) {
        // Basic test result parsing (adapt for specific test frameworks)
        const results = { passed: 0, failed: 0, skipped: 0 };
        
        // Jest pattern
        let match = output.match(/Tests:\s+(\d+)\s+failed,\s+(\d+)\s+passed/);
        if (match) {
            results.failed = parseInt(match[1]);
            results.passed = parseInt(match[2]);
            return results;
        }
        
        // Mocha pattern
        match = output.match(/(\d+)\s+passing/);
        if (match) {
            results.passed = parseInt(match[1]);
        }
        
        match = output.match(/(\d+)\s+failing/);
        if (match) {
            results.failed = parseInt(match[1]);
        }
        
        // PyTest pattern
        match = output.match(/(\d+)\s+passed/);
        if (match) {
            results.passed = parseInt(match[1]);
        }
        
        match = output.match(/(\d+)\s+failed/);
        if (match) {
            results.failed = parseInt(match[1]);
        }
        
        match = output.match(/(\d+)\s+skipped/);
        if (match) {
            results.skipped = parseInt(match[1]);
        }
        
        return results;
    }

    displayTestResult(testInfo) {
        const status = testInfo.status === 'success' ? '✅ PASSED' : '❌ FAILED';
        const duration = `${testInfo.duration}ms`;
        
        console.log('\n' + '='.repeat(60));
        console.log(`Test Result: ${status}`);
        console.log(`Project: ${testInfo.projectName}`);
        console.log(`Suite: ${testInfo.testSuite}`);
        console.log(`Duration: ${duration}`);
        
        if (testInfo.passed !== undefined) {
            console.log(`Passed: ${testInfo.passed}`);
            console.log(`Failed: ${testInfo.failed}`);
            console.log(`Skipped: ${testInfo.skipped || 0}`);
        }
        
        if (testInfo.status !== 'success' && testInfo.errors) {
            console.log('\nErrors:');
            console.log(testInfo.errors);
        }
        
        console.log('='.repeat(60) + '\n');
    }

    getBuildStats() {
        const last24h = this.buildHistory.filter(b => 
            Date.now() - b.startTime < 86400000
        );

        const successful = last24h.filter(b => b.status === 'success');
        const failed = last24h.filter(b => b.status === 'failed');

        return {
            total: this.buildHistory.length,
            last24h: last24h.length,
            successful: successful.length,
            failed: failed.length,
            successRate: last24h.length > 0 ? 
                (successful.length / last24h.length) * 100 : 0,
            averageDuration: this.calculateAverageDuration(last24h),
            recentBuilds: last24h.slice(-5)
        };
    }

    calculateAverageDuration(builds) {
        if (builds.length === 0) return 0;
        const totalDuration = builds.reduce((sum, build) => sum + build.duration, 0);
        return Math.round(totalDuration / builds.length);
    }

    async exportBuildReport(format = 'json') {
        const stats = this.getBuildStats();
        const report = {
            generated: new Date().toISOString(),
            stats,
            recentBuilds: this.buildHistory.slice(-10),
            activeBuild: this.activeBuild
        };

        if (format === 'json') {
            return JSON.stringify(report, null, 2);
        } else if (format === 'csv') {
            const lines = ['timestamp,project,type,duration,status,exitCode'];
            
            for (const build of this.buildHistory) {
                const line = [
                    new Date(build.startTime).toISOString(),
                    build.projectName,
                    build.buildType,
                    build.duration,
                    build.status,
                    build.exitCode || ''
                ].join(',');
                lines.push(line);
            }
            
            return lines.join('\n');
        }

        return report;
    }

    async watchProject(projectPath, buildCommand, testCommand, options = {}) {
        const fs = require('fs');
        const chokidar = require('chokidar'); // Would need to install this
        
        console.log(`Watching project: ${projectPath}`);
        console.log(`Build command: ${buildCommand}`);
        console.log(`Test command: ${testCommand}\n`);

        // Watch for file changes
        const watcher = chokidar.watch(projectPath, {
            ignored: /(^|[\/\\])\../, // ignore dotfiles
            persistent: true,
            ignoreInitial: true
        });

        let buildTimeout;
        
        watcher.on('change', (path) => {
            console.log(`File changed: ${path}`);
            
            // Debounce builds
            clearTimeout(buildTimeout);
            buildTimeout = setTimeout(async () => {
                console.log('Triggering build due to file changes...');
                
                // Run build
                const buildResult = await this.runBuild(projectPath, buildCommand, options);
                
                // Run tests if build succeeded
                if (buildResult.status === 'success' && testCommand) {
                    await this.runTests(projectPath, testCommand, options);
                }
            }, 2000); // 2 second debounce
        });

        // Keep watching until interrupted
        process.on('SIGINT', () => {
            console.log('\nStopping file watcher...');
            watcher.close();
            process.exit(0);
        });
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const monitor = new BuildMonitor();
    
    if (args[0] === 'build') {
        const projectPath = args[1] || process.cwd();
        const buildCommand = args[2] || 'npm run build';
        
        monitor.runBuild(projectPath, buildCommand).then(result => {
            process.exit(result.status === 'success' ? 0 : 1);
        });
        
    } else if (args[0] === 'test') {
        const projectPath = args[1] || process.cwd();
        const testCommand = args[2] || 'npm test';
        
        monitor.runTests(projectPath, testCommand).then(result => {
            process.exit(result.status === 'success' ? 0 : 1);
        });
        
    } else if (args[0] === 'watch') {
        const projectPath = args[1] || process.cwd();
        const buildCommand = args[2] || 'npm run build';
        const testCommand = args[3] || 'npm test';
        
        monitor.watchProject(projectPath, buildCommand, testCommand);
        
    } else {
        console.log('Usage:');
        console.log('  node build-monitor.js build [project-path] [build-command]');
        console.log('  node build-monitor.js test [project-path] [test-command]');
        console.log('  node build-monitor.js watch [project-path] [build-command] [test-command]');
    }
}

module.exports = BuildMonitor;