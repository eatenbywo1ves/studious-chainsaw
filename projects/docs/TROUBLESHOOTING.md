# Troubleshooting Guide

Comprehensive solutions for common issues encountered in the projects monorepo.

## Quick Diagnosis

### Health Check Commands

```bash
# Check overall project health
npm run check

# Verify workspace dependencies
npm run status

# Check TypeScript compilation
npm run typecheck

# Verify all packages can build
npm run build:parallel

# Run basic tests
npm test -- --passWithNoTests
```

### Environment Verification

```bash
# Check Node.js and npm versions
node --version    # Should be >= 18.0.0
npm --version     # Should be >= 9.0.0

# Verify workspace configuration
npm config get workspaces-update
npm ls --workspaces --depth=0

# Check for conflicting global packages
npm ls -g --depth=0 | grep -E "(react|typescript|jest)"
```

## Installation Issues

### Problem: `npm install` Fails

#### Symptom
```
npm ERR! peer dep missing: react@>=18.0.0
npm ERR! could not resolve dependency tree
```

#### Solution
```bash
# Clear all caches and reinstall
rm -rf node_modules package-lock.json
rm -rf packages/*/node_modules
rm -rf mcp-servers/*/node_modules
rm -rf financial-apps/*/node_modules
rm -rf agents/*/node_modules

# Clear npm cache
npm cache clean --force

# Reinstall with exact versions
npm ci

# If still failing, install with legacy peer deps
npm install --legacy-peer-deps
```

### Problem: Workspace Dependencies Not Found

#### Symptom
```
Module not found: Can't resolve '@monorepo/shared'
```

#### Solution
```bash
# Verify workspace linking
npm ls --workspaces

# Rebuild all packages
npm run build:clean
npm run build:parallel

# Check TypeScript project references
npx tsc --showConfig

# Verify package.json exports
cat packages/shared/package.json | grep -A 5 "main\|types\|exports"
```

### Problem: Permission Errors (Windows)

#### Symptom
```
EACCES: permission denied, open 'package-lock.json'
EPERM: operation not permitted, rmdir 'node_modules'
```

#### Solution
```bash
# Run as administrator or fix permissions
icacls "C:\Users\Corbin\projects" /grant:r Users:F /t

# Alternative: Use different package manager
npm install -g pnpm
pnpm install

# Or use Yarn
npm install -g yarn
yarn install
```

## Build Issues

### Problem: TypeScript Compilation Errors

#### Symptom
```
error TS2307: Cannot find module '@monorepo/shared' or its corresponding type declarations
error TS6053: File 'packages/shared/src/index.ts' not found
```

#### Solution
```bash
# Check TypeScript configuration
npx tsc --showConfig

# Verify project references
cat tsconfig.json | grep -A 10 "references"

# Build in correct order
npm run build:ts:clean
npm run build:ts

# Check individual package builds
cd packages/shared && npm run build
cd packages/stochastic-components && npm run build
```

### Problem: ESLint Configuration Conflicts

#### Symptom
```
Configuration for rule "react-hooks/exhaustive-deps" is invalid
Parsing error: Cannot read config file
```

#### Solution
```bash
# Check ESLint configuration
npx eslint --print-config packages/stochastic-components/src/index.ts

# Verify ESLint extends chain
cat .eslintrc.json

# Clear ESLint cache
npx eslint --cache --cache-location .eslintcache packages/ --fix

# Update ESLint configuration
npm install @typescript-eslint/eslint-plugin@latest
```

### Problem: Jest Configuration Issues

#### Symptom
```
Test environment jest-environment-jsdom cannot be found
Cannot find module 'jest-environment-jsdom'
```

#### Solution
```bash
# Install missing Jest dependencies
npm install --save-dev jest-environment-jsdom @testing-library/jest-dom

# Verify Jest configuration
npx jest --showConfig

# Clear Jest cache
npx jest --clearCache

# Run Jest with debug info
npx jest --debug
```

## Runtime Issues

### Problem: React Component Errors

#### Symptom
```
Warning: React.createElement: type is invalid
Error: Minified React error #130
```

#### Solution
```bash
# Check React version compatibility
npm ls react react-dom

# Verify component exports
grep -r "export" packages/stochastic-components/src/index.ts

# Check for circular dependencies
npx madge --circular packages/stochastic-components/src

# Build in development mode for better errors
NODE_ENV=development npm run build
```

### Problem: MCP Server Connection Issues

#### Symptom
```
MCP connection failed: ECONNREFUSED
MCP server process exited with code 1
```

#### Solution
```bash
# Check MCP server status
cd mcp-servers/financial-stochastic-mcp
npm start &
curl http://localhost:3001/health

# Verify MCP configuration
cat .claude.json | grep -A 5 "mcpServers"

# Check server logs
tail -f mcp-servers/*/logs/*.log

# Test MCP server directly
node mcp-servers/financial-stochastic-mcp/src/index.js
```

### Problem: Memory Issues

#### Symptom
```
FATAL ERROR: Ineffective mark-compacts near heap limit
JavaScript heap out of memory
```

#### Solution
```bash
# Increase Node.js memory limit
export NODE_OPTIONS="--max-old-space-size=4096"

# Check memory usage
npm run build:parallel -- --verbose

# Use more efficient build process
npm run build:turbo

# Monitor memory during build
top -p $(pgrep node)
```

## Development Issues

### Problem: Hot Reload Not Working

#### Symptom
```
Changes not reflected in browser
Dev server not detecting file changes
```

#### Solution
```bash
# Check file watching limits (Linux)
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Verify dev server configuration
cat financial-apps/*/vite.config.ts

# Restart dev servers
npm run dev:parallel

# Check for file permission issues
ls -la packages/stochastic-components/src/
```

### Problem: Import Path Resolution

#### Symptom
```
Module not found: Can't resolve '../../../shared'
Cannot resolve module '@monorepo/shared'
```

#### Solution
```bash
# Check TypeScript path mapping
cat tsconfig.json | grep -A 10 "paths"

# Verify package.json exports
cat packages/shared/package.json | grep -A 5 "exports"

# Use absolute imports
# Instead of: import { utils } from '../../../shared'
# Use: import { utils } from '@monorepo/shared'

# Update import statements
find packages/ -name "*.ts" -o -name "*.tsx" | xargs sed -i 's/import.*\.\.\/.*shared/import from "@monorepo\/shared"/g'
```

### Problem: Stale Cache Issues

#### Symptom
```
Old version of component still rendering
Build artifacts from previous version
```

#### Solution
```bash
# Clear all caches
npm run build:clean
rm -rf .turbo/
rm -rf packages/*/.turbo/
rm -rf .eslintcache
rm -rf coverage/

# Clear browser cache
# Chrome: Ctrl+Shift+R
# Firefox: Ctrl+F5

# Restart development servers
npm run dev:parallel
```

## Performance Issues

### Problem: Slow Build Times

#### Symptom
```
Build taking > 5 minutes
TypeScript compilation very slow
```

#### Diagnosis
```bash
# Measure build performance
time npm run build:parallel

# Check TypeScript performance
npx tsc --diagnostics --noEmit

# Analyze bundle sizes
npm run build:analyze
```

#### Solution
```bash
# Use incremental builds
npm run build:ts -- --incremental

# Enable parallel builds
npm run build:turbo

# Optimize TypeScript configuration
# Add to tsconfig.json:
{
  "compilerOptions": {
    "incremental": true,
    "tsBuildInfoFile": ".tsbuildinfo"
  }
}

# Use faster alternatives
npm install --save-dev esbuild
```

### Problem: Large Bundle Sizes

#### Symptom
```
Bundle size exceeding limits
Slow page load times
```

#### Solution
```bash
# Analyze bundle composition
npm run build:analyze

# Check for duplicate dependencies
npx webpack-bundle-analyzer dist/

# Implement code splitting
# Add dynamic imports:
const Component = lazy(() => import('./HeavyComponent'));

# Optimize imports
# Instead of: import * as utils from 'lodash'
# Use: import { debounce } from 'lodash'
```

### Problem: Memory Leaks in Components

#### Symptom
```
Browser tab consuming excessive memory
Performance degradation over time
```

#### Solution
```typescript
// Implement proper cleanup
useEffect(() => {
  const subscription = data$.subscribe(handleData);
  const timer = setInterval(update, 1000);

  return () => {
    subscription.unsubscribe();
    clearInterval(timer);
  };
}, []);

// Use React.memo for expensive components
const ExpensiveComponent = React.memo(({ data }) => {
  // Component implementation
});

// Optimize large datasets
const VirtualizedList = ({ items }) => {
  return (
    <FixedSizeList
      height={600}
      itemCount={items.length}
      itemSize={35}
    >
      {Row}
    </FixedSizeList>
  );
};
```

## Testing Issues

### Problem: Tests Failing in CI but Passing Locally

#### Symptom
```
Tests pass on local machine but fail in GitHub Actions
Timing-related test failures
```

#### Solution
```bash
# Increase timeouts for CI
export CI=true
npm test -- --testTimeout=10000

# Use more stable test patterns
// Instead of:
setTimeout(() => expect(element).toBeInTheDocument(), 100);

// Use:
await waitFor(() => {
  expect(element).toBeInTheDocument();
}, { timeout: 5000 });

# Mock time-dependent functions
jest.useFakeTimers();
jest.setSystemTime(new Date('2024-01-01'));
```

### Problem: Flaky Tests

#### Symptom
```
Tests sometimes pass, sometimes fail
Inconsistent test results
```

#### Solution
```bash
# Run tests multiple times to identify flaky ones
for i in {1..10}; do npm test -- --testNamePattern="flaky test"; done

# Use better test patterns
// Avoid:
expect(Math.random()).toBe(0.5);

// Use:
jest.spyOn(Math, 'random').mockReturnValue(0.5);
expect(Math.random()).toBe(0.5);

# Ensure test isolation
beforeEach(() => {
  jest.clearAllMocks();
  cleanup();
});
```

## Platform-Specific Issues

### Windows Issues

#### Problem: Path Length Limitations
```bash
# Enable long paths in Windows
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# Use shorter directory names
mkdir C:\p  # Instead of C:\Users\Username\Documents\Projects
```

#### Problem: Line Ending Issues
```bash
# Configure Git to handle line endings
git config --global core.autocrlf true

# Convert existing files
npx prettier --write "**/*.{js,ts,tsx,json,md}"
```

### macOS Issues

#### Problem: Permission Issues with npm
```bash
# Fix npm permissions
sudo chown -R $(whoami) $(npm config get prefix)/{lib/node_modules,bin,share}

# Use Node version manager
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18
```

### Linux Issues

#### Problem: File Watching Limits
```bash
# Increase file watching limits
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Check current limits
cat /proc/sys/fs/inotify/max_user_watches
```

## Debugging Strategies

### Enable Debug Logging

```bash
# Enable debug mode for npm
DEBUG=* npm run build

# Enable verbose logging
npm run build -- --verbose

# Check build output
npm run build > build.log 2>&1
tail -f build.log
```

### Use Development Tools

```bash
# Chrome DevTools for React components
# Install React Developer Tools extension

# VS Code debugging
# Add to .vscode/launch.json:
{
  "type": "node",
  "request": "launch",
  "name": "Debug Tests",
  "program": "${workspaceFolder}/node_modules/.bin/jest",
  "args": ["--runInBand"],
  "console": "integratedTerminal"
}
```

### Network Debugging

```bash
# Check network connectivity
curl -I https://registry.npmjs.org/

# Test MCP server endpoints
curl -X POST http://localhost:3001/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list","params":{}}'

# Monitor network traffic
netstat -an | grep :3001
```

## Getting Help

### Internal Resources

1. **Documentation**: Check `/docs` directory for detailed guides
2. **Examples**: Look at `/examples` for working implementations
3. **Tests**: Examine test files for usage patterns
4. **CI Logs**: Review GitHub Actions logs for build details

### External Resources

1. **React Documentation**: https://react.dev/
2. **TypeScript Handbook**: https://www.typescriptlang.org/docs/
3. **Jest Documentation**: https://jestjs.io/docs/
4. **MCP Specification**: https://modelcontextprotocol.io/

### Creating Support Requests

When creating issues, include:

```bash
# System information
npm run status
node --version
npm --version
git log --oneline -5

# Error logs
npm run build 2>&1 | tee build-error.log

# Environment details
echo "OS: $(uname -a)"
echo "Node: $(node --version)"
echo "NPM: $(npm --version)"
echo "Git: $(git --version)"
```

## Prevention Strategies

### Proactive Monitoring

```bash
# Add health check script
cat > scripts/health-check.js << 'EOF'
const { execSync } = require('child_process');

const checks = [
  'npm run typecheck',
  'npm run lint',
  'npm test -- --passWithNoTests',
  'npm run build:parallel'
];

checks.forEach(check => {
  try {
    execSync(check, { stdio: 'inherit' });
    console.log(`✅ ${check}`);
  } catch (error) {
    console.error(`❌ ${check}`);
    process.exit(1);
  }
});
EOF

# Run daily health checks
npm run health-check
```

### Automated Maintenance

```bash
# Update dependencies regularly
npm update
npm audit fix

# Clean up periodically
npm run build:clean
npm cache clean --force

# Monitor bundle sizes
npm run build:analyze > bundle-report.txt
```

### Code Quality Gates

```bash
# Pre-commit hooks
npx husky add .husky/pre-commit "npm run check"

# CI quality gates
# Add to .github/workflows/quality.yml:
- name: Quality Gate
  run: |
    npm run check
    npm run test:coverage
    npm run build:parallel
```

---

This troubleshooting guide covers the most common issues and their solutions. For persistent problems, please create an issue with detailed reproduction steps and system information.