# PostgreSQL MCP - Quick Start Guide

## ⚡ 1-Minute Setup

### Step 1: Set Password
```bash
# Add to ~/development/saas/.env
echo "POSTGRES_PASSWORD=secure_password_change_me" >> ~/development/saas/.env
```

### Step 2: Start Database
```bash
cd ~/development
docker compose --profile saas up -d postgres
```

### Step 3: Restart Claude Code
The PostgreSQL MCP is already configured in `~/.mcp.json`

### Step 4: Test Connection
Ask Claude:
> "Show me all tables in the catalytic_saas database"

## 🎯 Common Tasks

### Check Table Sizes
> "What are my 5 largest tables?"

### Analyze Partitions
> "Show me the status of api_logs partitions"

### Find Slow Queries
> "What queries are running slowly?"

### Check Archival Status
> "Run the archival status check"

### Verify Indexes
> "Are there any missing indexes on foreign keys?"

### Monitor Connections
> "How many active connections do we have?"

## 🛡️ Safety Features

✅ **5 connection limit** - Won't exhaust your pool
✅ **30s query timeout** - Prevents runaway queries
✅ **10s connection timeout** - Fast failure detection
✅ **Production mode** - Optimized performance
✅ **SSL preferred** - Encrypted connections

## 🔧 Troubleshooting

**Can't connect?**
```bash
docker ps | grep postgres
export POSTGRES_PASSWORD="your-password"
```

**Too slow?**
- Use LIMIT in queries
- Add indexes first
- Check with EXPLAIN ANALYZE

**Need help?**
Ask Claude to explain any database concept or query result!

## 📖 Full Documentation
See [POSTGRESQL_MCP_GUIDE.md](./POSTGRESQL_MCP_GUIDE.md) for comprehensive usage guide.
