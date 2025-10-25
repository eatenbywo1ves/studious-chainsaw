# Claude Context Optimization - Quick Reference

## 🎯 Current Status
- **Usage**: 59k / 200k tokens (30%)
- **Available**: 141k tokens (70%)
- **Biggest Consumer**: Messages (37.2k tokens)

## ⚡ Immediate Actions to Free Tokens

### 1. Clear Message History (Save ~18k tokens)
Start new conversations for unrelated tasks

### 2. Use Smart File Reading
```python
# Instead of: Read entire file
Read("file.py")

# Use: Read specific parts
Read("file.py", limit=50)  # First 50 lines
Read("file.py", tail=30)   # Last 30 lines
```

### 3. Batch Operations (Save 30-40% on tool calls)
```python
# Instead of multiple calls:
Read("file1.py")
Read("file2.py")
Read("file3.py")

# Use single call:
read_multiple_files(["file1.py", "file2.py", "file3.py"])
```

## 🔥 High-Value Strategies

### Strategy 1: Use Task Agents for Heavy Lifting
```python
# Offload complex searches and analysis
Task(subagent_type="general-purpose",
     prompt="Search codebase for all API endpoints and document them")
```

### Strategy 2: Search Before Reading
```python
# Don't read entire directories
# Instead, search first:
Grep(pattern="function.*process", glob="**/*.py")
# Then read only relevant files
```

### Strategy 3: Leverage MCP Tools (More Efficient)
- `mcp__filesystem__directory_tree` instead of recursive `ls`
- `mcp__filesystem__search_files` instead of `find`
- `mcp__filesystem__read_multiple_files` for batch reads

## 📊 Token Budget Guidelines

### For Different Task Types:
- **Quick Fix**: 10-20k tokens
- **Feature Implementation**: 30-50k tokens
- **Large Refactor**: 50-80k tokens
- **Full Project Setup**: 80-120k tokens

### Red Flags (Clear context when you see these):
- Message tokens > 40k
- Same files read multiple times
- Large directory listings stored
- Completed task details still in history

## 🚀 Power User Tips

### 1. Context Window Sliding
Keep only last 10 messages + key decisions

### 2. Semantic Compression
After completing a task, summarize:
"Implemented feature X, modified files A, B, C - all tests passing"

### 3. Dynamic Tool Loading
Load specialized tools only when needed

### 4. Smart Caching
Store frequently accessed configs in memory

## 📈 Monitoring Commands

### Check Context Usage
```bash
/context  # See current usage breakdown
```

### Clean Up Todos
```python
TodoWrite([])  # Clear completed todos
```

### Start Fresh
Begin new conversation for unrelated tasks

## ⚠️ Warning Thresholds
- **75% (150k)**: Start cleanup procedures
- **85% (170k)**: Aggressive summarization
- **90% (180k)**: New conversation recommended

## 💡 Golden Rules
1. **Search > Read**: Always search first
2. **Batch > Sequential**: Group operations
3. **Summarize > Retain**: Keep outcomes, not steps
4. **Delegate > Direct**: Use agents for complex tasks
5. **Fresh > Stale**: New conversations for new topics

---
*Remember: Every token saved is more space for problem-solving!*