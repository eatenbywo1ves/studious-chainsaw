# MCP Function Testing Guide

After restarting Claude Code, you can test your reorganized MCP servers with these commands:

## 🧪 **Quick Tests to Verify Everything Works**

### **Financial Stochastic MCP**
```
Generate a simple stock price simulation:
- Tool: generate_gbm
- Parameters: steps=100, timeHorizon=1, initialPrice=100

Generate mean-reverting process:
- Tool: generate_ou_process  
- Parameters: steps=100, timeHorizon=1, initialValue=0.05
```

### **Random Walk MCP**
```
Generate a basic random walk:
- Tool: generate_simple_walk
- Parameters: steps=1000, dimensions=2

Generate a biased random walk:
- Tool: generate_biased_walk
- Parameters: steps=500, bias=0.1
```

### **Multidimensional Stochastic MCP**
```
Generate correlated multi-asset paths:
- Tool: generate_multi_gbm
- Parameters: steps=100, timeHorizon=1, assets=[{"initialPrice":100,"mu":0.05,"sigma":0.2}]
```

### **Financial Localization MCP**
```
Translate financial terms:
- Tool: translate_financial_term
- Parameters: term="portfolio", to_language="es"

Format currency:
- Tool: format_currency
- Parameters: amount=1000, currency="USD", locale="en-US"
```

### **Filesystem MCP**
```
List development directory:
- Tool: list_directory
- Parameters: path="C:\\Users\\Corbin\\development"

Search for files:
- Tool: search_files
- Parameters: path="C:\\Users\\Corbin\\development", pattern="*.py"
```

## 📊 **Expected Results**

If everything is working correctly, you should see:

✅ **Financial MCPs** generate realistic financial data paths  
✅ **Random Walk MCPs** create various walk patterns  
✅ **Localization MCP** provides translations and formatting  
✅ **Filesystem MCP** can access your development directory  

## 🔧 **Troubleshooting**

If you encounter issues:

1. **Check the verification script results:**
   ```bash
   cd C:\Users\Corbin\development
   python verify-mcp-setup.py
   ```

2. **Verify MCP server paths in Claude Code:**
   - Check if `~/.mcp.json` was updated correctly
   - Ensure all paths point to `C:\Users\Corbin\development\mcp-servers\...`

3. **Check MCP server dependencies:**
   ```bash
   # Navigate to each MCP server directory and run:
   cd mcp-servers/financial/stochastic
   npm install
   
   cd ../localization  
   npm install
   
   # etc. for each server
   ```

## 🎯 **Success Indicators**

- All MCP tools appear in your Claude Code session
- Financial models generate realistic data
- File operations work in the development directory
- No error messages about missing files or servers

---

**Your reorganized MCP ecosystem is ready for production use!** 🚀