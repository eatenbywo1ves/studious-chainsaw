# Basic MCP Server Template

This is a template for creating MCP (Model Context Protocol) servers. It provides a foundation with example tools that you can customize for your specific needs.

## Features

- ✅ Basic MCP server setup using the official SDK
- ✅ Example tools: `hello` and `calculate`
- ✅ Error handling and validation
- ✅ TypeScript-ready structure
- ✅ Development and testing scripts

## Quick Start

1. **Clone this template:**
   ```bash
   cp -r templates/basic-mcp-template my-new-mcp-server
   cd my-new-mcp-server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Customize your server:**
   - Edit `package.json` to change name, description, etc.
   - Modify `src/index.js` to add your tools
   - Update this README with your server's documentation

4. **Test your server:**
   ```bash
   npm run dev
   ```

## Available Tools

### `hello`
Says hello with an optional name parameter.

**Parameters:**
- `name` (string, optional): Name to greet

**Example:**
```json
{
  "name": "hello",
  "arguments": {
    "name": "Alice"
  }
}
```

### `calculate`
Performs basic mathematical operations.

**Parameters:**
- `operation` (string): One of "add", "subtract", "multiply", "divide"
- `a` (number): First number
- `b` (number): Second number

**Example:**
```json
{
  "name": "calculate",
  "arguments": {
    "operation": "multiply",
    "a": 6,
    "b": 7
  }
}
```

## Development

- **Development mode:** `npm run dev` (auto-restart on changes)
- **Production mode:** `npm start`
- **Linting:** `npm run lint`
- **Testing:** `npm test`

## Integration

To use this server with Claude:

### Claude Code
Add to your `.mcp.json`:
```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["src/index.js"],
      "cwd": "/path/to/your/server"
    }
  }
}
```

### Claude Desktop
Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["src/index.js"],
      "cwd": "/path/to/your/server"
    }
  }
}
```

## Customization

1. **Add new tools:** Extend the `ListToolsRequestSchema` handler and add corresponding tool handlers
2. **Add resources:** Implement resource handlers if your server provides data resources
3. **Add prompts:** Implement prompt templates if needed
4. **Error handling:** Customize error messages and validation logic

## Best Practices

- Always validate input parameters
- Provide clear error messages
- Use appropriate MCP error codes
- Document your tools with clear descriptions
- Test edge cases and error conditions
- Keep tool responses focused and actionable

## License

MIT License - feel free to use this template for any purpose.