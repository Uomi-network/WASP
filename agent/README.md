# 🤖 WASP - WebAssembly Agent Simulation for UOMI

<div align="center">

*The development toolkit for building UOMI Network AI agents with WebAssembly and Rust* 🦀

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![WebAssembly](https://img.shields.io/badge/wasm-%23654FF0.svg?style=for-the-badge&logo=webassembly&logoColor=white)](https://webassembly.org/)
[![Node.js](https://img.shields.io/badge/node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
</div>

## 🌟 Overview

WASP (WebAssembly Agent Simulation Protocol) is a development environment for creating, testing, and deploying AI agents on the UOMI Network. It provides a comprehensive suite of tools and services to build powerful WebAssembly-based agents that can interact with LLMs, handle file storage, and process data efficiently.

## 🚀 Quick Start

```bash
# Create new agent project
npx wasp create my-agent

# Enter project directory
cd my-agent

# Start development environment
npm start
```

## 📋 Requirements

- Rust (latest stable)
- Node.js (v14+)
- WebAssembly target: `rustup target add wasm32-unknown-unknown`

## 🛠 Core Services

### AI Model Integration
- Multiple model support via `uomi.config.json`
- Built-in handling of different API formats
- Automatic token usage tracking
- Performance metrics collection

### IPFS Storage
- Direct IPFS file access
- CID-based content retrieval
- Integrated content addressing
- Built-in timeout handling

### Local File Processing
- Input file handling
- Binary data processing
- Automatic size management
- Memory-safe operations

### Development Tools
- Hot-reloading environment
- Interactive testing console
- Performance monitoring
- Debug logging system

## ⚙️ Configuration

```json
{
  "models": {
    "1": {
      "name": "Qwen/Qwen2.5-32B-Instruct-GPTQ-Int4"
    },
    "2": {
      "name": "gpt-3.5-turbo",
      "url": "https://api.openai.com/v1/chat/completions",
      "api_key": "your-api-key-here"
    }
  },
  "ipfs": {
    "gateway": "https://ipfs.io/ipfs",
    "timeout_ms": 10000
  }
}
```

## 🔌 API Reference

### Core Functions

```rust
// Input/Output Operations
read_input() -> Vec<u8>                    // Read user input data
save_output(data: &[u8])                   // Save agent response
get_input_file_service() -> Vec<u8>        // Process input file data

// AI Service Integration
call_ai_service(model: i32, content: Vec<u8>) -> Vec<u8>  // Call AI model
prepare_request(body: &str) -> Vec<u8>                    // Format API request

// IPFS Operations
get_cid_file_service(cid: Vec<u8>) -> Vec<u8>  // Fetch IPFS content

// Read Chain State
read_chain_state() -> Vec<u8>  // Read blockchain state data

// Development Tools
log(message: &str)  // Console logging
```

### Response Formats

Expected AI service response format:
```json
{
  "response": "Agent response content",
  "time_taken": 1.23,
  "tokens_per_second": 45,
  "total_tokens_generated": 54
}
```

## 💻 Development Console

Interactive commands available during development:

- `/clear` - Reset conversation state
- `/history` - Display message history
- `/metrics` - Show performance metrics
- `/exit` - End development session

## 🔍 Performance Monitoring

Track agent performance with built-in metrics:
- Response time
- Token usage
- Processing speed
- Memory utilization

## 🔒 Security

- Secure API key management
- Memory-safe operations
- Input validation
- Size-limited processing

## 🎯 Best Practices

1. **Error Handling**
   - Implement proper error handling for API calls
   - Validate input data
   - Handle memory limits appropriately

2. **Performance**
   - Monitor token usage
   - Optimize message processing
   - Use appropriate model selection

3. **Development**
   - Use debug logging effectively
   - Test with different models
   - Monitor metrics during development

## 📚 Additional Resources

- [UOMI Network Documentation](https://docs.uomi.network)
- [WebAssembly Guide](https://webassembly.org)
- [Rust Documentation](https://www.rust-lang.org/learn)

---

<div align="center">
Powered by UOMI Network 🚀
</div>
