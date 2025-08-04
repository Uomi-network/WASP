import fs from "fs";
import { exec } from "child_process";
import path from "path";
import readline from "readline";

// Configuration
const CONFIG = {
  inputPath: path.join("host", "src", "input.txt"),
  outputPath: path.join("host", "src", "output.txt"),
  buildScript: "bash ./bin/build_and_run_host.sh",
};

// Console colors
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
};

// Function to parse the response
function parseResponse(response) {
  try {
    // Remove "A:\n" prefix if present
    const cleanResponse = response.replace(/^A:\n/, "");
    let jsonResponse;
    
    try {
      jsonResponse = JSON.parse(cleanResponse);
    } catch (e) {
      console.log(`${colors.yellow}Warning: Could not parse response as JSON${colors.reset}`);
      return { content: cleanResponse };
    }

    // Check if it's OpenAI format
    if (jsonResponse.choices && Array.isArray(jsonResponse.choices)) {
      const content = jsonResponse.choices[0]?.message?.content || jsonResponse.choices[0]?.text;
      return {
        content,
        isOpenAI: true,
        performance: {
          timeTaken: jsonResponse.usage?.total_time,
          totalTokens: jsonResponse.usage?.total_tokens,
          promptTokens: jsonResponse.usage?.prompt_tokens,
          completionTokens: jsonResponse.usage?.completion_tokens,
        },
        model: jsonResponse.model,
      };
    }

    // Default UOMI format
    if (jsonResponse.response) {
      return {
        content: jsonResponse.response,
        isOpenAI: false,
        performance: {
          timeTaken: jsonResponse.time_taken,
          tokensPerSecond: jsonResponse.tokens_per_second,
          totalTokens: jsonResponse.total_tokens_generated,
        },
      };
    }

    // If neither format is recognized, return raw response
    return {
      content: cleanResponse,
      isOpenAI: false,
    };
  } catch (error) {
    console.log(`${colors.red}Error parsing response:${colors.reset}`, error);
    return { content: response };
  }
}

// Function to format output
function formatOutput(parsedResponse) {
  let output = "\n";

  // Main content
  output += `${colors.green}Assistant:${colors.reset}\n${parsedResponse.content}\n`;

  // Technical details based on response type
  if (parsedResponse.performance) {
    output += `\n${colors.cyan}Performance Metrics:${colors.reset}`;
    
    if (parsedResponse.isOpenAI) {
      if (parsedResponse.model) {
        output += `\n- Model: ${parsedResponse.model}`;
      }
      if (parsedResponse.performance.totalTokens) {
        output += `\n- Total tokens: ${parsedResponse.performance.totalTokens}`;
      }
      if (parsedResponse.performance.promptTokens) {
        output += `\n- Prompt tokens: ${parsedResponse.performance.promptTokens}`;
      }
      if (parsedResponse.performance.completionTokens) {
        output += `\n- Completion tokens: ${parsedResponse.performance.completionTokens}`;
      }
      if (parsedResponse.performance.timeTaken) {
        output += `\n- Time taken: ${parsedResponse.performance.timeTaken.toFixed(2)}s`;
      }
    } else {
      if (parsedResponse.performance.timeTaken) {
        output += `\n- Time taken: ${parsedResponse.performance.timeTaken.toFixed(2)}s`;
      }
      if (parsedResponse.performance.tokensPerSecond) {
        output += `\n- Tokens/second: ${Math.round(parsedResponse.performance.tokensPerSecond)}`;
      }
      if (parsedResponse.performance.totalTokens) {
        output += `\n- Total tokens: ${parsedResponse.performance.totalTokens}`;
      }
    }
  }

  return output;
}

class ConversationHistory {
  constructor() {
    this.messages = [];
  }

  addMessage(role, content) {
    // If content is a response object, extract only the text
    if (typeof content === "string") {
      try {
        const parsed = JSON.parse(content);
        if (parsed.response) {
          content = parsed.response;
        }
      } catch (e) {
        // If not valid JSON, use content as is
      }
    }

    this.messages.push({ role, content });
  }

  clear() {
    this.messages = [];
  }

  toString() {
    return this.messages
      .map((msg, i) => {
        return `${i + 1}. ${msg.role}: ${msg.content}\n`;
      })
      .join("");
  }
}

const conversation = new ConversationHistory();

async function runCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, { maxBuffer: 1024 * 1024 * 10 }, (err, stdout, stderr) => {
      if (err && !stderr.includes("Compiling")) {
        // If there's an error but not related to compilation
        reject({ err, stderr });
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function processMessage(message) {
  try {
    conversation.addMessage("user", message);
    fs.writeFileSync(CONFIG.inputPath, JSON.stringify(conversation.messages));

    console.log(`\n${colors.cyan}Executing WASM...${colors.reset}`);

    const { stdout, stderr } = await runCommand(CONFIG.buildScript);

    // Filter stderr messages
    const errorMessages = filterBuildMessages(stderr);
    if (errorMessages) {
      console.log(`${colors.red}Errors:${colors.reset}\n${errorMessages}`);
    }

    // Optional: filter stdout messages if needed
    const relevantOutput = filterBuildMessages(stdout);
    if (relevantOutput) {
      console.log(`${colors.bright}Logs:${colors.reset}\n${relevantOutput}`);
    }

    const output = fs.readFileSync(CONFIG.outputPath).toString();

    const parsedResponse = parseResponse(output);
    console.log(formatOutput(parsedResponse));

    conversation.addMessage("assistant", parsedResponse.content);

    return parsedResponse;
  } catch (error) {
    console.error(`${colors.red}Error:${colors.reset}`, error);
    return null;
  }
}

function filterBuildMessages(messages) {
  if (!messages) return null;

  const ignorePatterns = [
    /Finished.*profile/,
    /Compiling.*/,
    /Running.*/,
    /warning: profiles for the non root package will be ignored/,
    /warning: virtual workspace defaulting to/,
    /note: to keep the current resolver/,
    /note: to use the edition 2021 resolver/,
    /note: for more details see/,
  ];

  const lines = messages.split("\n");

  const relevantLines = lines.filter((line) => {
    const isRelevant = !ignorePatterns.some((pattern) => pattern.test(line));
    const isNotEmpty = line.trim().length > 0;
    return isRelevant && isNotEmpty;
  });

  return relevantLines.length > 0 ? relevantLines.join("\n") : null;
}

function startInteractiveMode() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  console.log(`${colors.bright}UOMI Development Environment${colors.reset}`);
  console.log("Type your messages. Use these commands:");
  console.log("/clear - Clear conversation history");
  console.log("/history - Show conversation history");
  console.log("/exit - Exit the program\n");

  function askQuestion() {
    rl.question(`${colors.green}You:${colors.reset} `, async (input) => {
      if (input.toLowerCase() === "/exit") {
        rl.close();
        return;
      }

      if (input.toLowerCase() === "/clear") {
        conversation.clear();
        console.log(
          `${colors.yellow}Conversation history cleared${colors.reset}`
        );
        askQuestion();
        return;
      }

      if (input.toLowerCase() === "/history") {
        console.log(`${colors.blue}Conversation History:${colors.reset}`);
        console.log(conversation.toString());
        askQuestion();
        return;
      }

      await processMessage(input);
      askQuestion();
    });
  }

  askQuestion();
}

// Command line arguments handling
const args = process.argv.slice(2);
if (args.length > 0) {
  // Single-shot mode
  const message = args.join(" ");
  processMessage(message);
} else {
  // Interactive mode
  startInteractiveMode();
}

// Unhandled error handling
process.on("unhandledRejection", (error) => {
  console.error(
    `${colors.red}Unhandled promise rejection:${colors.reset}`,
    error
  );
});

process.on("uncaughtException", (error) => {
  console.error(`${colors.red}Uncaught exception:${colors.reset}`, error);
});
