
-----

# MiniFuzz: A Simple Smart Contract Fuzzer

[](https://opensource.org/licenses/MIT)
[](https://www.python.org/downloads/)

MiniFuzz is a lightweight, educational fuzzing tool designed to automatically test Solidity smart contracts for common vulnerabilities. It works by deploying a contract to a local test blockchain, throwing a barrage of randomly generated yet valid inputs at its functions, and analyzing the resulting execution traces for known vulnerability patterns.

-----

## Features

  - **Automatic Compiler Detection**: Reads the `pragma` directive in your Solidity file to download and use the correct `solc` version.
  - **Random Test Generation**: Generates random inputs for all basic data types (`uint`, `address`, `string`, `bool`, `bytes`).
  - **Automated Deployment**: Deploys a fresh instance of the contract for each test run to ensure a clean state.
  - **Transaction Execution**: Calls contract functions with generated inputs, including sending `value` to `payable` functions.
  - **Trace Analysis**: Uses `debug_traceTransaction` to get a step-by-step EVM execution trace for every successful transaction.
  - **Vulnerability Detection**: Includes simple yet effective detectors for common security flaws.

-----

## How It Works

The fuzzer operates in a simple, linear pipeline for each test case:

1.  **Compilation**: The target `.sol` file is compiled to get its ABI, bytecode, and Abstract Syntax Tree (AST).
2.  **Test Suite Generation**: The AST is parsed to find all function and constructor definitions. The fuzzer then generates a list of functions to call, complete with randomized inputs tailored to each parameter's data type.
3.  **Deployment**: A connection is established to a local blockchain node, and a new instance of the contract is deployed using the generated constructor inputs.
4.  **Execution & Analysis**: The fuzzer iterates through the generated functions, executing them with random inputs. For each successful transaction, it fetches the execution trace and passes it to the vulnerability detectors.
5.  **Detection**: The detectors analyze the EVM opcodes in the trace for specific, unsafe patterns. If a pattern is matched, a critical vulnerability warning is logged to the console.

-----

## Prerequisites

Before you begin, ensure you have the following installed and running:

  - **Python** (version 3.10 or newer)
  - **An Ethereum Test Node**: A local blockchain environment like [**Hardhat**](https://hardhat.org/hardhat-network/docs/overview).

**Important**: Your test node must be running and accessible. The default RPC URL is typically `http://127.0.0.1:8545`.

-----

## Installation

1.  **Clone the repository:**

    ```sh
    git clone https://github.com/your-username/minifuzz.git
    cd minifuzz
    ```

2.  **Create and activate a virtual environment (recommended):**

    ```sh
    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate

    # For Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install the required packages:**

    ```sh
    pip install -r requirements.txt
    ```

-----

## Usage

To run the fuzzer, use the main script from your terminal.

1.  **Start your local blockchain node** (e.g., Hardhat).

2.  **Run the fuzzer script** with the following arguments:

    ```sh
    python main.py <path_to_contract> <num_test_cases> <rpc_url>
    ```

      - `<path_to_contract>`: The relative or absolute path to the `.sol` file you want to test.
      - `<num_test_cases>`: The number of times you want to deploy and test the contract.
      - `<rpc_url>`: The HTTP RPC endpoint of your running blockchain node.

    **Example:**

    ```sh
    python main.py ./contracts/Vulnerable.sol 5 http://127.0.0.1:8545
    ```

### Expected Output

You will see log messages indicating the progress of the fuzzer. If a vulnerability is found, a critical message will be displayed.

```
INFO - Compiling the smart contract...
INFO - Compiler version 0.8.20 not found. Installing now...
INFO - Downloaded solc v0.8.20 to /path/to/solc-bin/solc-v0.8.20
INFO - Smart contract compiled!
INFO - Running Test Case 0...
INFO - Generating the test suite...
...
INFO - Running function `withdraw`...
INFO - Transaction `withdraw` executed successfully: 0x123...
CRITICAL - ------ SCWE-046: Reentrancy Attack detected! ------
INFO - Test Case 0 finished!
...
```

-----

## Project Structure

  - `main.py`: The main entry point of the script. Parses command-line arguments and orchestrates the fuzzing process.
  - `/utils/compiler.py`: Handles the compilation of the Solidity smart contract.
  - `/fuzzer/mini_fuzzer.py`: The core class that generates test suites and runs the overall fuzzing loop.
  - `/testnet/blockchain_connection.py`: A wrapper around `web3.py` that manages blockchain connection, deployment, and transaction execution.
  - `/detectors/vulnerability_detector.py`: Contains the logic for analyzing execution traces and identifying vulnerability patterns.

-----

## Detected Vulnerabilities

This tool currently detects the following vulnerabilities:

  - **Reentrancy (SCWE-046)**: Detects when a contract makes an external call before updating its state, following the Checks-Effects-Interactions pattern.
  - **Authorization through `tx.origin` (SCWE-018)**: Flags the use of the `ORIGIN` opcode, which is an unsafe method for authorization.

-----

## Next steps

- Add more detectors based on instruction-level approaches;
- Improve Fuzzing execution;
- Show the vulnerable code line in the terminal;
 