"""A command-line script for running a fuzzer on a smart contract.

This script compiles a specified smart contract and then uses the MiniFuzzer
to execute fuzz testing based on the provided number of test cases and RPC URL.

Usage:
    python main.py <path_to_contract.sol> <num_test_cases> <rpc_url>
"""

import sys
import logging
from utils import compiler
from fuzzer.mini_fuzzer import MiniFuzzer
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Parse command-line arguments to get the contract path, number of test
    # cases, and the RPC URL for connecting to an EVM network.
    try:
        contract_path = sys.argv[1]
        test_cases = int(sys.argv[2])
        rpc_url = sys.argv[3]
    except:
        raise Exception("Incorrect arguments. Check documentation for instructions!")

    # Compile the target smart contract to extract its ABI, bytecode, and AST.
    output = compiler.compile_smart_contract(contract_path)

    # Initialize the fuzzer with the compiled contract data and test configuration.
    fuzz = MiniFuzzer(
        abi=output["abi"],
        bytecode=output["bin"],
        ast=output["ast"],
        rpc_url=rpc_url,
        test_cases=test_cases
    )
    
    # Begin the fuzzing process to find potential vulnerabilities.
    fuzz.run()