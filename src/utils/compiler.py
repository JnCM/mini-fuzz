"""
A utility for compiling Solidity smart contracts using the solcx library.

This module provides a function to read a Solidity source file, automatically
detect the required compiler version from the pragma directive, install it if
needed, and compile the contract to retrieve its ABI, bytecode, and AST.
"""

import re
import logging
import solcx
logger = logging.getLogger(__name__)

def compile_smart_contract(contract_path: str) -> dict | None:
    """Compiles a Solidity smart contract from a given file path.

    This function reads the source code, determines the required solc version
    from the pragma line, installs that version if not already present,
    and then compiles the contract.

    Args:
        contract_path (str): The file path to the Solidity smart contract (.sol).

    Returns:
        output (dict | None): A dictionary containing the contract's "abi", "bin" (bytecode),
                     and "ast". Returns None if compilation fails.
    """
    logging.info("Compiling the smart contract...")
    
    try:
        # Read the contract's source code from the file.
        with open(contract_path, 'r') as file:
            source_code = file.read()
        
        # Use regex to find the pragma line and extract the compiler version.
        compiler_version = None
        pragma_match = re.search(r"pragma solidity (\^?|>=?|<=?)?([0-9]+\.[0-9]+\.[0-9]+);", source_code)
        if pragma_match:
            compiler_version = pragma_match.group(2)
        
        # Ensure a compiler version was found before proceeding.
        if compiler_version is None:
            raise Exception("Solidity version could not be accessed. Check the smart contract source code!")

        # If the required compiler version is not installed, install it automatically.
        if compiler_version not in solcx.get_installed_solc_versions():
            logging.info(f"Compiler version {compiler_version} not found. Installing now...")
            solcx.install_solc(compiler_version)

        # Set the active solc version for the compilation process.
        solcx.set_solc_version(compiler_version, True)

        # Compile the source code with optimizations enabled.
        compiler_output = solcx.compile_source(
            source_code,
            optimize=True,
            optimize_runs=200,
            output_values=["abi", "bin", "ast"],
            solc_version=compiler_version
        )
    except Exception as e:
        logging.error(f"Smart contract could not be compiled. Check the smart contract path and source code! Error description: {e}")
        return None

    logging.info("Smart contract compiled!")
    return list(compiler_output.values())[0]