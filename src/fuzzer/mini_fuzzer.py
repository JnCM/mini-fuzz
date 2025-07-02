import random
import logging
from web3 import Web3
from testnet.blockchain import BlockchainConnection
from detectors.detector import VulnerabilityDetector
logger = logging.getLogger(__name__)

class MiniFuzzer:
    """
    A simple fuzzer for testing smart contracts for vulnerabilities.

    This class orchestrates the fuzzing process by generating random test cases,
    deploying the contract to a testnet, executing transactions with random inputs,
    and analyzing the execution trace for potential security issues.
    """
    def __init__(self, abi: list, bytecode: str, ast: dict, rpc_url: str, test_cases: int):
        """
        Initializes the MiniFuzzer instance.

        Args:
            abi (list): The Application Binary Interface (ABI) of the smart contract.
            bytecode (str): The compiled bytecode of the smart contract.
            ast (dict): The Abstract Syntax Tree (AST) of the compiled contract.
            rpc_url (str): The URL of the RPC endpoint for the blockchain connection.
            test_cases (int): The total number of test cases to run.
        """
        # Fuzzing configuration
        self.__num_tests = test_cases
        
        # Smart contract artifacts
        self.__bytecode = bytecode
        self.__abi = abi
        self.__ast = ast
        
        # Helper modules
        self.__blockhainwrapper = BlockchainConnection(rpc_url)
        self.__detector = VulnerabilityDetector()

    def generate_inputs(self, param_list: list) -> list | None:
        """
        Generates random inputs for a given list of function parameters.

        Args:
            param_list (list): A list of parameter objects from the contract's AST.

        Returns:
            inputs (list | None): A list of randomly generated values corresponding to the
                         parameter types. Returns None on failure.
        """
        logging.info("Generating inputs for a function...")

        try:
            inputs = []
            for param in param_list:
                # Extracts the type string, e.g., 'uint256' or 'address'.
                param_type = param["typeDescriptions"]["typeString"]
                value = None

                # Generate a random value based on the parameter's data type.
                if param_type in ('uint256', 'uint'):
                    value = random.randint(0, 2**256 - 1)
                elif param_type == 'address':
                    # Create a random valid Ethereum address.
                    value = Web3.to_checksum_address('0x' + ''.join(random.choices('0123456789abcdef', k=40)))
                elif param_type == 'string':
                    value = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=random.randint(5, 15)))
                elif param_type == 'bool':
                    value = random.choice([True, False])
                elif param_type.startswith('bytes'):
                    # Determine byte size from type string (e.g., 'bytes32') or pick a random one.
                    size = int(param_type.replace('bytes', '')) if len(param_type) > 5 else random.randint(1, 32)
                    value = '0x' + ''.join(random.choices('0123456789abcdef', k=size * 2))
                
                inputs.append(value)
        except Exception as e:
            logging.error(f"Inputs could not be generated. Error description: {e}")
            return None
        
        logging.info("Inputs generated!")
        return inputs

    def generate_test_suite(self) -> tuple[list | None, list | None]:
        """
        Generates a test suite by parsing the contract's AST.

        A test suite consists of a list of functions to call with generated inputs
        and the inputs required for the contract's constructor.

        Returns:
            test (tuple): A tuple containing the list of functions and the constructor inputs.
                   Returns (None, None) on failure.
        """
        logging.info("Generating the test suite...")

        try:
            functions = []
            constructor_inputs = None
            # Iterate through the AST to find the main contract definition.
            for node in self.__ast['nodes']:
                if node['nodeType'] == "ContractDefinition":
                    # Find all function and constructor definitions within the contract.
                    for vf in node['nodes']:
                        # Case 1: A standard, callable function.
                        if vf['nodeType'] == 'FunctionDefinition' and vf["kind"] == "function":
                            functions.append({
                                "name": vf['name'],
                                "inputs": self.generate_inputs(vf["parameters"]["parameters"]),
                                # Generate a random Ether value for payable functions.
                                "value": random.randint(10**15, 5*10**18) if vf["stateMutability"] == "payable" else 0
                            })
                        # Case 2: The contract constructor.
                        elif vf['nodeType'] == 'FunctionDefinition' and vf["kind"] == "constructor":
                            constructor_inputs = self.generate_inputs(vf["parameters"]["parameters"])
        except Exception as e:
            logging.error(f"Error during test suite generation. Error description: {e}")
            return None, None

        logging.info("Test suite generated!")
        return functions, constructor_inputs

    def execute_functions(self, functions: list, contract: object):
        """
        Executes a list of functions against a deployed contract instance.

        Args:
            functions (list): A list of function objects from generate_test_suite.
            contract (object): A deployed contract object from the BlockchainConnection.
        """
        for function in functions:
            tx_receipt = self.__blockhainwrapper.execute_transaction(contract, function)
            # Proceed only if the transaction was successfully mined.
            if tx_receipt is not None:
                result = self.__blockhainwrapper.debug_transaction(tx_receipt)
                # Analyze the execution trace if the transaction did not revert.
                if not result.failed:
                    for instruction in result["structLogs"]:
                        # Run each detector on the instruction trace.
                        self.__detector.reentrancy(instruction)
                        self.__detector.tx_origin(instruction)
                    # Reset detector state for the next function call.
                    self.__detector.reset_variables()

    def run(self):
        """
        The main entry point to start the fuzzing process.
        
        This method runs a loop for a specified number of test cases. In each case,
        it generates a new test suite, deploys a fresh instance of the contract,
        and executes the generated function calls against it.
        """
        for test in range(self.__num_tests):
            logging.info(f"Running Test Case {test}...")
            # Generate a new, random set of functions and inputs.
            functions, constructor_inputs = self.generate_test_suite()
            
            # Deploy a fresh contract instance for each test case to ensure isolation.
            deployed_contract = self.__blockhainwrapper.deploy_smart_contract(
                abi=self.__abi,
                bytecode=self.__bytecode,
                constructor_args=constructor_inputs
            )
            
            # Execute the function calls if the contract deployed successfully.
            if deployed_contract:
                self.execute_functions(functions, deployed_contract)
            
            logging.info(f"Test Case {test} finished!")