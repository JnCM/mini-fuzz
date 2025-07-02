import logging
from web3 import Web3
logger = logging.getLogger(__name__)

class BlockchainConnection:
    """
    A wrapper for Web3.py to handle blockchain interactions.

    This class simplifies connecting to an Ethereum node, deploying smart
    contracts, and executing transactions for the fuzzer.
    """
    def __init__(self, rpc_url: str):
        """
        Initializes the connection to an Ethereum-like blockchain.

        Args:
            rpc_url (str): The HTTP endpoint of the JSON-RPC provider.

        Raises:
            ConnectionError: If the connection to the RPC provider fails.
        """
        logging.info("Connecting with the blockchain...")
        self.__w3_conn = Web3(Web3.HTTPProvider(rpc_url))
        
        # Verify that the connection was successful.
        if self.__w3_conn.is_connected():
            logging.info("Blockchain connected successfully!")
            # Set a default account for sending transactions. This is usually the first unlocked account on a test node.
            self.__w3_conn.eth.default_account = self.__w3_conn.eth.accounts[0]
        else:
            raise ConnectionError("Error during blockchain connection. Check the RPC Provider!")

    def deploy_smart_contract(self, abi: list, bytecode: str, constructor_args: list | None = None) -> object | None:
        """
        Deploys a smart contract to the connected blockchain.

        Args:
            abi (list): The Application Binary Interface (ABI) of the contract.
            bytecode (str): The compiled EVM bytecode of the contract.
            constructor_args (list | None, optional): A list of arguments for the contract's constructor. Defaults to None.

        Returns:
            contract (object | None): A Web3.py contract object representing the deployed contract, or None if deployment fails.
        """
        logging.info("Deploying smart contract...")
        
        try:
            # Create a contract factory from the ABI and bytecode.
            contract = self.__w3_conn.eth.contract(abi=abi, bytecode=bytecode)
            
            # Deploy the contract, passing constructor arguments if they exist.
            if constructor_args is not None:
                tx_hash = contract.constructor(*constructor_args).transact()
            else:
                tx_hash = contract.constructor().transact()
            
            # Wait for the deployment transaction to be mined and get its receipt.
            tx_receipt = self.__w3_conn.eth.wait_for_transaction_receipt(tx_hash)
            contract_address = tx_receipt.contractAddress
        except Exception as e:
            logging.error(f"Smart contract could not be deployed. Error description: {e}")
            return None
        
        logging.info(f"Contract deployed at `{contract_address}`!")
        # Return an interactive contract instance attached to the new address.
        return self.__w3_conn.eth.contract(address=contract_address, abi=abi)

    def execute_transaction(self, contract: object, function: dict) -> object | None:
        """
        Executes a function on a deployed smart contract.

        Args:
            contract (object): The Web3.py contract object to interact with.
            function (dict): A dictionary containing the function's name, inputs, and value.

        Returns:
            receipt (object | None): The transaction receipt if successful, otherwise None.
        """
        logging.info(f"Running function `{function['name']}`...")
        
        try:
            # Dynamically get the function from the contract object by its name.
            func_to_call = getattr(contract.functions, function['name'])

            # Call the function with or without arguments and include any Ether value.
            if len(function["inputs"]) > 0:
                txn = func_to_call(*function["inputs"]).transact({'value': function["value"]})
            else:
                txn = func_to_call().transact({'value': function["value"]})

            # Wait for the transaction to be mined.
            tx_receipt = self.__w3_conn.eth.wait_for_transaction_receipt(txn)
        except Exception as e:
            logging.error(f"Contract function could not be executed. Error description: {e}")
            return None
        
        logging.info(f"Transaction `{function['name']}` executed successfully: {tx_receipt.transactionHash.hex()}")
        return tx_receipt

    def debug_transaction(self, tx_receipt: object) -> dict:
        """
        Retrieves the detailed execution trace of a transaction.

        Note: This requires the connected Ethereum node to have the debug API enabled.

        Args:
            tx_receipt (object): The transaction receipt from a successful transaction.

        Returns:
            instructions (dict): The debug trace containing the list of EVM instructions (structLogs).
        """
        # Use a direct JSON-RPC request for the non-standard `debug_traceTransaction`.
        return self.__w3_conn.manager.request_blocking('debug_traceTransaction', [f"0x{tx_receipt.transactionHash.hex()}"])