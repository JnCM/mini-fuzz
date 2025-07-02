import logging
logger = logging.getLogger(__name__)

class VulnerabilityDetector:
    """
    Analyzes EVM execution traces to detect common smart contract vulnerabilities.

    This class inspects a stream of EVM instructions (structLogs) from a single
    transaction to identify patterns associated with specific security flaws,
    such as reentrancy and insecure use of `tx.origin`.
    """
    def __init__(self):
        """Initializes the detector's state variables."""
        # A dictionary to track storage reads {storage_index: program_counter}.
        self.__sloads = dict()
        # A set to store the program counter of detected external calls.
        self.__calls = set()
        # A flag to prevent duplicate logging for the same reentrancy vulnerability.
        self.__flag = False

    def reentrancy(self, instruction: dict):
        """
        Detects potential reentrancy vulnerabilities in an instruction trace.

        This method follows the "Checks-Effects-Interactions" pattern. It flags cases
        where a contract makes an external call (Interaction) before it has finished
        updating its state (Effect), which was based on a prior check (Check).

        Args:
            instruction (dict): A single EVM instruction from a structLog.
        """
        # Phase 1: Track state reads (Checks).
        # Record the program counter (pc) of every storage read (SLOAD).
        if instruction["op"] == "SLOAD":
            storage_index = instruction["stack"][-1]
            self.__sloads[storage_index] = instruction["pc"]

        # Phase 2: Identify dangerous external calls (Interactions).
        # A 'CALL' with sufficient gas and a non-zero Ether value is potentially risky.
        elif instruction["op"] == "CALL" and self.__sloads:
            gas = int(instruction["stack"][-1], 16)
            value = int(instruction["stack"][-3], 16)
            # Standard stipend for transfers is 2300 gas. More gas allows the recipient to call back.
            if gas > 2300 and value > 0:
                self.__calls.add(instruction["pc"])
                # Check if any state was read *before* this external call occurred.
                for pc in self.__sloads.values():
                    if pc < instruction["pc"]:
                        logging.critical("------ SCWE-046: Reentrancy Attack detected! ------")
                        self.__flag = True
                        return # Exit after first detection to avoid log spam.

        # Phase 3: Check if state is written *after* an external call (Effects).
        # This confirms the unsafe ordering of operations.
        elif instruction["op"] == "SSTORE" and self.__calls:
            storage_index = instruction["stack"][-1]
            # Check if this write corresponds to a previously read slot.
            if storage_index in self.__sloads:
                for pc in self.__calls:
                    # If a call happened before this write and we haven't flagged it yet, it's a vulnerability.
                    if pc < instruction["pc"] and not self.__flag:
                        logging.critical("------ SCWE-046: Reentrancy Attack detected! ------")
                        return # Exit after first detection.

    def tx_origin(self, instruction: dict):
        """
        Detects the use of `tx.origin` for authorization.

        Using `tx.origin` for authentication is unsafe because any contract can
        be tricked into performing actions on behalf of the original user.
        `msg.sender` should be used instead.

        Args:
            instruction (dict): A single EVM instruction from a structLog.
        """
        # The 'ORIGIN' opcode pushes the address of the original transaction sender into the stack.
        if instruction["op"] == "ORIGIN":
            logging.critical("------ SCWE-018: Use of tx.origin for Authorization detected! ------")

    def reset_variables(self):
        """Resets the internal state of the detector.

        This must be called between analyzing different transaction traces to
        prevent state from one analysis from leaking into the next, which
        would cause false positives.
        """
        self.__sloads = dict()
        self.__calls = set()
        self.__flag = False