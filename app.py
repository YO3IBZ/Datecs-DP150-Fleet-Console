import socket
import datetime
import json
import os
import time
import shutil
import calendar
from flask import Flask, jsonify, request, render_template

app = Flask(__name__)
CONFIG_FILE = "config.json"

# Log directory configurations
LOGS_DIR = "/logs"
LOG_FILE = os.path.join(LOGS_DIR, "active.log")

# =====================================================================
# Logging & Auto-Rotation Setup (with Hostname/Computer Name lookup)  #
# =====================================================================
def ensure_log_dir():
    """
    Verifies that the /logs directory and active.log file exist.
    Gracefully falls back to the application directory if root permissions block writes.
    """
    global LOGS_DIR, LOG_FILE
    try:
        if not os.path.exists(LOGS_DIR):
            os.makedirs(LOGS_DIR)
    except PermissionError:
        # Fallback to local application directory if /logs is read-only
        base_dir = os.path.dirname(os.path.abspath(__file__))
        LOGS_DIR = os.path.join(base_dir, "logs")
        if not os.path.exists(LOGS_DIR):
            os.makedirs(LOGS_DIR)
            
    LOG_FILE = os.path.join(LOGS_DIR, "active.log")
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            f.write("")

def check_and_rotate_logs():
    """
    Examines the active log's modification timestamp.
    If the month/year of the file is older than the current clock, 
    the active log is archived by month name and cleared.
    """
    ensure_log_dir()
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        return

    mtime = os.path.getmtime(LOG_FILE)
    log_date = datetime.datetime.fromtimestamp(mtime)
    now = datetime.datetime.now()

    # Compare file date against current clock to trigger transition
    if log_date.month != now.month or log_date.year != now.year:
        month_name = calendar.month_name[log_date.month]  # e.g., "July"
        archive_name = f"{month_name}_{log_date.year}.log"
        archive_path = os.path.join(LOGS_DIR, archive_name)
        
        try:
            shutil.copy(LOG_FILE, archive_path)
            # Truncate/recreate active log
            with open(LOG_FILE, 'w') as f:
                f.write("")
        except Exception as e:
            print(f"System logging rotation failed: {str(e)}")

def write_log(action_details, register_name="Global System", register_ip="N/A"):
    """
    Assembles and appends a structured audit entry including the client computer name.
    """
    check_and_rotate_logs()
    
    # Capture accessing client IP (inspect proxy headers first)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip and ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()
        
    # Perform a reverse DNS lookup to extract the client's computer name (hostname)
    client_hostname = "Unknown"
    if client_ip:
        try:
            # We set a temporary socket timeout to prevent slow DNS queries from delaying the log write
            socket.setdefaulttimeout(1.5)
            client_hostname = socket.gethostbyaddr(client_ip)[0]
        except Exception:
            client_hostname = "Unknown"
        
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_entry = (
        f"[{timestamp}] "
        f"Client_IP: {client_ip} | "
        f"Client_Host: {client_hostname} | "
        f"Reg_Name: {register_name} | "
        f"Reg_IP: {register_ip} | "
        f"Action: {action_details}\n"
    )
    
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Failed to record change log entry: {str(e)}")

# =====================================================================
# Config File Operations (JSON Persistence)
# =====================================================================
def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "admin_password": "admin",
            "registers": []
        }
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {"admin_password": "admin", "registers": []}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

load_config()

def verify_admin_password():
    client_pwd = request.headers.get("X-Admin-Password")
    config = load_config()
    return client_pwd == config["admin_password"]

# =====================================================================
# Datecs DP-150MX Controller Class (Romanian Fiscal Edition)
# =====================================================================
class DatecsDP150Controller:
    SEP = b"\t"
    
    def __init__(self, ip: str, port: int = 3999):
        self.ip = ip
        self.port = port
        self.seq = 0x20

    def _get_and_increment_seq(self) -> int:
        current = self.seq
        self.seq = 0x20 + ((self.seq - 0x20 + 1) % 96)
        return current

    def _encode_to_4_bytes(self, value: int) -> bytes:
        n1 = (value >> 12) & 0x0F
        n2 = (value >> 8) & 0x0F
        n3 = (value >> 4) & 0x0F
        n4 = value & 0x0F
        return bytes([n1 + 0x30, n2 + 0x30, n3 + 0x30, n4 + 0x30])

    def calculate_bcc(self, data: bytes) -> bytes:
        checksum = sum(data) & 0xFFFF
        return self._encode_to_4_bytes(checksum)

    def make_packet(self, cmd_word: int, data_payload: bytes = b"") -> bytes:
        seq_byte = self._get_and_increment_seq()
        cmd_bytes = self._encode_to_4_bytes(cmd_word)
        len_val = len(data_payload) + 10 + 0x20
        len_bytes = self._encode_to_4_bytes(len_val)
        
        payload = len_bytes + bytes([seq_byte]) + cmd_bytes + data_payload + b'\x05'
        bcc = self.calculate_bcc(payload)
        return b'\x01' + payload + bcc + b'\x03'

    def send_command(self, cmd_word: int, data_payload: bytes = b"") -> bytes:
        packet = self.make_packet(cmd_word, data_payload)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.5)
                s.connect((self.ip, self.port))
                s.sendall(packet)
                
                buffer = b""
                while True:
                    chunk = s.recv(1)
                    if not chunk:
                        break
                    if chunk == b'\x16':
                        continue
                    if chunk == b'\x15':
                        raise ConnectionError("Device returned NAK. Checksum or frame layout was rejected.")
                    buffer += chunk
                    if len(buffer) > 0 and buffer[0] == 0x01 and buffer[-1] == 0x03:
                        return buffer
                if not buffer:
                    raise ConnectionError("Empty response received from the register.")
                return buffer
        except socket.timeout:
            raise ConnectionError("Connection timeout.")
        except Exception as e:
            raise ConnectionError(f"Error: {str(e)}")

    def _parse_response_raw(self, response: bytes) -> bytes:
        if len(response) < 5:
            return b""
        is_4_byte_len = all(0x30 <= b <= 0x3F for b in response[1:5])
        is_4_byte_cmd = all(0x30 <= b <= 0x3F for b in response[6:10]) if len(response) >= 10 else False
        
        data_start_idx = 10 if (is_4_byte_len and is_4_byte_cmd) else (7 if is_4_byte_len else 4)
        
        idx_04 = response.find(b'\x04')
        if idx_04 != -1:
            return response[data_start_idx:idx_04]
        idx_05 = response.find(b'\x05')
        if idx_05 != -1:
            return response[data_start_idx:idx_05]
        return b""

    def read_date_time(self) -> str:
        """Command 62 (0x003E): Read Date and Time."""
        response = self.send_command(0x003E)
        raw_data = self._parse_response_raw(response)
        parts = raw_data.split(self.SEP)
        if len(parts) >= 2:
            return parts[1].decode('ascii', errors='replace')
        return raw_data.decode('ascii', errors='replace')

    def set_date_time(self, dt_str: str, use_dst: bool) -> str:
        """Command 61 (0x003D): Set Manual Date and Time."""
        dt_obj = datetime.datetime.strptime(dt_str, "%Y-%m-%dT%H:%M")
        dst_suffix = " DST" if use_dst else ""
        time_str = dt_obj.strftime(f"%d-%m-%y %H:%M:00{dst_suffix}").encode('ascii')
        data_payload = time_str + self.SEP
        
        response = self.send_command(0x003D, data_payload)
        raw_data = self._parse_response_raw(response)
        parts = raw_data.split(self.SEP)
        if len(parts) >= 1:
            code = parts[0].decode('ascii')
            return "Success" if code == "0" else f"Error Code: {code}"
        return raw_data.decode('ascii', errors='replace')

    def read_vat_rates_raw(self) -> list:
        """Command 50 (0x0032): Return list of raw active VAT rates (Romania TaxA to TaxE)."""
        response = self.send_command(0x0032)
        raw_data = self._parse_response_raw(response)
        parts = raw_data.split(self.SEP)
        rates = []
        if len(parts) >= 7:
            for b in parts[2:7]:
                try:
                    rates.append(float(b.decode('ascii')))
                except ValueError:
                    rates.append(100.02)
        else:
            rates = [100.02] * 5
        return rates

    def set_vat_rates(self, rates: list) -> str:
        """Command 83 (0x0053): Program VAT rates (Romania expects 5 parameters)."""
        padded_rates = rates[:5]
        if len(padded_rates) < 5:
            padded_rates += [100.02] * (5 - len(padded_rates))
            
        params = [f"{rate:.2f}".encode('ascii') for rate in padded_rates]
        data_payload = self.SEP.join(params) + self.SEP
        
        response = self.send_command(0x0053, data_payload)
        raw_data = self._parse_response_raw(response)
        parts = raw_data.split(self.SEP)
        if len(parts) >= 1:
            code = parts[0].decode('ascii')
            return "Success" if code == "0" else f"Error Code: {code}"
        return raw_data.decode('ascii', errors='replace')

# =====================================================================
# Flask JSON APIs
# =====================================================================

@app.route("/api/registers", methods=["GET"])
def get_registers():
    config = load_config()
    return jsonify(config["registers"])

@app.route("/api/registers", methods=["POST"])
def add_register():
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid admin password"}), 401
        
    data = request.json
    config = load_config()
    
    new_id = max([r["id"] for r in config["registers"]], default=0) + 1
    new_reg = {
        "id": new_id,
        "name": data.get("name"),
        "ip_address": data.get("ip_address"),
        "port": int(data.get("port", 3999))
    }
    
    config["registers"].append(new_reg)
    save_config(config)
    
    write_log(f"Added new register configuration: {new_reg['name']} ({new_reg['ip_address']}:{new_reg['port']})", new_reg['name'], new_reg['ip_address'])
    return jsonify({"status": "ok"})

@app.route("/api/registers/<int:reg_id>", methods=["PUT"])
def update_register(reg_id):
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid admin password"}), 401
        
    data = request.json
    config = load_config()
    
    found = False
    for r in config["registers"]:
        if r["id"] == reg_id:
            r["name"] = data.get("name")
            r["ip_address"] = data.get("ip_address")
            r["port"] = int(data.get("port", 3999))
            found = True
            write_log(f"Modified configuration of register to: {r['name']} ({r['ip_address']}:{r['port']})", r['name'], r['ip_address'])
            break
            
    if not found:
        return jsonify({"error": "Register not found"}), 404
        
    save_config(config)
    return jsonify({"status": "ok"})

@app.route("/api/registers/<int:reg_id>", methods=["DELETE"])
def delete_register(reg_id):
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid admin password"}), 401
        
    config = load_config()
    reg = next((r for r in config["registers"] if r["id"] == reg_id), None)
    initial_count = len(config["registers"])
    config["registers"] = [r for r in config["registers"] if r["id"] != reg_id]
    
    if len(config["registers"]) == initial_count:
        return jsonify({"error": "Register not found"}), 404
        
    save_config(config)
    if reg:
        write_log("Deleted register configuration from system inventory", reg['name'], reg['ip_address'])
    return jsonify({"status": "ok"})

@app.route("/api/registers/<int:reg_id>/status", methods=["GET"])
def get_register_status(reg_id):
    config = load_config()
    reg = next((r for r in config["registers"] if r["id"] == reg_id), None)
    
    if not reg:
        return jsonify({"error": "Register not found"}), 404
        
    try:
        device = DatecsDP150Controller(reg["ip_address"], reg["port"])
        time_str = device.read_date_time()
        vat_list = device.read_vat_rates_raw()
        return jsonify({
            "status": "Online",
            "time": time_str,
            "vat_raw": vat_list
        })
    except Exception as e:
        return jsonify({
            "status": "Offline",
            "error": str(e)
        })

@app.route("/api/registers/<int:reg_id>/set-time", methods=["POST"])
def set_register_time(reg_id):
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid admin password"}), 401
        
    data = request.json
    dt_str = data.get("datetime")
    use_dst = bool(data.get("dst", False))
    
    config = load_config()
    reg = next((r for r in config["registers"] if r["id"] == reg_id), None)
    
    if not reg:
        return jsonify({"error": "Register not found"}), 404
        
    try:
        device = DatecsDP150Controller(reg["ip_address"], reg["port"])
        result = device.set_date_time(dt_str, use_dst)
        write_log(f"Set Manual Date & Time to: {dt_str} (DST: {use_dst}) | Result: {result}", reg['name'], reg['ip_address'])
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/registers/<int:reg_id>/set-vat", methods=["POST"])
def set_register_vat(reg_id):
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid admin password"}), 401
        
    data = request.json
    rates = [float(r) for r in data.get("rates", [])]
    
    config = load_config()
    reg = next((r for r in config["registers"] if r["id"] == reg_id), None)
    
    if not reg:
        return jsonify({"error": "Register not found"}), 404
        
    try:
        device = DatecsDP150Controller(reg["ip_address"], reg["port"])
        result = device.set_vat_rates(rates)
        write_log(f"Wrote Programmed VAT Rates to: {rates} | Result: {result}", reg['name'], reg['ip_address'])
        return jsonify({"result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/settings/change-password", methods=["POST"])
def change_password():
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid old password"}), 401
        
    data = request.json
    new_pwd = data.get("new_password")
    if not new_pwd:
        return jsonify({"error": "Invalid password string"}), 400
        
    config = load_config()
    config["admin_password"] = new_pwd
    save_config(config)
    
    write_log("Administrative system password updated.")
    return jsonify({"status": "ok"})

@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    Parses active.log line-by-line and returns structured JSON output.
    Accessible only with a valid X-Admin-Password.
    """
    if not verify_admin_password():
        return jsonify({"error": "Unauthorized: Invalid admin password"}), 401
        
    ensure_log_dir()
    log_entries = []
    
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
                
            # Reverse lines to display the newest events at the top
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    # Expected format: [timestamp] Client_IP: ... | Client_Host: ... | Reg_Name: ... | Reg_IP: ... | Action: ...
                    parts = line.split(" | ")
                    timestamp_part = parts[0].split("] ")[0].replace("[", "")
                    client_ip = parts[0].split("Client_IP: ")[1]
                    client_host = parts[1].split("Client_Host: ")[1]
                    reg_name = parts[2].split("Reg_Name: ")[1]
                    reg_ip = parts[3].split("Reg_IP: ")[1]
                    action = parts[4].split("Action: ")[1]
                    
                    log_entries.append({
                        "timestamp": timestamp_part,
                        "client_ip": client_ip,
                        "client_host": client_host,
                        "reg_name": reg_name,
                        "reg_ip": reg_ip,
                        "action": action
                    })
                except Exception:
                    # Fallback for manually appended custom lines
                    log_entries.append({
                        "timestamp": "N/A",
                        "client_ip": "N/A",
                        "client_host": "N/A",
                        "reg_name": "N/A",
                        "reg_ip": "N/A",
                        "action": line
                    })
        except Exception as e:
            return jsonify({"error": f"Failed to parse active log: {str(e)}"}), 500
            
    return jsonify(log_entries)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
