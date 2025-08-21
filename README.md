# Python SMS Tool for 3G/4G/5G Modems

A comprehensive Python implementation of SMS functionality for 3G/4G/5G modems, with special support for RM520N-GL modems.

## Features

- ✅ **Send SMS messages** with Unicode/emoji/Chinese/CJK support
- ✅ **Receive and decode SMS messages** from SIM and modem storage
- ✅ **Multipart SMS support** with automatic assembly
- ✅ **Delete SMS messages** individually or in bulk
- ✅ **USSD queries** for balance checks and service codes
- ✅ **Modem reset** functionality for RM520N-GL
- ✅ **Raw AT command** interface for debugging
- ✅ **JSON output** format for integration
- ✅ **Multiple storage support** (SIM card and modem memory)
- ✅ **Auto-delete after fetch** option

## Installation

### Requirements
- Python 3.6+
- `pyserial` library

```bash
pip install pyserial
```

### Download
Clone this repo.

## Quick Start

### Command Line Usage

```bash
# Send SMS (supports Chinese, emoji, and all Unicode)
python3 pysms_tool.py -d /dev/ttyUSB2 send "+1234567890" "Hello World! 你好世界 🌍"

# Receive messages
python3 pysms_tool.py -d /dev/ttyUSB2 recv

# Receive with multipart assembly
python3 pysms_tool.py -d /dev/ttyUSB2 -A recv

# Get JSON output
python3 pysms_tool.py -d /dev/ttyUSB2 -j recv

# Check balance via USSD
python3 pysms_tool.py -d /dev/ttyUSB2 ussd "*100#"

# Reset modem (RM520N-GL)
python3 pysms_tool.py -d /dev/ttyUSB2 reset
```

### Python Module Usage

```python
from pysms_tool import SMSTool

# Create SMS tool instance
sms = SMSTool(device="/dev/ttyUSB2", debug=True)

# Send SMS
sms.send_sms("+1234567890", "Hello from Python!")

# Get all messages from both SIM and modem storage
messages = sms.get_all_messages(storage_types=["SM", "ME"])

for msg in messages:
    decoded = msg['decoded']
    print(f"From: {decoded['sender']}")
    print(f"Message: {decoded['message']}")
    if 'reference' in decoded:
        print(f"Part {decoded['part']}/{decoded['total']}")

# Reset modem
sms.reset_modem()
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --device` | TTY device path (default: /dev/ttyUSB0) |
| `-b, --baudrate` | Serial baudrate (default: 115200) |
| `-D, --debug` | Enable debug mode |
| `-j, --json` | JSON output format |
| `-A, --assemble` | Assemble multipart SMS messages |
| `--all-storage` | Fetch from both SIM (SM) and modem (ME) storage |
| `--delete-after` | Delete messages after fetching |
| `-r, --raw-output` | Raw PDU output |
| `-s, --storage` | Preferred storage (SM/ME/MT) |

## Commands

| Command | Description | Examples |
|---------|-------------|----------|
| `send` | Send SMS to phone number | `send "+1234567890" "Hello"` |
| `recv` | Receive SMS messages | `recv` |
| `delete` | Delete SMS by index or all | `delete 5` or `delete all` |
| `status` | Show modem storage status | `status` |
| `ussd` | Send USSD code | `ussd "*100#"` |
| `at` | Send raw AT command | `at "AT+CIMI"` |
| `reset` | Factory reset RM520N-GL modem | `reset` |

## Advanced Examples

### Multipart SMS Assembly
```bash
# Regular receive (shows individual parts)
python3 pysms_tool.py -d /dev/ttyUSB2 -j recv

# Assembled receive (combines parts into complete messages)
python3 pysms_tool.py -d /dev/ttyUSB2 -A -j recv
```

### Fetch and Delete
```bash
# Fetch from all storage and delete after reading
python3 pysms_tool.py -d /dev/ttyUSB2 --all-storage --delete-after recv
```

### Integration Example
```bash
# Get messages in JSON, assemble multipart, and pipe to another tool
python3 pysms_tool.py -d /dev/ttyUSB2 -A -j recv | jq '.msg[] | select(.type=="multipart")'
```

## Demo Script

Run the interactive demo to explore features:

```bash
# Interactive menu
python3 demo.py interactive

# Quick demos
python3 demo.py basic
python3 demo.py send "+1234567890" "Test message"
python3 demo.py ussd "*100#"
```

## API Reference

### SMSTool Class

#### Constructor
```python
SMSTool(device="/dev/ttyUSB0", baudrate=115200, debug=False, storage="", dateformat="%m/%d/%y %H:%M:%S", gsm_mode=False)
```

#### Methods

**send_sms(phone: str, message: str) -> bool**
- Send SMS to specified phone number
- Supports Unicode/emoji/Chinese/CJK characters via UCS2 encoding

**get_all_messages(storage_types: List[str] = None, delete_after: bool = False) -> List[Dict]**
- Get decoded messages from specified storage types
- Returns list of message dictionaries with decoded content

**receive_sms(json_output: bool = False, raw_output: bool = False, storage_types: List[str] = None, delete_after: bool = False) -> bool**
- Print received messages to stdout
- Supports JSON and raw PDU output formats

**receive_sms_assembled(json_output: bool = False, storage_types: List[str] = None, delete_after: bool = False) -> bool**
- Print received messages with multipart SMS assembled
- Groups message parts by sender and reference number

**reset_modem() -> bool**
- Factory reset RM520N-GL modem
- Sends AT+QCFG="ResetFactory" command

**send_ussd(code: str, raw_input: bool = False, raw_output: bool = False) -> bool**
- Send USSD code for service queries

**delete_sms(index: str) -> bool**
- Delete SMS by index number or "all"

**get_status() -> bool**
- Display SMS storage status

**send_at_command(command: str) -> bool**
- Send raw AT command to modem

## Message Format

### Raw Message Dictionary
```python
{
    'index': 1,              # Message index in storage
    'storage': 'SM',         # Storage location (SM/ME)
    'pdu': '07915...',       # Raw PDU data
    'decoded': {             # Decoded message data
        'sender': '+1234567890',
        'timestamp': '2025/08/21 23:35:05 GMT+08:00',
        'message': 'Hello World',
        'reference': 202,    # Present for multipart SMS
        'part': 1,           # Part number (1-based)
        'total': 3           # Total parts
    }
}
```

### Assembled Message Types
- **single**: Regular SMS message
- **multipart**: Complete assembled message from multiple parts  
- **incomplete**: Multipart message missing some parts

## Modem Compatibility

### Tested Modems
- ✅ **RM520N-GL** - Full support including factory reset
- ✅ **RM500U** - Basic SMS functionality
- ⚠️ **Other Quectel modems** - Should work with basic features

### AT Commands Used
- `AT+CMGF` - Set SMS format (PDU/Text mode)
- `AT+CMGS` - Send SMS
- `AT+CMGL` - List SMS messages
- `AT+CMGD` - Delete SMS messages
- `AT+CPMS` - Set/query SMS storage
- `AT+CUSD` - Send USSD commands
- `AT+QCFG="ResetFactory"` - Factory reset (RM520N-GL)

## Troubleshooting

### Common Issues

**"No response from modem"**
- Check device path (`ls /dev/ttyUSB*`)
- Verify modem is not being used by another process
- Try different baudrate with `-b` option

**"Permission denied"**
- Add user to dialout group: `sudo usermod -a -G dialout $USER`
- Or run with sudo (not recommended)

**"Cannot decode SMS"**
- Enable debug mode with `-D` to see raw PDU data
- Some messages may use unsupported encoding

**Multipart SMS not assembling**
- Use `-A` flag for assembly
- Check that all parts were received
- Debug with `-D` to see reference numbers

### Debug Mode
```bash
# Enable debug to see AT commands and responses
python3 pysms_tool.py -d /dev/ttyUSB2 -D recv
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## License

MIT License - See LICENSE file for details

## Credits

Based on the C implementation by Cezary Jackiewicz and lovewilliam. Rewritten in Python with additional features and RM520N-GL support.
