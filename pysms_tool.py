#!/usr/bin/env python3
"""
SMS Tool for 3G/4G/5G Modem - Python Version
===========================================

Based on the C implementation by Cezary Jackiewicz and lovewilliam

DESCRIPTION:
    This tool provides comprehensive SMS and modem management functionality:
    • Send SMS messages via 3G/4G/5G modems
    • Receive and decode SMS messages  
    • Delete SMS messages from storage
    • Check modem and storage status
    • Send USSD codes for service queries
    • Send raw AT commands for debugging

USAGE:
    python3 sms_tool_python.py [OPTIONS] COMMAND [ARGUMENTS]

COMMANDS:
    send <phone> <message>  Send SMS to specified phone number
    recv                    Receive and display SMS messages
    delete <index|all>      Delete SMS by index or all messages
    status                  Show modem storage status
    ussd <code>            Send USSD code (e.g., *100# for balance)
    at <command>           Send raw AT command to modem
    reset                  Factory reset RM520N-GL modem

OPTIONS:
    -b, --baudrate <rate>      Serial baudrate (default: 115200)
    -d, --device <device>      TTY device path (default: /dev/ttyUSB0)
    -D, --debug               Enable debug mode for ussd/at commands
    -f, --dateformat <fmt>    Date/time format string (default: %m/%d/%y %H:%M:%S)
    -j, --json                JSON output format for recv command
    -R, --raw-input           Use raw input for ussd commands
    -r, --raw-output          Use raw output for ussd/recv commands
    -s, --storage <type>      SMS storage type (SM/ME/MT for recv/status)

EXAMPLES:
    # Send SMS
    python3 sms_tool_python.py -d /dev/ttyUSB2 send +1234567890 "Hello World"
    
    # Check balance via USSD
    python3 sms_tool_python.py -d /dev/ttyUSB2 ussd "*100#"
    
    # Receive messages in JSON format
    python3 sms_tool_python.py -d /dev/ttyUSB2 -j recv
    
    # Receive and assemble multipart messages
    python3 sms_tool_python.py -d /dev/ttyUSB2 -A recv
    
    # Fetch from both SIM and modem storage, delete after
    python3 sms_tool_python.py -d /dev/ttyUSB2 --all-storage --delete-after recv
    
    # Check storage status
    python3 sms_tool_python.py -d /dev/ttyUSB2 status
    
    # Delete all messages
    python3 sms_tool_python.py -d /dev/ttyUSB2 delete all
    
    # Reset modem to factory settings
    python3 sms_tool_python.py -d /dev/ttyUSB2 reset
"""

import argparse
import serial
import time
import sys
import json
import signal
import re
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any


class SMSCharset:
    GSM_7BIT = 0
    BINARY_8BIT = 1
    UCS2 = 2


class PDUDecoder:
    """PDU encoding/decoding functionality"""
    
    @staticmethod
    def swap_decimal_nibble(x: int) -> int:
        """Swap decimal digits of a number (e.g. 12 -> 21)"""
        return (x // 16) + ((x % 16) * 10)
    
    @staticmethod
    def encode_7bit(text: str) -> bytes:
        """Encode text using GSM 7-bit encoding"""
        if len(text) > 160:
            raise ValueError("SMS message too long")
        
        output = bytearray()
        carry = 0
        carry_bits = 0
        
        for char in text:
            char_code = ord(char) & 0x7F
            
            # Combine character with carry from previous iteration
            byte_val = ((char_code << carry_bits) | carry) & 0xFF
            output.append(byte_val)
            
            # Update carry for next iteration
            carry = char_code >> (7 - carry_bits)
            carry_bits += 1
            
            # If carry has accumulated 7 bits, it forms a complete character
            if carry_bits == 7:
                carry = 0
                carry_bits = 0
            
        return bytes(output)
    
    @staticmethod
    def decode_7bit(data: bytes, length: int) -> str:
        """Decode GSM 7-bit encoded data"""
        output = []
        carry = 0
        carry_bits = 0
        
        for i, byte_val in enumerate(data):
            if len(output) >= length:
                break
                
            # Extract character from current byte and carry
            char_val = ((byte_val << carry_bits) | carry) & 0x7F
            output.append(chr(char_val))
            
            # Update carry for next iteration
            carry = byte_val >> (7 - carry_bits)
            carry_bits += 1
            
            # If we have enough carry bits for a full character
            if carry_bits == 7:
                if len(output) < length:
                    output.append(chr(carry & 0x7F))
                carry = 0
                carry_bits = 0
                
        return ''.join(output[:length])
    
    @staticmethod
    def encode_phone_number(phone: str) -> bytes:
        """Encode phone number for PDU"""
        if phone.startswith('+'):
            ton_npi = 0x91  # International format
            phone = phone[1:]
        else:
            ton_npi = 0x81  # Unknown format
            
        # Pad with F if odd length
        if len(phone) % 2:
            phone += 'F'
            
        # Swap digit pairs
        encoded = bytearray()
        for i in range(0, len(phone), 2):
            digit1 = phone[i]
            digit2 = phone[i + 1] if i + 1 < len(phone) else 'F'
            encoded.append(int(digit2 + digit1, 16))
            
        return bytes([len(phone.rstrip('F')), ton_npi] + list(encoded))
    
    @staticmethod
    def decode_phone_number(data: bytes, offset: int) -> Tuple[str, int]:
        """Decode phone number from PDU"""
        length = data[offset]
        ton_npi = data[offset + 1]
        
        # Calculate number of bytes needed
        num_bytes = (length + 1) // 2
        phone_bytes = data[offset + 2:offset + 2 + num_bytes]
        
        phone = ''
        for byte_val in phone_bytes:
            digit1 = byte_val & 0x0F
            digit2 = (byte_val & 0xF0) >> 4
            
            if digit1 != 0xF:
                phone += str(digit1)
            if digit2 != 0xF:
                phone += str(digit2)
                
        if len(phone) > length:
            phone = phone[:length]
            
        if ton_npi == 0x91:
            phone = '+' + phone
            
        return phone, offset + 2 + num_bytes
    
    @staticmethod
    def decode_timestamp(data: bytes, offset: int) -> Tuple[str, int]:
        """Decode timestamp from PDU"""
        timestamp_bytes = data[offset:offset + 7]
        
        # Each byte represents two digits in swapped format
        year = PDUDecoder.swap_decimal_nibble(timestamp_bytes[0])
        month = PDUDecoder.swap_decimal_nibble(timestamp_bytes[1])
        day = PDUDecoder.swap_decimal_nibble(timestamp_bytes[2])
        hour = PDUDecoder.swap_decimal_nibble(timestamp_bytes[3])
        minute = PDUDecoder.swap_decimal_nibble(timestamp_bytes[4])
        second = PDUDecoder.swap_decimal_nibble(timestamp_bytes[5])
        
        # Timezone is in quarters of an hour
        tz_byte = timestamp_bytes[6]
        tz_quarters = PDUDecoder.swap_decimal_nibble(tz_byte & 0x7F)
        tz_sign = '-' if (tz_byte & 0x08) else '+'
        
        timestamp = f"20{year:02d}/{month:02d}/{day:02d} {hour:02d}:{minute:02d}:{second:02d} GMT{tz_sign}{tz_quarters//4:02d}:{(tz_quarters%4)*15:02d}"
        
        return timestamp, offset + 7
    
    @staticmethod
    def decode_message_text(data: bytes, offset: int, length: int, dcs: int) -> str:
        """Decode message text based on data coding scheme"""
        if dcs == 0x00:
            # GSM 7-bit encoding
            return PDUDecoder.decode_7bit(data[offset:], length)
        elif dcs == 0x08:
            # UCS2 encoding (UTF-16BE)
            try:
                # Length is in bytes for UCS2
                ucs2_data = data[offset:offset + length]
                return ucs2_data.decode('utf-16be')
            except UnicodeDecodeError:
                return f"[UCS2 decode error: {data[offset:offset + length].hex()}]"
        else:
            # Unknown encoding
            return f"[Unknown encoding DCS={dcs:02X}: {data[offset:offset + length].hex()}]"
    
    @staticmethod
    def decode_pdu(pdu_hex: str) -> Dict[str, Any]:
        """Decode a complete SMS PDU"""
        try:
            # Convert hex string to bytes
            pdu = bytes.fromhex(pdu_hex)
            offset = 0
            
            # SMSC length and number
            smsc_len = pdu[offset]
            offset += 1 + smsc_len
            
            # PDU type
            pdu_type = pdu[offset]
            offset += 1
            
            # Sender address
            sender, offset = PDUDecoder.decode_phone_number(pdu, offset)
            
            # Protocol identifier
            pid = pdu[offset]
            offset += 1
            
            # Data coding scheme
            dcs = pdu[offset]
            offset += 1
            
            # Service center timestamp
            timestamp, offset = PDUDecoder.decode_timestamp(pdu, offset)
            
            # User data length
            udl = pdu[offset]
            offset += 1
            
            # User data header (if present)
            reference = None
            part = None
            total = None
            
            if pdu_type & 0x40:  # UDHI bit set
                udhl = pdu[offset]
                offset += 1
                udh_start = offset
                udh_end = offset + udhl
                
                # Parse User Data Header
                while offset < udh_end:
                    ie_id = pdu[offset]
                    ie_len = pdu[offset + 1]
                    ie_data = pdu[offset + 2:offset + 2 + ie_len]
                    
                    if ie_id == 0x00 and ie_len == 3:  # Concatenated SMS header
                        reference = ie_data[0]
                        total = ie_data[1]
                        part = ie_data[2]
                    elif ie_id == 0x08 and ie_len == 4:  # Concatenated SMS 16-bit reference
                        reference = (ie_data[0] << 8) | ie_data[1]
                        total = ie_data[2]
                        part = ie_data[3]
                    
                    offset += 2 + ie_len
                
                udl -= udhl + 1
            
            # Message text
            message = PDUDecoder.decode_message_text(pdu, offset, udl, dcs)
            
            result = {
                'sender': sender,
                'timestamp': timestamp,
                'message': message,
                'pdu_type': pdu_type,
                'dcs': dcs
            }
            
            # Add multipart SMS fields if present
            if reference is not None:
                result['reference'] = reference
            if part is not None:
                result['part'] = part
            if total is not None:
                result['total'] = total
            
            return result
            
        except Exception as e:
            return {
                'sender': '[Decode error]',
                'timestamp': '[Decode error]',
                'message': f'[PDU decode failed: {str(e)}]',
                'pdu_type': 0,
                'dcs': 0
            }
    
    @staticmethod
    def encode_pdu(phone: str, message: str) -> str:
        """Encode SMS message to PDU format"""
        pdu = bytearray()
        
        # SMSC length (0 for default)
        pdu.append(0x00)
        
        # PDU type (SMS-SUBMIT)
        pdu.append(0x11)
        
        # Message reference (let network assign)
        pdu.append(0x00)
        
        # Destination address
        phone_encoded = PDUDecoder.encode_phone_number(phone)
        pdu.extend(phone_encoded)
        
        # Protocol identifier
        pdu.append(0x00)
        
        # Data coding scheme (7-bit)
        pdu.append(0x00)
        
        # User data length
        pdu.append(len(message))
        
        # User data (7-bit encoded)
        message_encoded = PDUDecoder.encode_7bit(message)
        pdu.extend(message_encoded)
        
        return pdu.hex().upper()


class SMSTool:
    """Main SMS tool class"""
    
    def __init__(self, device: Optional[str] = "/dev/ttyUSB0", baudrate: int = 115200, 
                 debug: bool = False, storage: str = "", dateformat: str = "%m/%d/%y %H:%M:%S",
                 gsm_mode: bool = False, serial_port: Optional[serial.Serial] = None):
        self.device = device
        self.baudrate = baudrate
        self.debug = debug
        self.storage = storage
        self.dateformat = dateformat
        self.gsm_mode = gsm_mode
        
        # If a serial port object is provided, use it directly
        if serial_port is not None:
            self.serial_port = serial_port
            self._external_serial = True
            # Override device path since we're using external serial
            self.device = getattr(serial_port, 'port', 'external_serial')
        else:
            self.serial_port = None
            self._external_serial = False
        
        # Set up signal handler for timeout
        signal.signal(signal.SIGALRM, self._timeout_handler)
    
    def _timeout_handler(self, signum, frame):
        """Handle timeout signal"""
        print("No response from modem.", file=sys.stderr)
        sys.exit(2)
    
    def _open_serial(self):
        """Open serial connection to modem"""
        # If using external serial object, check if it's already open
        if self._external_serial:
            if self.serial_port and not self.serial_port.is_open:
                try:
                    self.serial_port.open()
                    time.sleep(0.1)  # Allow port to stabilize
                except Exception as e:
                    print(f"Failed to open external serial port: {e}", file=sys.stderr)
                    sys.exit(1)
            elif not self.serial_port:
                print("External serial port is None", file=sys.stderr)
                sys.exit(1)
            return
        
        # Original behavior for device path strings
        try:
            self.serial_port = serial.Serial(
                port=self.device,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )
            time.sleep(0.1)  # Allow port to stabilize
        except Exception as e:
            print(f"Failed to open {self.device}: {e}", file=sys.stderr)
            sys.exit(1)
    
    def _close_serial(self):
        """Close serial connection"""
        # Don't close external serial objects - let the caller manage them
        if self._external_serial:
            return
        
        # Original behavior for internally created serial connections
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
    
    def _send_command(self, command: str) -> str:
        """Send AT command and return response"""
        if not self.serial_port:
            raise RuntimeError("Serial port not open")
        
        # Debug output for sent command with blue background
        if self.debug:
            print(f"\033[44m[SEND] {command}\033[0m", file=sys.stderr)
        
        self.serial_port.write((command + '\r\n').encode('utf-8'))
        
        response_lines = []
        while True:
            line = self.serial_port.readline().decode(errors='ignore').strip()
            if not line:
                continue
            
            # Debug output for received response with yellow background
            if self.debug:
                print(f"\033[43m[RECV] {line}\033[0m", file=sys.stderr)
            
            if line in ('OK', 'ERROR') or line.startswith('+CMS ERROR:') or line.startswith('+CME ERROR:'):
                response_lines.append(line)
                break
            response_lines.append(line)
        
        return '\n'.join(response_lines)
    
    def _wait_for_response(self, timeout: int = 5) -> List[str]:
        """Wait for response lines from modem"""
        signal.alarm(timeout)
        responses = []
        
        try:
            while True:
                line = self.serial_port.readline().decode(errors='ignore').strip()
                if not line:
                    continue
                
                # Debug output for received response with yellow background
                if self.debug:
                    print(f"\033[43m[RECV] {line}\033[0m", file=sys.stderr)
                
                responses.append(line)
                if line in ('OK', 'ERROR') or line.startswith('+CMS ERROR:') or line.startswith('+CME ERROR:'):
                    break
        finally:
            signal.alarm(0)
        
        return responses
    
    def send_sms(self, phone: str, message: str) -> bool:
        """Send SMS message using UCS2 or GSM encoding"""
        if self.gsm_mode:
            # GSM mode - ASCII only, 160 character limit
            if len(message) > 160:
                print(f"SMS message too long: {len(message)} chars (max 160 for GSM)", file=sys.stderr)
                return False
            
            # Check for non-ASCII characters
            if any(ord(c) > 127 for c in message):
                print("Warning: Non-ASCII characters detected in GSM mode, may not display correctly", file=sys.stderr)
        else:
            # UCS2 mode - check message length for UCS2 encoding
            try:
                utf16_bytes = message.encode('utf-16be')
                # SMS limit is 140 bytes for UCS2 (70 UTF-16 characters)
                if len(utf16_bytes) > 140:
                    print(f"SMS message too long: {len(utf16_bytes)} bytes (max 140 bytes for UCS2)", file=sys.stderr)
                    return False
            except UnicodeEncodeError:
                print(f"Cannot encode message: {message}", file=sys.stderr)
                return False
        
        self._open_serial()
        try:
            # Use text mode
            self._send_command("AT+CMGF=1")
            
            if self.gsm_mode:
                # Set character set to GSM
                self._send_command('AT+CSCS="GSM"')
                
                # Send CMGS command with phone number
                cmd = f'AT+CMGS="{phone}"'
                if self.debug:
                    print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
                self.serial_port.write((cmd + '\r\n').encode('utf-8'))
                time.sleep(1)
                
                # Send message with Ctrl-Z
                if self.debug:
                    print(f"\033[44m[SEND] {message}<CTRL-Z>\033[0m", file=sys.stderr)
                self.serial_port.write((message + '\x1A').encode('utf-8'))
            else:
                # Set character set to UCS2
                self._send_command('AT+CSCS="UCS2"')
                
                # Set SMS parameters for UCS2
                self._send_command('AT+CSMP=17,167,0,25')
                
                # Encode phone number to UCS2
                phone_ucs2 = ''.join(f'{ord(c):04X}' for c in phone)
                
                # Send CMGS command with UCS2 encoded phone number
                cmd = f'AT+CMGS="{phone_ucs2}"'
                if self.debug:
                    print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
                self.serial_port.write((cmd + '\r\n').encode('utf-8'))
                time.sleep(1)
                
                # Encode message to UCS2/UTF-16BE (handle emojis with surrogate pairs)
                try:
                    # Encode to UTF-16BE and convert to hex string
                    utf16_bytes = message.encode('utf-16be')
                    message_ucs2 = utf16_bytes.hex().upper()
                except UnicodeEncodeError:
                    print(f"Cannot encode message to UCS2: {message}", file=sys.stderr)
                    return False
                
                # Send UCS2 encoded message with Ctrl-Z
                if self.debug:
                    print(f"\033[44m[SEND] {message_ucs2}<CTRL-Z>\033[0m", file=sys.stderr)
                self.serial_port.write((message_ucs2 + '\x1A').encode('utf-8'))
            
            responses = self._wait_for_response()
            
            for response in responses:
                if response.startswith('+CMGS:'):
                    print(f"SMS sent successfully: {response[7:]}")
                    return True
                elif response.startswith('+CMS ERROR:'):
                    print(f"SMS not sent, error code: {response[11:]}", file=sys.stderr)
                    return False
                elif response == 'ERROR':
                    print("SMS not sent, command error", file=sys.stderr)
                    return False
            
            return False
            
        finally:
            self._close_serial()
    
    def _get_messages_from_storage(self, storage_type: str, delete_after: bool = False) -> List[Dict]:
        """Internal method to get messages from specific storage"""
        # Set storage
        self._send_command(f'AT+CPMS="{storage_type}"')
        
        # Set PDU mode
        self._send_command("AT+CMGF=0")
        
        # List all messages
        cmd = "AT+CMGL=4"
        if self.debug:
            print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
        self.serial_port.write((cmd + "\r\n").encode())
        
        messages = []
        current_msg = None
        
        responses = self._wait_for_response(10)
        
        for response in responses:
            if response.startswith('+CMGL:'):
                # Parse message header
                match = re.match(r'\+CMGL:\s*(\d+),', response)
                if match:
                    if current_msg:
                        messages.append(current_msg)
                    current_msg = {'index': int(match.group(1)), 'storage': storage_type}
            elif current_msg and response and not response in ('OK', 'ERROR'):
                # This should be the PDU data
                current_msg['pdu'] = response
        
        if current_msg:
            messages.append(current_msg)
        
        # Decode all messages
        for msg in messages:
            msg['decoded'] = PDUDecoder.decode_pdu(msg['pdu'])
        
        # Delete messages if requested
        if delete_after:
            for msg in messages:
                cmd = f"AT+CMGD={msg['index']}"
                if self.debug:
                    print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
                self.serial_port.write((cmd + "\r\n").encode())
                self._wait_for_response()
        
        return messages

    def get_all_messages(self, storage_types: List[str] = None, delete_after: bool = False) -> List[Dict]:
        """Get all messages from specified storage types"""
        if storage_types is None:
            storage_types = ["SM", "ME"]
        
        all_messages = []
        self._open_serial()
        try:
            for storage_type in storage_types:
                try:
                    messages = self._get_messages_from_storage(storage_type, delete_after)
                    all_messages.extend(messages)
                except Exception as e:
                    if self.debug:
                        print(f"Error accessing {storage_type}: {e}", file=sys.stderr)
            return all_messages
        finally:
            self._close_serial()

    def receive_sms(self, json_output: bool = False, raw_output: bool = False, storage_types: List[str] = None, delete_after: bool = False) -> bool:
        """Receive SMS messages"""
        if storage_types is None:
            storage_types = [self.storage] if self.storage else ["SM", "ME"]
        
        all_messages = self.get_all_messages(storage_types, delete_after)
        
        if json_output:
            print('{"msg":[', end='')
        
        for i, msg in enumerate(all_messages):
            if json_output and i > 0:
                print(',', end='')
            
            if json_output:
                print(f'{{"index":{msg["index"]},', end='')
            else:
                print(f"MSG: {msg['index']} ({msg['storage']})")
            
            if raw_output:
                if json_output:
                    print(f'"content":"{msg["pdu"]}"}}', end='')
                else:
                    print(msg['pdu'])
            else:
                # Use decoded data
                decoded = msg['decoded']
                if json_output:
                    sender = decoded['sender'].replace('"', '\\"')
                    timestamp = decoded['timestamp'].replace('"', '\\"')
                    content = decoded['message'].replace('"', '\\"')
                    
                    json_fields = [f'"sender":"{sender}"', f'"timestamp":"{timestamp}"', f'"content":"{content}"']
                    
                    # Add multipart SMS fields if present
                    if 'reference' in decoded:
                        json_fields.append(f'"reference":{decoded["reference"]}')
                    if 'part' in decoded:
                        json_fields.append(f'"part":{decoded["part"]}')
                    if 'total' in decoded:
                        json_fields.append(f'"total":{decoded["total"]}')
                    
                    print(','.join(json_fields) + '}', end='')
                else:
                    print(f"From: {decoded['sender']}")
                    print(f"Date/Time: {decoded['timestamp']}")
                    print(decoded['message'])
                    print()
        
        if json_output:
            print(']}')
        
        return True

    def receive_sms_assembled(self, json_output: bool = False, storage_types: List[str] = None, delete_after: bool = False) -> bool:
        """Receive SMS messages with multipart messages assembled"""
        all_messages = self.get_all_messages(storage_types, delete_after)
        
        # Group multipart messages by sender and reference
        multipart_groups = {}
        single_messages = []
        
        for msg in all_messages:
            decoded = msg['decoded']
            if 'reference' in decoded and 'part' in decoded and 'total' in decoded:
                # This is part of a multipart message
                key = (decoded['sender'], decoded['reference'])
                if key not in multipart_groups:
                    multipart_groups[key] = {}
                multipart_groups[key][decoded['part']] = {
                    'content': decoded['message'],
                    'timestamp': decoded['timestamp'],
                    'total': decoded['total'],
                    'index': msg['index'],
                    'storage': msg['storage']
                }
            else:
                # Single message
                single_messages.append(msg)
        
        # Assemble multipart messages
        assembled_messages = []
        
        # Add single messages
        for msg in single_messages:
            assembled_messages.append({
                'type': 'single',
                'index': msg['index'],
                'storage': msg['storage'],
                'sender': msg['decoded']['sender'],
                'timestamp': msg['decoded']['timestamp'],
                'content': msg['decoded']['message']
            })
        
        # Add assembled multipart messages
        for (sender, reference), parts in multipart_groups.items():
            if not parts:
                continue
                
            # Get total parts expected
            total_parts = next(iter(parts.values()))['total']
            
            # Check if we have all parts
            if len(parts) == total_parts:
                # Assemble message in correct order
                assembled_content = ""
                earliest_timestamp = None
                indices = []
                storages = []
                
                for part_num in range(1, total_parts + 1):
                    if part_num in parts:
                        part_data = parts[part_num]
                        assembled_content += part_data['content']
                        indices.append(part_data['index'])
                        storages.append(part_data['storage'])
                        
                        # Use earliest timestamp
                        if earliest_timestamp is None or part_data['timestamp'] < earliest_timestamp:
                            earliest_timestamp = part_data['timestamp']
                
                assembled_messages.append({
                    'type': 'multipart',
                    'indices': indices,
                    'storages': storages,
                    'sender': sender,
                    'timestamp': earliest_timestamp,
                    'content': assembled_content,
                    'reference': reference,
                    'total_parts': total_parts
                })
            else:
                # Incomplete multipart message - add individual parts
                for part_num, part_data in parts.items():
                    assembled_messages.append({
                        'type': 'incomplete_multipart',
                        'index': part_data['index'],
                        'storage': part_data['storage'],
                        'sender': sender,
                        'timestamp': part_data['timestamp'],
                        'content': part_data['content'],
                        'reference': reference,
                        'part': part_num,
                        'total_parts': part_data['total']
                    })
        
        # Sort by timestamp
        assembled_messages.sort(key=lambda x: x['timestamp'])
        
        # Output results
        if json_output:
            print('{"msg":[', end='')
        
        for i, msg in enumerate(assembled_messages):
            if json_output and i > 0:
                print(',', end='')
            
            if json_output:
                sender = msg['sender'].replace('"', '\\"')
                timestamp = msg['timestamp'].replace('"', '\\"')
                content = msg['content'].replace('"', '\\"')
                
                if msg['type'] == 'single':
                    print(f'{{"type":"single","index":{msg["index"]},"sender":"{sender}","timestamp":"{timestamp}","content":"{content}"}}', end='')
                elif msg['type'] == 'multipart':
                    indices_str = ','.join(map(str, msg['indices']))
                    print(f'{{"type":"multipart","indices":[{indices_str}],"sender":"{sender}","timestamp":"{timestamp}","content":"{content}","reference":{msg["reference"]},"total_parts":{msg["total_parts"]}}}', end='')
                else:  # incomplete_multipart
                    print(f'{{"type":"incomplete","index":{msg["index"]},"sender":"{sender}","timestamp":"{timestamp}","content":"{content}","reference":{msg["reference"]},"part":{msg["part"]},"total_parts":{msg["total_parts"]}}}', end='')
            else:
                if msg['type'] == 'single':
                    print(f"MSG: {msg['index']} ({msg['storage']})")
                elif msg['type'] == 'multipart':
                    indices_str = ','.join(map(str, msg['indices']))
                    print(f"MSG: [{indices_str}] (Assembled from {msg['total_parts']} parts)")
                else:  # incomplete_multipart
                    print(f"MSG: {msg['index']} ({msg['storage']}) [Incomplete: part {msg['part']}/{msg['total_parts']}]")
                
                print(f"From: {msg['sender']}")
                print(f"Date/Time: {msg['timestamp']}")
                print(msg['content'])
                print()
        
        if json_output:
            print(']}')
        
        return True
    
    def delete_sms(self, index: str) -> bool:
        """Delete SMS message(s)"""
        self._open_serial()
        try:
            if index.lower() == 'all':
                start_idx, end_idx = 0, 49
                print(f"Delete msg from {start_idx} to {end_idx}")
            else:
                start_idx = end_idx = int(index)
                print(f"Delete msg from {start_idx} to {end_idx}")
            
            for i in range(start_idx, end_idx + 1):
                cmd = f"AT+CMGD={i}"
                if self.debug:
                    print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
                self.serial_port.write((cmd + "\r\n").encode())
                responses = self._wait_for_response()
                
                for response in responses:
                    if response == 'OK':
                        print(f"Deleted message {i}")
                        break
                    elif response.startswith('+CMS ERROR:'):
                        print(f"Error deleting message {i}: {response[12:]}")
                        break
            
            return True
            
        finally:
            self._close_serial()
    
    def get_status(self) -> bool:
        """Get SMS storage status"""
        self._open_serial()
        try:
            # Set storage if specified
            if self.storage:
                self._send_command(f'AT+CPMS="{self.storage}"')
            
            # Query storage status
            cmd = "AT+CPMS?"
            if self.debug:
                print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
            self.serial_port.write((cmd + "\r\n").encode())
            responses = self._wait_for_response()
            
            for response in responses:
                if response.startswith('+CPMS:'):
                    # Parse storage info
                    match = re.match(r'\+CPMS:\s*"([^"]+)",(\d+),(\d+)', response)
                    if match:
                        storage_type, used, total = match.groups()
                        print(f"Storage type: {storage_type}, used: {used}, total: {total}")
                        return True
            
            return False
            
        finally:
            self._close_serial()
    
    def send_ussd(self, code: str, raw_input: bool = False, raw_output: bool = False) -> bool:
        """Send USSD code"""
        self._open_serial()
        try:
            if raw_input:
                command = f'AT+CUSD=1,"{code}",15'
            else:
                # Encode to PDU (simplified)
                encoded_code = code.encode().hex().upper()
                command = f'AT+CUSD=1,"{encoded_code}",15'
            
            if self.debug:
                print(f"\033[44m[SEND] {command}\033[0m", file=sys.stderr)
            
            self.serial_port.write((command + '\r\n').encode('utf-8'))
            responses = self._wait_for_response(10)
            
            for response in responses:
                if response.startswith('+CME ERROR:'):
                    print(f"Error: {response[12:]}", file=sys.stderr)
                    return False
                elif response.startswith('+CUSD:'):
                    # Parse USSD response (simplified)
                    if raw_output:
                        match = re.search(r'"([^"]*)"', response)
                        if match:
                            print(match.group(1))
                    else:
                        print("[USSD response decoding not fully implemented]")
                    return True
            
            return False
            
        finally:
            self._close_serial()
    
    def send_at_command(self, command: str) -> bool:
        """Send raw AT command"""
        self._open_serial()
        try:
            if self.debug:
                print(f"\033[44m[SEND] {command}\033[0m", file=sys.stderr)
            self.serial_port.write((command + '\r\n').encode('utf-8'))
            responses = self._wait_for_response()
            
            for response in responses:
                if response == 'OK':
                    if self.debug:
                        print(response)
                    return True
                elif response in ('ERROR', 'COMMAND NOT SUPPORT') or response.startswith('+CME ERROR:'):
                    if self.debug:
                        print(response)
                    return False
                else:
                    print(response)
            
            return False
            
        finally:
            self._close_serial()
    
    def reset_modem(self) -> bool:
        """Reset RM520N-GL modem to factory settings"""
        self._open_serial()
        try:
            # Send factory reset command for RM520N-GL
            cmd = 'AT+QCFG="ResetFactory"'
            if self.debug:
                print(f"\033[44m[SEND] {cmd}\033[0m", file=sys.stderr)
            self.serial_port.write((cmd + '\r\n').encode('utf-8'))
            responses = self._wait_for_response(30)  # Longer timeout for reset
            
            for response in responses:
                if response == 'OK':
                    print("Modem reset successful")
                    return True
                elif response in ('ERROR', 'COMMAND NOT SUPPORT') or response.startswith('+CME ERROR:'):
                    print(f"Modem reset failed: {response}", file=sys.stderr)
                    return False
                else:
                    if self.debug:
                        print(response)
            
            return False
            
        finally:
            self._close_serial()


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage='''%(prog)s [options] send phoneNumber message
       %(prog)s [options] recv
       %(prog)s [options] delete msg_index | all
       %(prog)s [options] status
       %(prog)s [options] ussd code
       %(prog)s [options] at command
       %(prog)s [options] reset
options:
        -b <baudrate> (default: 115200)
        -d <tty device> (default: /dev/ttyUSB0)
        -D debug (for ussd and at)
        -f <date/time format> (for sms/recv)
        -j json output (for sms/recv)
        -R use raw input (for ussd)
        -r use raw output (for ussd and sms/recv)
        -s <preferred storage> (for sms/recv/status)
        -A assemble multipart SMS messages
        -G use GSM character set instead of UCS2
        --delete-after delete messages after fetching
        --all-storage fetch from both SIM and modem storage
        -h, --help show this help message''')
    
    parser.add_argument('-b', '--baudrate', type=int, default=115200, help=argparse.SUPPRESS)
    parser.add_argument('-d', '--device', default='/dev/ttyUSB0', help=argparse.SUPPRESS)
    parser.add_argument('-D', '--debug', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-f', '--dateformat', default='%m/%d/%y %H:%M:%S', help=argparse.SUPPRESS)
    parser.add_argument('-G', '--gsm-mode', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-j', '--json', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-R', '--raw-input', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-r', '--raw-output', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-s', '--storage', default='', help=argparse.SUPPRESS)
    parser.add_argument('-A', '--assemble', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--delete-after', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--all-storage', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('-h', '--help', action='help', help=argparse.SUPPRESS)
    
    parser.add_argument('command', nargs='?', help=argparse.SUPPRESS)
    parser.add_argument('args', nargs='*', help=argparse.SUPPRESS)
    
    args = parser.parse_args()
    
    # Show help if no command provided
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Validate command and arguments
    if args.command == 'send':
        if len(args.args) < 2:
            parser.error('send command requires phone number and message')
    elif args.command == 'delete':
        if len(args.args) < 1:
            parser.error('delete command requires message index or "all"')
    elif args.command in ('ussd', 'at'):
        if len(args.args) < 1:
            parser.error(f'{args.command} command requires additional argument')
    
    # Create SMS tool instance
    sms_tool = SMSTool(
        device=args.device,
        baudrate=args.baudrate,
        debug=args.debug,
        storage=args.storage,
        dateformat=args.dateformat,
        gsm_mode=args.gsm_mode
    )
    
    # Execute command
    try:
        if args.command == 'send':
            phone, message = args.args[0], args.args[1]
            success = sms_tool.send_sms(phone, message)
        elif args.command == 'recv':
            storage_types = None
            if args.all_storage:
                storage_types = ["SM", "ME"]
            elif args.storage:
                storage_types = [args.storage]
            
            if args.assemble:
                success = sms_tool.receive_sms_assembled(args.json, storage_types, args.delete_after)
            else:
                success = sms_tool.receive_sms(args.json, args.raw_output, storage_types, args.delete_after)
        elif args.command == 'delete':
            success = sms_tool.delete_sms(args.args[0])
        elif args.command == 'status':
            success = sms_tool.get_status()
        elif args.command == 'ussd':
            success = sms_tool.send_ussd(args.args[0], args.raw_input, args.raw_output)
        elif args.command == 'at':
            success = sms_tool.send_at_command(args.args[0])
        elif args.command == 'reset':
            success = sms_tool.reset_modem()
        else:
            parser.error(f'Unknown command: {args.command}')
        
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()