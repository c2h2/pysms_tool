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
    
    # Check storage status
    python3 sms_tool_python.py -d /dev/ttyUSB2 status
    
    # Delete all messages
    python3 sms_tool_python.py -d /dev/ttyUSB2 delete all
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
        
        # Simple 7-bit encoding implementation
        output = bytearray()
        carry_bits = 0
        carry_count = 0
        
        for i, char in enumerate(text):
            char_code = ord(char) & 0x7F
            
            if carry_count == 0:
                output.append(char_code)
                carry_bits = char_code >> 7
                carry_count = 1
            else:
                byte_val = ((char_code << (8 - carry_count)) | carry_bits) & 0xFF
                output.append(byte_val)
                
                carry_bits = char_code >> carry_count
                carry_count += 1
                
                if carry_count == 8:
                    if i < len(text) - 1:
                        output.append(carry_bits & 0x7F)
                    carry_count = 0
                    carry_bits = 0
        
        if carry_count > 0 and carry_bits > 0:
            output.append(carry_bits & 0x7F)
            
        return bytes(output)
    
    @staticmethod
    def decode_7bit(data: bytes, length: int = None) -> str:
        """Decode GSM 7-bit encoded data"""
        if length is None:
            length = len(data) * 8 // 7
            
        output = []
        carry_bits = 0
        carry_count = 0
        
        for i, byte_val in enumerate(data):
            if carry_count == 0:
                output.append(chr(byte_val & 0x7F))
                carry_bits = (byte_val & 0x80) >> 7
                carry_count = 1
            else:
                char_code = ((byte_val << carry_count) | carry_bits) & 0x7F
                output.append(chr(char_code))
                
                carry_bits = byte_val >> (7 - carry_count)
                carry_count += 1
                
                if carry_count == 7:
                    if len(output) < length:
                        output.append(chr(carry_bits & 0x7F))
                    carry_count = 0
                    carry_bits = 0
                    
            if len(output) >= length:
                break
                
        return ''.join(output)
    
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
    
    def __init__(self, device: str = "/dev/ttyUSB0", baudrate: int = 115200, 
                 debug: bool = False, storage: str = "", dateformat: str = "%m/%d/%y %H:%M:%S"):
        self.device = device
        self.baudrate = baudrate
        self.debug = debug
        self.storage = storage
        self.dateformat = dateformat
        self.serial_port: Optional[serial.Serial] = None
        
        # Set up signal handler for timeout
        signal.signal(signal.SIGALRM, self._timeout_handler)
    
    def _timeout_handler(self, signum, frame):
        """Handle timeout signal"""
        print("No response from modem.", file=sys.stderr)
        sys.exit(2)
    
    def _open_serial(self):
        """Open serial connection to modem"""
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
        if self.serial_port and self.serial_port.is_open:
            self.serial_port.close()
    
    def _send_command(self, command: str) -> str:
        """Send AT command and return response"""
        if not self.serial_port:
            raise RuntimeError("Serial port not open")
        
        self.serial_port.write((command + '\r\n').encode('utf-8'))
        
        response_lines = []
        while True:
            line = self.serial_port.readline().decode(errors='ignore').strip()
            if not line:
                continue
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
                responses.append(line)
                if line in ('OK', 'ERROR') or line.startswith('+CMS ERROR:') or line.startswith('+CME ERROR:'):
                    break
        finally:
            signal.alarm(0)
        
        return responses
    
    def send_sms(self, phone: str, message: str) -> bool:
        """Send SMS message with Unicode support"""
        # Check message length based on encoding
        needs_unicode = any(ord(c) > 127 for c in message)
        
        if needs_unicode:
            # For Unicode, check actual UTF-16BE byte count
            try:
                utf16_bytes = message.encode('utf-16be')
                # SMS limit is 140 bytes for UCS2 (70 UTF-16 characters)
                if len(utf16_bytes) > 140:
                    print(f"SMS message too long: {len(utf16_bytes)} bytes (max 140 bytes for Unicode)", file=sys.stderr)
                    return False
            except UnicodeEncodeError:
                print(f"Cannot encode message: {message}", file=sys.stderr)
                return False
        else:
            # ASCII limit is 160 characters
            if len(message) > 160:
                print(f"SMS message too long: {len(message)} chars (max 160 for ASCII)", file=sys.stderr)
                return False
        
        self._open_serial()
        try:
            if needs_unicode:
                # Use text mode with UCS2 encoding for Unicode messages
                self._send_command("AT+CMGF=1")
                
                # Set character set to UCS2
                self._send_command('AT+CSCS="UCS2"')
                
                # Set SMS parameters for UCS2
                self._send_command('AT+CSMP=17,167,0,25')
                
                # Encode phone number to UCS2
                phone_ucs2 = ''.join(f'{ord(c):04X}' for c in phone)
                
                # Send CMGS command with UCS2 encoded phone number
                self.serial_port.write(f'AT+CMGS="{phone_ucs2}"\r\n'.encode('utf-8'))
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
                self.serial_port.write((message_ucs2 + '\x1A').encode('utf-8'))
            else:
                # Use text mode for ASCII messages
                self._send_command("AT+CMGF=1")
                
                # Set character set to UTF-8
                self._send_command('AT+CSCS="UTF-8"')
                
                # Send CMGS command with phone number
                self.serial_port.write(f'AT+CMGS="{phone}"\r\n'.encode('utf-8'))
                time.sleep(1)
                
                # Send message with Ctrl-Z
                self.serial_port.write((message + '\x1A').encode('utf-8'))
            
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
    
    def receive_sms(self, json_output: bool = False, raw_output: bool = False) -> bool:
        """Receive SMS messages"""
        self._open_serial()
        try:
            # Set storage if specified
            if self.storage:
                self._send_command(f'AT+CPMS="{self.storage}"')
            
            # Set PDU mode
            self._send_command("AT+CMGF=0")
            
            # List all messages
            self.serial_port.write("AT+CMGL=4\r\n".encode())
            
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
                        current_msg = {'index': int(match.group(1))}
                elif current_msg and response and not response in ('OK', 'ERROR'):
                    # This should be the PDU data
                    current_msg['pdu'] = response
            
            if current_msg:
                messages.append(current_msg)
            
            if json_output:
                print('{"msg":[', end='')
            
            for i, msg in enumerate(messages):
                if json_output and i > 0:
                    print(',', end='')
                
                if json_output:
                    print(f'{{"index":{msg["index"]},', end='')
                else:
                    print(f"MSG: {msg['index']}")
                
                if raw_output:
                    if json_output:
                        print(f'"content":"{msg["pdu"]}"}}', end='')
                    else:
                        print(msg['pdu'])
                else:
                    # Decode PDU (simplified - would need full PDU decoder)
                    if json_output:
                        print('"sender":"","timestamp":"","content":"[PDU decoding not fully implemented]"}', end='')
                    else:
                        print("From: [PDU decoding not fully implemented]")
                        print("Date/Time: [PDU decoding not fully implemented]")
                        print("[PDU decoding not fully implemented]")
                        print()
            
            if json_output:
                print(']}')
            
            return True
            
        finally:
            self._close_serial()
    
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
                self.serial_port.write(f"AT+CMGD={i}\r\n".encode())
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
            self.serial_port.write("AT+CPMS?\r\n".encode())
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
                print(f"debug: {command}")
            
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


def main():
    parser = argparse.ArgumentParser(description='SMS Tool for 3G/4G/5G modem - Python version')
    parser.add_argument('-b', '--baudrate', type=int, default=115200, help='Baudrate (default: 115200)')
    parser.add_argument('-d', '--device', default='/dev/ttyUSB0', help='TTY device (default: /dev/ttyUSB0)')
    parser.add_argument('-D', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('-f', '--dateformat', default='%m/%d/%y %H:%M:%S', help='Date/time format')
    parser.add_argument('-j', '--json', action='store_true', help='JSON output')
    parser.add_argument('-R', '--raw-input', action='store_true', help='Use raw input')
    parser.add_argument('-r', '--raw-output', action='store_true', help='Use raw output')
    parser.add_argument('-s', '--storage', default='', help='Preferred storage')
    
    parser.add_argument('command', help='Command: send, recv, delete, status, ussd, at')
    parser.add_argument('args', nargs='*', help='Command arguments')
    
    args = parser.parse_args()
    
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
        dateformat=args.dateformat
    )
    
    # Execute command
    try:
        if args.command == 'send':
            phone, message = args.args[0], args.args[1]
            success = sms_tool.send_sms(phone, message)
        elif args.command == 'recv':
            success = sms_tool.receive_sms(args.json, args.raw_output)
        elif args.command == 'delete':
            success = sms_tool.delete_sms(args.args[0])
        elif args.command == 'status':
            success = sms_tool.get_status()
        elif args.command == 'ussd':
            success = sms_tool.send_ussd(args.args[0], args.raw_input, args.raw_output)
        elif args.command == 'at':
            success = sms_tool.send_at_command(args.args[0])
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