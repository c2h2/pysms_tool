#!/usr/bin/env python3
"""
Unit Testing Tool for SMS Tool
==============================

This tool tests the SMS functionality using dummy AT command responses
without requiring a real modem connection.
"""

import unittest
import sys
import time
import logging
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from io import StringIO
from pysms_tool import SMSTool, PDUDecoder

class MockSerial:
    """Mock serial port for testing"""
    
    def __init__(self, responses=None, port="/dev/mock"):
        self.is_open = True
        self.responses = responses or []
        self.response_index = 0
        self.sent_commands = []
        self.port = port
        
    def write(self, data):
        """Mock write - record sent commands"""
        command = data.decode('utf-8').strip()
        self.sent_commands.append(command)
        
    def readline(self):
        """Mock readline - return pre-programmed responses"""
        if self.response_index < len(self.responses):
            response = self.responses[self.response_index]
            self.response_index += 1
            return (response + '\r\n').encode('utf-8')
        return b'\r\n'
    
    def open(self):
        """Mock open"""
        self.is_open = True
        
    def close(self):
        """Mock close"""
        self.is_open = False

def setup_logging():
    """Setup logging to file with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"test_log_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return log_filename

class SimpleTestResult:
    """Simple test result tracking"""
    def __init__(self):
        self.tests_run = 0
        self.passed = 0
        self.failed = 0
        self.errors = []
        
    def add_success(self, test_name):
        self.tests_run += 1
        self.passed += 1
        print(f"✅ {test_name}")
        logging.info(f"PASS: {test_name}")
        
    def add_failure(self, test_name, error):
        self.tests_run += 1
        self.failed += 1
        print(f"❌ {test_name}: {error}")
        logging.error(f"FAIL: {test_name} - {error}")
        self.errors.append((test_name, error))
        
    def print_summary(self):
        print(f"\nTest Results: {self.passed}/{self.tests_run} passed")
        if self.failed > 0:
            print(f"Failed tests: {self.failed}")
        return self.failed == 0

class TestSMSTool(unittest.TestCase):
    """Test cases for SMS Tool functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.sms_tool = SMSTool(device="/dev/mock", debug=False)  # Disable debug for cleaner output
        
    def create_mock_responses(self, command_responses):
        """Create mock serial with specific responses"""
        responses = []
        for cmd_response in command_responses:
            responses.extend(cmd_response)
        return MockSerial(responses)
    
    def test_send_sms_success(self):
        """Test successful SMS sending"""
        logging.info("Testing SMS Send (Success)")
        
        # Mock responses for SMS send
        mock_responses = [
            ['OK'],                    # AT+CMGF=1
            ['OK'],                    # AT+CSCS="UCS2"
            ['OK'],                    # AT+CSMP=17,167,0,25
            ['>'],                     # AT+CMGS="..."
            ['+CMGS: 123', 'OK']      # Message sent with ID 123
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            result = self.sms_tool.send_sms("+1234567890", "Test message 测试")
            
        self.assertTrue(result)
        logging.info(f"Sent commands: {mock_serial.sent_commands}")
        
    def test_send_sms_failure(self):
        """Test SMS sending failure"""
        logging.info("Testing SMS Send (Failure)")
        
        mock_responses = [
            ['OK'],                    # AT+CMGF=1
            ['OK'],                    # AT+CSCS="UCS2"
            ['OK'],                    # AT+CSMP=17,167,0,25
            ['>'],                     # AT+CMGS="..."
            ['+CMS ERROR: 302', 'ERROR']  # Send failed
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            result = self.sms_tool.send_sms("+1234567890", "Test message")
            
        self.assertFalse(result)
        
    def test_receive_sms_single(self):
        """Test receiving single SMS message"""
        logging.info("Testing SMS Receive (Single Message)")
        
        # Real PDU for "Hello" from +1234567890
        test_pdu = "0791947122723014040B915121436587F900001270217143214800048C65C8329BFD06"
        
        mock_responses = [
            ['OK'],                    # AT+CPMS="SM"
            ['OK'],                    # AT+CMGF=0
            ['+CMGL: 1,1,,26', test_pdu, 'OK'],  # List messages
            ['OK'],                    # AT+CPMS="ME"
            ['OK'],                    # AT+CMGF=0
            ['OK']                     # No messages in ME
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            messages = self.sms_tool.get_all_messages()
            
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]['index'], 1)
        logging.info(f"Received {len(messages)} messages")
        logging.info(f"Message content: {messages[0]['decoded']['message']}")
        
    def test_receive_sms_multipart(self):
        """Test receiving multipart SMS messages"""
        logging.info("Testing SMS Receive (Multipart)")
        
        # Mock multipart SMS PDUs (3 parts)
        part1_pdu = "0041000B815121436587F9000050002031803010203414243444546474849"
        part2_pdu = "0041000B815121436587F9000050002031803020203444546474849414243"
        part3_pdu = "0041000B815121436587F9000050002031803030203474849414243444546"
        
        mock_responses = [
            ['OK'],                    # AT+CPMS="SM"
            ['OK'],                    # AT+CMGF=0
            ['+CMGL: 1,1,,40', part1_pdu,
             '+CMGL: 2,1,,40', part2_pdu,
             '+CMGL: 3,1,,40', part3_pdu, 'OK'],
            ['OK'],                    # AT+CPMS="ME"
            ['OK'],                    # AT+CMGF=0
            ['OK']                     # No messages in ME
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            messages = self.sms_tool.get_all_messages()
            
        self.assertEqual(len(messages), 3)
        logging.info(f"Received {len(messages)} multipart messages")
        
    def test_delete_sms_single(self):
        """Test deleting single SMS message"""
        logging.info("Testing SMS Delete (Single)")
        
        mock_responses = [
            ['OK']  # AT+CMGD=1
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            result = self.sms_tool.delete_sms("1")
            
        self.assertTrue(result)
        self.assertIn('AT+CMGD=1', mock_serial.sent_commands)
        
    def test_delete_sms_all(self):
        """Test deleting all SMS messages"""
        logging.info("Testing SMS Delete (All)")
        
        # Mock responses for deleting messages 0-49
        mock_responses = [['OK'] for _ in range(50)]  # 50 OK responses
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            result = self.sms_tool.delete_sms("all")
            
        self.assertTrue(result)
        # Should have sent 50 delete commands
        delete_commands = [cmd for cmd in mock_serial.sent_commands if cmd.startswith('AT+CMGD=')]
        self.assertEqual(len(delete_commands), 50)
        logging.info(f"Bulk delete test passed - sent {len(delete_commands)} delete commands")
        
    def test_receive_after_delete(self):
        """Test receiving messages after deletion"""
        logging.info("Testing Receive After Delete")
        
        # First, populate with messages
        test_pdu = "0791947122723014040B915121436587F900001270217143214800048C65C8329BFD06"
        
        # Initial receive - has messages
        mock_responses_before = [
            ['OK'],                    # AT+CPMS="SM"
            ['OK'],                    # AT+CMGF=0
            ['+CMGL: 1,1,,26', test_pdu,
             '+CMGL: 2,1,,26', test_pdu, 'OK'],
            ['OK'],                    # AT+CPMS="ME"
            ['OK'],                    # AT+CMGF=0
            ['OK']                     # No messages in ME
        ]
        
        mock_serial_before = self.create_mock_responses(mock_responses_before)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial_before), \
             patch('signal.alarm'):
            messages_before = self.sms_tool.get_all_messages()
            
        self.assertEqual(len(messages_before), 2)
        logging.info(f"Before delete: {len(messages_before)} messages")
        
        # Delete all messages
        mock_responses_delete = [['OK'] for _ in range(50)]
        mock_serial_delete = self.create_mock_responses(mock_responses_delete)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial_delete), \
             patch('signal.alarm'):
            delete_result = self.sms_tool.delete_sms("all")
            
        self.assertTrue(delete_result)
        logging.info("Delete operation completed")
        
        # Receive after delete - should be empty
        mock_responses_after = [
            ['OK'],                    # AT+CPMS="SM"
            ['OK'],                    # AT+CMGF=0
            ['OK'],                    # Empty CMGL response
            ['OK'],                    # AT+CPMS="ME"
            ['OK'],                    # AT+CMGF=0
            ['OK']                     # Empty CMGL response
        ]
        
        mock_serial_after = self.create_mock_responses(mock_responses_after)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial_after), \
             patch('signal.alarm'):
            messages_after = self.sms_tool.get_all_messages()
            
        self.assertEqual(len(messages_after), 0)
        logging.info(f"After delete: {len(messages_after)} messages")
        
    def test_receive_with_delete_after(self):
        """Test receive with auto-delete functionality"""
        logging.info("Testing Receive with Auto-Delete")
        
        test_pdu = "0791947122723014040B915121436587F900001270217143214800048C65C8329BFD06"
        
        # Responses for get_all_messages with delete_after=True
        mock_responses = [
            ['OK'],                    # AT+CPMS="SM"
            ['OK'],                    # AT+CMGF=0
            ['+CMGL: 1,1,,26', test_pdu, 'OK'],  # List messages
            ['OK'],                    # AT+CMGD=1 (delete)
            ['OK'],                    # AT+CPMS="ME"
            ['OK'],                    # AT+CMGF=0
            ['OK']                     # Empty CMGL for ME
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial), \
             patch('signal.alarm'):
            messages = self.sms_tool.get_all_messages(delete_after=True)
            
        self.assertEqual(len(messages), 1)
        delete_commands = [cmd for cmd in mock_serial.sent_commands if cmd.startswith('AT+CMGD=')]
        self.assertEqual(len(delete_commands), 1)
        logging.info("Auto-delete functionality test passed")
        
    def test_serial_object_interface(self):
        """Test using serial object directly instead of device path"""
        logging.info("Testing Serial Object Interface")
        
        # Create mock serial object
        mock_responses = [
            ['OK'],                    # AT+CMGF=1
            ['OK'],                    # AT+CSCS="UCS2"
            ['OK'],                    # AT+CSMP=17,167,0,25
            ['>'],                     # AT+CMGS="..."
            ['+CMGS: 789', 'OK']      # Message sent with ID 789
        ]
        
        mock_serial = self.create_mock_responses(mock_responses)
        
        # Test with serial object directly
        sms_tool_serial_obj = SMSTool(serial_port=mock_serial, debug=False)
        
        with patch('signal.alarm'):
            result = sms_tool_serial_obj.send_sms("+1234567890", "Test with serial object")
            
        self.assertTrue(result)
        self.assertTrue(sms_tool_serial_obj._external_serial)
        logging.info(f"Serial object test passed - sent commands: {len(mock_serial.sent_commands)}")
        
        # Verify serial object wasn't closed
        self.assertTrue(mock_serial.is_open)
        logging.info("Serial object remains open after operation (correct behavior)")
        
    def test_mixed_usage(self):
        """Test that both device path and serial object methods work"""
        logging.info("Testing Mixed Usage (Device Path vs Serial Object)")
        
        # Test 1: Traditional device path method
        mock_responses_1 = [
            ['OK'],                    # AT+CMGF=1
            ['OK'],                    # AT+CSCS="UCS2"
            ['OK'],                    # AT+CSMP=17,167,0,25
            ['>'],                     # AT+CMGS="..."
            ['+CMGS: 111', 'OK']      # Message sent
        ]
        
        mock_serial_1 = self.create_mock_responses(mock_responses_1)
        
        with patch('pysms_tool.serial.Serial', return_value=mock_serial_1), \
             patch('signal.alarm'):
            sms_tool_path = SMSTool(device="/dev/mock", debug=False)
            result_1 = sms_tool_path.send_sms("+1111111111", "Test device path")
            
        self.assertTrue(result_1)
        self.assertFalse(sms_tool_path._external_serial)
        
        # Test 2: Serial object method
        mock_responses_2 = [
            ['OK'],                    # AT+CMGF=1
            ['OK'],                    # AT+CSCS="UCS2"
            ['OK'],                    # AT+CSMP=17,167,0,25
            ['>'],                     # AT+CMGS="..."
            ['+CMGS: 222', 'OK']      # Message sent
        ]
        
        mock_serial_2 = self.create_mock_responses(mock_responses_2)
        
        with patch('signal.alarm'):
            sms_tool_obj = SMSTool(serial_port=mock_serial_2, debug=False)
            result_2 = sms_tool_obj.send_sms("+2222222222", "Test serial object")
            
        self.assertTrue(result_2)
        self.assertTrue(sms_tool_obj._external_serial)
        
        logging.info("Mixed usage test passed - both methods work correctly")
        
    def test_pdu_decoder(self):
        """Test PDU decoding functionality"""
        logging.info("Testing PDU Decoder")
        
        # Test simple message
        simple_pdu = "0791947122723014040B915121436587F900001270217143214800048C65C8329BFD06"
        decoded = PDUDecoder.decode_pdu(simple_pdu)
        
        # Check if sender starts with + and contains digits
        self.assertTrue(decoded['sender'].startswith('+'))
        self.assertTrue(any(c.isdigit() for c in decoded['sender']))
        self.assertIn('message', decoded)
        logging.info(f"Simple PDU decoded: {decoded['message']}")
        
        # Test multipart message PDU with proper header
        multipart_pdu = "07915121551532F4400B915121436587F900005011711103804023050003CC0201B8329BFD0685C3"
        decoded_mp = PDUDecoder.decode_pdu(multipart_pdu)
        
        if 'reference' in decoded_mp:
            logging.info(f"Multipart PDU decoded - Part {decoded_mp['part']}/{decoded_mp['total']}")
        else:
            logging.info("PDU decoded (not multipart)")

def run_simple_tests():
    """Run simplified tests with clean output"""
    print("SMS Tool Tests")
    print("==============")
    
    result = SimpleTestResult()
    test_instance = TestSMSTool()
    test_instance.setUp()
    
    # Test list with simple names
    tests = [
        ("Send SMS Success", test_instance.test_send_sms_success),
        ("Send SMS Failure", test_instance.test_send_sms_failure),
        ("Receive Single SMS", test_instance.test_receive_sms_single),
        ("Receive Multipart SMS", test_instance.test_receive_sms_multipart),
        ("Delete Single SMS", test_instance.test_delete_sms_single),
        ("Delete All SMS", test_instance.test_delete_sms_all),
        ("Receive After Delete", test_instance.test_receive_after_delete),
        ("Auto-Delete Feature", test_instance.test_receive_with_delete_after),
        ("Serial Object Interface", test_instance.test_serial_object_interface),
        ("Mixed Usage", test_instance.test_mixed_usage),
        ("PDU Decoder", test_instance.test_pdu_decoder)
    ]
    
    for test_name, test_func in tests:
        try:
            test_func()
            result.add_success(test_name)
        except Exception as e:
            result.add_failure(test_name, str(e))
    
    return result.print_summary()

def test_real_world_scenario():
    """Test a real-world SMS scenario"""
    print("\n" + "="*60)
    print("REAL-WORLD SCENARIO TEST")
    print("="*60)
    
    print("Scenario: Send message, receive replies, clean up")
    
    # Step 1: Send a message
    print("\n1. Sending SMS message...")
    sms_tool = SMSTool(device="/dev/mock", debug=False)
    
    send_responses = [
        ['OK'],                    # AT+CMGF=1
        ['OK'],                    # AT+CSCS="UCS2"
        ['OK'],                    # AT+CSMP=17,167,0,25
        ['>'],                     # AT+CMGS="..."
        ['+CMGS: 456', 'OK']      # Message sent
    ]
    
    mock_serial = MockSerial()
    mock_serial.responses = []
    for resp_group in send_responses:
        mock_serial.responses.extend(resp_group)
    
    with patch('serial.Serial', return_value=mock_serial):
        send_result = sms_tool.send_sms("+1234567890", "Hello! How are you? 你好吗？")
    
    print(f"   Send result: {'✅ Success' if send_result else '❌ Failed'}")
    
    # Step 2: Receive multiple replies
    print("\n2. Receiving reply messages...")
    
    # Mock PDUs for replies
    reply1_pdu = "0791947122723014040B915121436587F900001270217143214800084C65C8329BFD06"
    reply2_pdu = "0791947122723014040B915121436587F900001270217143214800084C65C8329BFD06"
    
    recv_responses = [
        ['OK'],                    # AT+CPMS="SM"
        ['OK'],                    # AT+CMGF=0
        ['+CMGL: 1,1,,30', reply1_pdu,
         '+CMGL: 2,1,,30', reply2_pdu, 'OK'],
        ['OK'],                    # AT+CPMS="ME"
        ['OK'],                    # AT+CMGF=0
        ['OK']                     # No messages in ME
    ]
    
    mock_serial.responses = []
    mock_serial.response_index = 0
    for resp_group in recv_responses:
        mock_serial.responses.extend(resp_group)
    
    with patch('serial.Serial', return_value=mock_serial):
        messages = sms_tool.get_all_messages()
    
    print(f"   Received: {len(messages)} messages")
    for i, msg in enumerate(messages):
        print(f"     Message {i+1}: {msg['decoded']['message'][:30]}...")
    
    # Step 3: Clean up
    print("\n3. Cleaning up messages...")
    
    cleanup_responses = [['OK'] for _ in range(50)]  # Delete all
    mock_serial.responses = cleanup_responses
    mock_serial.response_index = 0
    
    with patch('serial.Serial', return_value=mock_serial):
        cleanup_result = sms_tool.delete_sms("all")
    
    print(f"   Cleanup result: {'✅ Success' if cleanup_result else '❌ Failed'}")
    
    # Step 4: Verify cleanup
    print("\n4. Verifying cleanup...")
    
    verify_responses = [
        ['OK'],                    # AT+CPMS="SM"
        ['OK'],                    # AT+CMGF=0
        ['OK'],                    # Empty CMGL
        ['OK'],                    # AT+CPMS="ME"
        ['OK'],                    # AT+CMGF=0
        ['OK']                     # Empty CMGL
    ]
    
    mock_serial.responses = verify_responses
    mock_serial.response_index = 0
    
    with patch('serial.Serial', return_value=mock_serial):
        remaining_messages = sms_tool.get_all_messages()
    
    print(f"   Remaining messages: {len(remaining_messages)}")
    
    scenario_success = (send_result and len(messages) > 0 and 
                       cleanup_result and len(remaining_messages) == 0)
    
    print(f"\n🎯 Scenario result: {'✅ Success' if scenario_success else '❌ Failed'}")
    
    return scenario_success

if __name__ == '__main__':
    # Setup logging
    log_file = setup_logging()
    print(f"SMS Tool Unit Tests (Log: {log_file})")
    print("=" * 40)
    
    # Handle command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == 'scenario':
            success = test_real_world_scenario()
        elif command in ['comprehensive', 'comp']:
            success = run_simple_tests()  # comprehensive just runs all tests
        else:
            print(f"Unknown command: {command}")
            print("Usage: python3 test_sms_tool.py [scenario|comprehensive]")
            sys.exit(1)
    else:
        # Default: run simple tests
        success = run_simple_tests()
    
    print(f"\nDetailed logs saved to: {log_file}")
    sys.exit(0 if success else 1)