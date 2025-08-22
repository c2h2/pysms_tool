#!/usr/bin/env python3
"""
Demo: Serial Object Interface vs Device Path
============================================

This demo shows the difference between using device paths and serial objects
with the SMS tool, demonstrating the benefits of reduced port open/close overhead.
"""

import serial
import time
from pysms_tool import SMSTool

def demo_device_path_method():
    """Demo traditional device path method"""
    print("=== Method 1: Device Path (Traditional) ===")
    print("Opens and closes serial port for each operation")
    
    # This will open/close port for each operation
    sms = SMSTool(device="/dev/ttyUSB2", debug=False)
    
    print("Operation 1: Send SMS (opens port)")
    # sms.send_sms("+1234567890", "First message")  # Uncomment for real usage
    print("  -> Port opened, SMS sent, port closed")
    
    print("Operation 2: Send SMS (opens port again)")  
    # sms.send_sms("+0987654321", "Second message")  # Uncomment for real usage
    print("  -> Port opened again, SMS sent, port closed again")
    
    print("Total port operations: 4 (2 opens + 2 closes)")
    print()

def demo_serial_object_method():
    """Demo serial object method"""
    print("=== Method 2: Serial Object (Recommended) ===")
    print("Reuses single serial connection for multiple operations")
    
    # Create serial object once
    try:
        # Uncomment for real usage:
        # ser = serial.Serial("/dev/ttyUSB2", baudrate=115200, timeout=1)
        # sms = SMSTool(serial_port=ser, debug=False)
        
        print("Serial port opened once")
        print("Operation 1: Send SMS (reuses connection)")
        # sms.send_sms("+1234567890", "First message")  # Uncomment for real usage
        print("  -> Connection reused, SMS sent")
        
        print("Operation 2: Send SMS (reuses connection)")
        # sms.send_sms("+0987654321", "Second message")  # Uncomment for real usage  
        print("  -> Connection reused, SMS sent")
        
        print("Operation 3: Receive SMS (reuses connection)")
        # messages = sms.get_all_messages()  # Uncomment for real usage
        print("  -> Connection reused, messages received")
        
        # ser.close()  # Uncomment for real usage
        print("Serial port closed once")
        print("Total port operations: 2 (1 open + 1 close)")
        
    except Exception as e:
        print(f"Note: {e} (This is expected in demo mode without real modem)")
    
    print()

def benchmark_comparison():
    """Show theoretical performance comparison"""
    print("=== Performance Comparison ===")
    print("Scenario: Send 10 SMS messages")
    print()
    
    print("Device Path Method:")
    print("  - Port operations: 20 (10 opens + 10 closes)")
    print("  - Overhead: High")
    print("  - Use case: Single operations, simple scripts")
    print()
    
    print("Serial Object Method:")
    print("  - Port operations: 2 (1 open + 1 close)")
    print("  - Overhead: Low")
    print("  - Use case: Multiple operations, performance critical")
    print()
    
    print("Performance improvement: ~90% less port operations")

def show_code_examples():
    """Show practical code examples"""
    print("=== Code Examples ===")
    print()
    
    print("1. Device Path Method:")
    print("""
from pysms_tool import SMSTool

sms = SMSTool(device="/dev/ttyUSB2")
sms.send_sms("+1234567890", "Hello")    # Opens/closes port
sms.send_sms("+0987654321", "World")    # Opens/closes port again
""")
    
    print("2. Serial Object Method:")
    print("""
import serial
from pysms_tool import SMSTool

# Open connection once
ser = serial.Serial("/dev/ttyUSB2", baudrate=115200, timeout=1)
sms = SMSTool(serial_port=ser)

# Multiple operations with same connection
sms.send_sms("+1234567890", "Hello")
sms.send_sms("+0987654321", "World")
messages = sms.get_all_messages()
sms.delete_sms("all")

# Close when done
ser.close()
""")

def main():
    """Run the demo"""
    print("SMS Tool Serial Interface Demo")
    print("=" * 40)
    print()
    
    demo_device_path_method()
    demo_serial_object_method()
    benchmark_comparison()
    show_code_examples()
    
    print("Benefits of Serial Object Interface:")
    print("✅ Reduced port open/close overhead")
    print("✅ Better performance for multiple operations")
    print("✅ User controls connection lifecycle")
    print("✅ Backward compatible with existing code")

if __name__ == "__main__":
    main()