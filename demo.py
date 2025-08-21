#!/usr/bin/env python3
"""
SMS Tool Demo Script
===================

This script demonstrates how to use the pysms_tool module programmatically.
It shows examples of sending SMS, receiving messages, and working with multipart SMS.
"""

import sys
from pysms_tool import SMSTool
import time

def demo_basic_operations(device="/dev/ttyUSB2"):
    """Demo basic SMS operations"""
    print("=== SMS Tool Demo ===")
    print(f"Using device: {device}")
    print()
    
    # Create SMS tool instance
    sms = SMSTool(device=device, debug=True)
    
    print("1. Checking modem status...")
    if sms.get_status():
        print("✅ Modem status check successful")
    else:
        print("❌ Modem status check failed")
        return False
    
    print("\n2. Receiving messages (raw format)...")
    messages = sms.get_all_messages()

    #print type
    print(f"Found {len(messages)} messages")
    
    for msg in messages:
        decoded = msg['decoded']
        print(f"  - From: {decoded['sender']}")
        print(f"    Time: {decoded['timestamp']}")
        print(f"    Content: {decoded['message'][:50]}...")
        if 'reference' in decoded:
            print(f"    Multipart: {decoded['part']}/{decoded['total']} (ref: {decoded['reference']})")
        print()
    
    print("3. Demonstrating assembled messages...")
    print("   (This will show multipart SMS assembled into complete messages)")
    sms.receive_sms_assembled(json_output=False)
    
    return True

def demo_send_sms(device="/dev/ttyUSB2", phone=None, message=None):
    """Demo sending SMS"""
    if not phone or not message:
        print("Demo send requires phone number and message")
        return
        
    print(f"\n=== Sending SMS Demo ===")
    print(f"To: {phone}")
    print(f"Message: {message}")
    
    sms = SMSTool(device=device, debug=True)
    
    if sms.send_sms(phone, message):
        print("✅ SMS sent successfully")
    else:
        print("❌ SMS sending failed")

def demo_advanced_features(device="/dev/ttyUSB2"):
    """Demo advanced features"""
    print("\n=== Advanced Features Demo ===")
    
    sms = SMSTool(device=device, debug=True)
    
    print("1. Fetching from both SIM (SM) and modem (ME) storage...")
    all_messages = sms.get_all_messages(storage_types=["SM", "ME"])
    
    sm_count = sum(1 for msg in all_messages if msg['storage'] == 'SM')
    me_count = sum(1 for msg in all_messages if msg['storage'] == 'ME')
    
    print(f"   SIM storage: {sm_count} messages")
    print(f"   Modem storage: {me_count} messages")
    
    print("\n2. Demonstrating JSON output with assembled messages...")
    sms.receive_sms_assembled(json_output=True)
    
    print("\n3. Testing modem reset (WARNING: This will reset your modem!)")
    response = input("   Do you want to reset the modem? (y/N): ")
    if response.lower() == 'y':
        if sms.reset_modem():
            print("✅ Modem reset successful")
        else:
            print("❌ Modem reset failed")
    else:
        print("   Modem reset skipped")

def demo_ussd(device="/dev/ttyUSB2", ussd_code="*100#"):
    """Demo USSD functionality"""
    print(f"\n=== USSD Demo ===")
    print(f"Sending USSD code: {ussd_code}")
    
    sms = SMSTool(device=device, debug=True)
    
    if sms.send_ussd(ussd_code, raw_input=True, raw_output=True):
        print("✅ USSD query successful")
    else:
        print("❌ USSD query failed")

def interactive_demo():
    """Interactive demo menu"""
    device = input("Enter device path (default: /dev/ttyUSB2): ").strip()
    if not device:
        device = "/dev/ttyUSB2"
    
    while True:
        print("\n" + "="*50)
        print("SMS Tool Interactive Demo")
        print("="*50)
        print("1. Basic operations (status, receive)")
        print("2. Send SMS")
        print("3. Advanced features")
        print("4. USSD query")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            demo_basic_operations(device)
        
        elif choice == '2':
            phone = input("Enter phone number: ").strip()
            message = input("Enter message: ").strip()
            if phone and message:
                demo_send_sms(device, phone, message)
            else:
                print("Both phone number and message are required")
        
        elif choice == '3':
            demo_advanced_features(device)
        
        elif choice == '4':
            ussd_code = input("Enter USSD code (default: *100#): ").strip()
            if not ussd_code:
                ussd_code = "*100#"
            demo_ussd(device, ussd_code)
        
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice, please try again")
        
        input("\nPress Enter to continue...")

def main():
    """Main function with command line arguments"""
    if len(sys.argv) < 2:
        print("SMS Tool Demo")
        print("Usage:")
        print(f"  {sys.argv[0]} interactive          - Interactive demo menu")
        print(f"  {sys.argv[0]} basic [device]       - Basic operations demo")
        print(f"  {sys.argv[0]} send phone message   - Send SMS demo")
        print(f"  {sys.argv[0]} advanced [device]    - Advanced features demo")
        print(f"  {sys.argv[0]} ussd [code] [device] - USSD demo")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} interactive")
        print(f"  {sys.argv[0]} basic /dev/ttyUSB2")
        print(f"  {sys.argv[0]} send +1234567890 'Hello World'")
        print(f"  {sys.argv[0]} ussd '*100#' /dev/ttyUSB2")
        return
    
    command = sys.argv[1].lower()
    
    if command == 'interactive':
        interactive_demo()
    
    elif command == 'basic':
        device = sys.argv[2] if len(sys.argv) > 2 else "/dev/ttyUSB2"
        demo_basic_operations(device)
    
    elif command == 'send':
        if len(sys.argv) < 4:
            print("Usage: demo.py send <phone> <message>")
            return
        phone = sys.argv[2]
        message = sys.argv[3]
        device = sys.argv[4] if len(sys.argv) > 4 else "/dev/ttyUSB2"
        demo_send_sms(device, phone, message)
    
    elif command == 'advanced':
        device = sys.argv[2] if len(sys.argv) > 2 else "/dev/ttyUSB2"
        demo_advanced_features(device)
    
    elif command == 'ussd':
        ussd_code = sys.argv[2] if len(sys.argv) > 2 else "*100#"
        device = sys.argv[3] if len(sys.argv) > 3 else "/dev/ttyUSB2"
        demo_ussd(device, ussd_code)
    
    else:
        print(f"Unknown command: {command}")
        print("Run without arguments to see usage help")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Demo error: {e}")
        sys.exit(1)