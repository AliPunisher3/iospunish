#  IOS/Punish Attack Exploit 
PFArray is such a subclass of NSArray. When a _PFArray is deserialized, it is deserialized with [NSArray initWithCoder:], which eventually calls [_PFArray initWithObjects:count:]. This method initializes the array with the objects provided by the NSKeyedUnarchiver, but does not retain references to these objects, so when the NSKeyedUnarchiver is released, the objects in the array will also be released, even though the user of the deserialized objects could still be using them.

This issue can be reached remotely via iMessage and crash Springboard with no user interaction. IOS/Punish is a Simple and Very Fast BOF attack Against IOS/MAC that can lead to DOS. The vulnerability is a heap buffer overflow in the networking code in the XNU operating system kernel. XNU is used by both iOS and macOS, which is why iPhones, iPads, and Macbooks are all affected.

##### Usage 
```
apt-get install nmap
python3 exploit.py
```
##### Find any Error : 
```
It is under development If you find any error let me know :) instagram: @alipunisher3
