  # Mission/Task Description:
    # * For the "password", provide an 10-digit time-based one time password conforming to RFC6238 TOTP.
    # 
    # ** You have to read RFC6238 (and the errata too!) and get a correct one time password by yourself.
    # ** TOTP's "Time Step X" is 30 seconds. "T0" is 0.
    # ** Use HMAC-SHA-512 for the hash function, instead of the default HMAC-SHA-1.
    # ** Token shared secret is the userid followed by ASCII string value "HDECHALLENGE003" (not including double quotations).
    # 
    # *** For example, if the userid is "ninja@example.com", the token shared secret is "ninja@example.comHDECHALLENGE003".
    # *** For example, if the userid is "ninjasamuraisumotorishogun@example.com", the token shared secret is "ninjasamuraisumotorishogun@example.comHDECHALLENGE003"
    # 

import hmac
import hashlib
import time
import sys
import struct

userid = "xingjianli59@gmail.com"
secret_suffix = "HENNGECHALLENGE003"
shared_secret = userid + secret_suffix

timestep = 30
T0 = 0

def HOTP(K, C, digits=10):
    """
    HTOP:
    K is the shared key
    C is the counter value
    digits control the response length
    """
    K_bytes = K.encode()
    C_bytes = struct.pack(">Q", C)
    hmac_sha512 = hmac.new(key = K_bytes, msg=C_bytes, digestmod=hashlib.sha512).hexdigest()
    return Truncate(hmac_sha512)[-digits:]

def Truncate(hmac_sha512):
    """truncate sha512 value"""
    offset = int(hmac_sha512[-1], 16)
    binary = int(hmac_sha512[(offset *2):((offset*2)+8)], 16) & 0x7FFFFFFF
    return str(binary)

def TOTP(K, digits=10, timeref = 0, timestep = 30):
    """
    TOTP, time-based variant of HOTP
    digits control the response length
    the C in HOTP is replaced by ( (currentTime - timeref) / timestep )
    """
    C = int( time.time() - timeref ) // timestep
    return HOTP(K, C, digits = digits)

password = TOTP(shared_secret, 10, T0, timestep).zfill(10)
print(password)