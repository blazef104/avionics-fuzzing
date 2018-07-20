# (C) Giulio Ginesi 2018
#
# General structure of a ADS-B message
# all the information are taken from mode-s.org
# +--------+--------+-----------+--------------------------+---------+
# |  DF 5  |  ** 3  |  ICAO 24  |          DATA 56         |  PI 24  |
# +--------+--------+-----------+--------------------------+---------+
# A ads-b message is 112 bits long
# DF -> downlink format
# next 3 bits depend on the message type
# DATA = 5bits for msg type(1-31) + 51 bits for real data
# esamples: DF0 -> 02e60eb841b511
# type11 -> 5d4d20237a55a6 (all call replay)
# extended squitter -> 8f4d20235877d0bc7d99551e27ca

import math

msg1 = "8f4d30235877d0bc7d99551e27ca"

GENERATOR = "1111111111111010000001001"
test_msg = "5d4d20237a55a6"  # "8D4840D6202CC371C32CE0"    # 112 bits


def hex2bin(hexstr):
    """Convert a hexdecimal string to binary string, with zero fillings. """
    scale = 16
    num_of_bits = len(hexstr) * math.log(scale, 2)
    binstr = bin(int(hexstr, scale))[2:].zfill(int(num_of_bits))
    return binstr


def genCrc(msg):    # from mode-s.org
    msgbin = list(hex2bin(msg))
    msgbin[-24:] = ['0'] * 24
    for i in range(len(msgbin)-24):
        # if 1, perform modulo 2 multiplication,
        if msgbin[i] == '1':
            for j in range(len(GENERATOR)):
                # modulo 2 multiplication = XOR
                msgbin[i+j] = str((int(msgbin[i+j]) ^ int(GENERATOR[j])))

    crc = ''.join(msgbin[-24:])
    return crc


def toHex(str):
    return('%0*X' % ((len(str) + 3) // 4, int(str, 2)))


def getDF(msg):
    msg = hex2bin(msg)
    df = int(msg[0:5], 2)
    return(df)


def getCap(msg):
    msg = hex2bin(msg)
    cap = int(msg[5:8], 2)
    return cap


def getICAO(msg):
    msg = hex2bin(msg)
    icao = int(msg[8:33], 2)
    return icao


def getData(msg):
    msg = hex2bin(msg)
    data = msg[32:len(msg)-24]
    return data


def setData(msg, data):
    msg = list(hex2bin(msg))
    data = list(data)
    if len(data) > 56:
        return 0
    for i in range(len(data)):
        msg[i+32] = data[i]
    return ''.join(msg)


print("Raw Message:\n", hex2bin(msg1), "  ", len(hex2bin(msg1)))
print("Message Type: ", getCap(msg1))
print("ICAO number: ", getICAO(msg1))
print("DATA: ", getData(msg1), "  ", len(getData(msg1)))
print("CRC: ", toHex(genCrc(msg1)))
new_msg = setData(msg1, "00101000011101111101000010111100011111011001100101010101")
print(toHex(new_msg))
print("CRC: ", toHex(genCrc(new_msg)))
mex = (112-24)*'1'
mmex = toHex(mex+genCrc(mex))
print(mmex)
