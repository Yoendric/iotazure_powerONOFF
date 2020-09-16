from machine import UART, RTC, Pin
import ntptime
import machine
from time import sleep
import time
import network
import ubinascii
from umqtt.simple import MQTTClient
from struct import *
import collections
import re
from uhashlib import sha256
try:
  import usocket as socket
except:
  import socket
from main.ota_updater import OTAUpdater
  
INITIAL_MODBUS = 0xFFFF
INITIAL_DF1 = 0x0000

table = (
0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040 )

def handle_interrupt(pin):
  global switch_ap
  if pin.value() == 1:
    print ("Poner en modo AP")
    switch_ap = True
  else:
    print ("Poner modo cliente")
    switch_ap = False 
  
def b64encode(s, altchars=None):
    bytes_types = (bytes, bytearray)
    if not isinstance(s, bytes_types):
        raise TypeError("expected bytes, not %s" % s.__class__.__name__)
    # Strip off the trailing newline
    encoded = ubinascii.b2a_base64(s)[:-1]
    if altchars is not None:
        if not isinstance(altchars, bytes_types):
            raise TypeError("expected bytes, not %s"
                            % altchars.__class__.__name__)
        assert len(altchars) == 2, repr(altchars)
        return encoded.translate(bytes.maketrans(b'+/', altchars))
    return encoded

def b64decode(s, altchars=None, validate=False):
    s = _bytes_from_decode_data(s)
    if altchars is not None:
        altchars = _bytes_from_decode_data(altchars)
        assert len(altchars) == 2, repr(altchars)
        s = s.translate(bytes.maketrans(altchars, b'+/'))
    if validate and not re.match(b'^[A-Za-z0-9+/]*={0,2}$', s):
        raise ubinascii.Error('Non-base64 digit found')
    return ubinascii.a2b_base64(s)

def _bytes_from_decode_data(s):
    if isinstance(s, str):
        try:
            return s.encode('ascii')
#        except UnicodeEncodeError:
        except:
            raise ValueError('string argument should contain only ASCII characters')
    elif isinstance(s, bytes_types):
        return s
    else:
        raise TypeError("argument should be bytes or ASCII string, not %s" % s.__class__.__name__)

def quote(string, safe='/', encoding=None, errors=None):
    if isinstance(string, str):
        if not string:
            return string
        if encoding is None:
            encoding = 'utf-8'
        if errors is None:
            errors = 'strict'
        string = string.encode(encoding, errors)
    else:
        if encoding is not None:
            raise TypeError("quote() doesn't support 'encoding' for bytes")
        if errors is not None:
            raise TypeError("quote() doesn't support 'errors' for bytes")
    return quote_from_bytes(string, safe)

def quote_plus(string, safe='', encoding=None, errors=None):
    if ((isinstance(string, str) and ' ' not in string) or
        (isinstance(string, bytes) and b' ' not in string)):
        return quote(string, safe, encoding, errors)
    if isinstance(safe, str):
        space = ' '
    else:
        space = b' '
    string = quote(string, safe + space, encoding, errors)
    return string.replace(' ', '+')
  
def quote_from_bytes(bs, safe='/'):
    _ALWAYS_SAFE = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                         b'abcdefghijklmnopqrstuvwxyz'
                         b'0123456789'
                         b'_.-')
    _ALWAYS_SAFE_BYTES = bytes(_ALWAYS_SAFE)
    _safe_quoters = {}
    if not isinstance(bs, (bytes, bytearray)):
        raise TypeError("quote_from_bytes() expected bytes")
    if not bs:
        return ''
    if isinstance(safe, str):
        # Normalize 'safe' by converting to bytes and removing non-ASCII chars
        safe = safe.encode('ascii', 'ignore')
    else:
        safe = bytes([c for c in safe if c < 128])
    if not bs.rstrip(_ALWAYS_SAFE_BYTES + safe):
        return bs.decode()
    try:
        quoter = _safe_quoters[safe]
    except KeyError:
        _safe_quoters[safe] = quoter = Quoter(safe).__getitem__
    return ''.join([quoter(char) for char in bs])
  
class Quoter(collections.defaultdict):
    def __init__(self, safe):
        """safe: bytes object."""
        _ALWAYS_SAFE = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ' b'abcdefghijklmnopqrstuvwxyz'b'0123456789'b'_.-')
        self.safe = _ALWAYS_SAFE.union(safe)

    def __repr__(self):
        # Without this, will just display as a defaultdict
        return "<Quoter %r>" % dict(self)

    def __missing__(self, b):
        # Handle a cache miss. Store quoted string in cache and return.
        res = chr(b) if b in self.safe else '%{:02X}'.format(b)
        self[b] = res
        return res

def urlencode(query, doseq=False, safe='', encoding=None, errors=None):
    if hasattr(query, "items"):
        query = query.items()
    l = []
    if not doseq:
        for k, v in query:
            if isinstance(k, bytes):
                k = quote_plus(k, safe)
            else:
                k = quote_plus(str(k), safe, encoding, errors)

            if isinstance(v, bytes):
                v = quote_plus(v, safe)
            else:
                v = quote_plus(str(v), safe, encoding, errors)
            l.append(k + '=' + v)
    else:
        for k, v in query:
            if isinstance(k, bytes):
                k = quote_plus(k, safe)
            else:
                k = quote_plus(str(k), safe, encoding, errors)

            if isinstance(v, bytes):
                v = quote_plus(v, safe)
                l.append(k + '=' + v)
            elif isinstance(v, str):
                v = quote_plus(v, safe, encoding, errors)
                l.append(k + '=' + v)
            else:
                try:
                    # Is this a sufficient test for sequence-ness?
                    x = len(v)
                except TypeError:
                    # not a sequence
                    v = quote_plus(str(v), safe, encoding, errors)
                    l.append(k + '=' + v)
                else:
                    # loop over the sequence
                    for elt in v:
                        if isinstance(elt, bytes):
                            elt = quote_plus(elt, safe)
                        else:
                            elt = quote_plus(str(elt), safe, encoding, errors)
                        l.append(k + '=' + elt)
    return '&'.join(l)

def xor(x, y):
    return bytes(x[i] ^ y[i] for i in range(min(len(x), len(y))))

def hmac_sha256(key_K, data):
    if len(key_K) > 64:
        raise ValueError('The key must be <= 64 bytes in length')
    padded_K = key_K + b'\x00' * (64 - len(key_K))
    ipad = b'\x36' * 64
    opad = b'\x5c' * 64
    h_inner = sha256(xor(padded_K, ipad))
    h_inner.update(data)
    h_outer = sha256(xor(padded_K, opad))
    h_outer.update(h_inner.digest())
    return h_outer.digest()

def write_wifi_data(essid,password):
  file = open('data_wifi.txt','w')
  file.write(essid + ' ' +password)
  file.close()
  
def erase_wifi_data():
  file = open('data_wifi.txt','w')
  file.close()
  
def read_wifi_data():
  file = open('data_wifi.txt','r')
  data = file.read()
  if not data:
    essid = ''
    passw = ''
  else:
    essid,passw=data.split(" ")
  return essid, passw

def calcByte( ch, crc):
    """Given a new Byte and previous CRC, Calc a new CRC-16"""
    if type(ch) == type("c"):
      by = ord( ch)
      
    else:
      by = ch
      
    crc = (crc >> 8) ^ table[(crc ^ by) & 0xFF]    
    return (crc & 0xFFFF)

def calcString( st, crc):
    """Given a bunary string and starting CRC, Calc a final CRC-16 """
    for ch in st:
        crc = (crc >> 8) ^ table[(crc ^ ord(ch)) & 0xFF]
    return crc
    
def zfill(s, width):
    if len(s) < width:
        return ("0" * (width - len(s))) + s
    else:
        return s

def rev(s):
    return "" if not(s) else rev(s[1::])+s[0]

def decoded_measurement(data):
    #print(" ".join("{:02x}".format(c) for c in data))
    metre = [None] * 6    
    for i in range(6) :
        if i == 0 :
            dt = data[0:2] 
            metre[i] = unpack('>H',dt)[0]
            metre[i] = zfill(hex(metre[i]).split('x')[-1],3)
        if i == 1 :
            dt = data[4:6]+data[2:4]
            metre[i] = unpack('>I',dt)[0]
            #metre[i] = zfill(hex(metre[i]).split('x')[-1],5)
        if i == 2 :
            dt = data[8:10]+data[6:8]
            metre[i] = unpack('>I',dt)[0]
            metre[i] = zfill(hex(metre[i]).split('x')[-1],5)
        if i == 3 :
            dt = data[12:14]+data[10:12]
            metre[i] = unpack('>I',dt)[0]
            metre[i] = zfill(hex(metre[i]).split('x')[-1],5)
        if i == 4 :
            dt = data[14:16]
            metre[i] = unpack('>H',dt)[0]
            metre[i] = zfill(hex(metre[i]).split('x')[-1],3)
        if i == 5 :
            dt = data[16:18]
            metre[i] = unpack('>H',dt)[0]
            metre[i] = zfill(hex(metre[i]).split('x')[-1],2)
    return metre

def read_measurement(addr):
    data= addr+'\x04'+'\x00'+'\x00'+'\x00'+'\x0a'
    crc = INITIAL_MODBUS
    for ch in data:
      crc = calcByte( ch, crc)
    crc = zfill(bin(crc)[2:],16)  
    put_crc = ''        
    for i in range(0,len(crc),8):
        put_crc += chr(int(crc[i:i+8],2))
    data = data + rev(put_crc)
    temp = bytes()
    for i in data:
      temp += bytes([ord(i)])
    return temp

def Reset_Energy(uart,addr1):
  addr = pack("B", addr1).decode()
  data = addr + '\x42'
  crc = INITIAL_MODBUS
  for ch in data:
    crc = calcByte( ch, crc)
  crc = zfill(bin(crc)[2:],16)  
  put_crc = '' 
  for i in range(0,len(crc),8):
    put_crc += chr(int(crc[i:i+8],2))
  data = data + rev(put_crc)
  temp = bytes()
  for i in data:
    temp += bytes([ord(i)])
  uart.write(temp)
  sleep(0.5)
  Read_PZEM(uart,1,addr1)
  return

def Adjustment_Time_RTC(UTC):
  while True:
    try:
      ntptime.settime() 
      (year, month, mday, week_of_year, hour, minute, second, milisecond)=RTC().datetime()
      RTC().init((year, month, mday, week_of_year, hour+UTC, minute, second, milisecond))
      print ("Fecha/Hora (year, month, mday, week of year, hour, minute, second, milisecond):", RTC().datetime())
      return
    except:
      print("ERROR ajustando RTC. Wait 1 second")
      time.sleep(1)  
  
def web_page(id_device,id_mensaje):
  html = """<html><head> <title>Web Server NIMBLU Checkinwatt</title> <meta http-equiv="Content-Type" content="text/html;charset=UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:,"> <style>html{font-family: Helvetica; display:inline-block; margin: 0px auto; text-align: center;}
  h1{color: #0F3376; padding: 2vh;}p{font-size: 1.5rem;}.button{display: inline-block; background-color: #4286f4; border: none;
  border-radius: 4px; color: white; padding: 16px 40px; text-decoration: none; font-size: 30px; margin: 2px; cursor: pointer;}
  </style> </head> <body> <h1>Web Server NIMBLU Checkinwatt</h1> <p>Configuracion de cliente WIFI: </p>
  <p><strong>ID device Azure IoT Hub: """ + id_device + """</strong></p> <form method = "post" enctype="multipart/form-data" accept-charset="UTF-8"> <table border="1" style="margin: 0 auto;"> <tr><td>
  <p style="color:#0F3376";>ESSID :<input type="text" style="text-align:center" name="essid"></p>
  <p style="color:#0F3376";>PASSWORD :<input type="password" style="text-align:center" name="password"></p> </td></tr>
  </table><p><button class="button">Conectar</button></p> <p style="color:rgb(255,0,0);"><strong>"""+id_mensaje+""" </strong></p></form> </body></html>"""
  return html
  
def ap_mode(): 
  ap = network.WLAN(network.AP_IF)
  mac = ubinascii.hexlify(network.WLAN().config('mac'),':').decode()
  mac = mac.upper()
  ap.active(True)
  ap.config(essid='Nimblu_chekinwatts('+mac[-8:]+')', authmode=network.AUTH_WPA_WPA2_PSK, password='12345678')
  ap.ifconfig(('192.168.0.1', '255.255.255.0', '192.168.0.1', '192.168.0.1'))
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    s.bind(('0.0.0.0', 80))
  except:
    machine.reset()
  s.listen(2)
  while True:
    conn, addr = s.accept()
    print('Got a connection from %s' % str(addr))
    request = conn.recv(1024)
    request = str(request)
    print('Content = %s' % request)
    ptr1 = request.find('essid')
    ptr2 = request.find('password')
    if ((ptr1 != -1) | (ptr2 != -1)):         
      essid = request[ptr1+14:ptr2-86]
      password =request[ptr2+17:-51]
      if essid: 
        mensaje="Intentando conexion a AP sugerido"
        response = web_page(mac,mensaje)
        conn.send('HTTP/1.1 200 OK\n')
        conn.send('Content-Type: text/html\n')
        conn.send('Connection: close\n\n')
        conn.sendall(response)
        conn.close()
        s.close()
        ap.active(False)
        print('Pasar a modo cliente')
        return essid,password
    mensaje=""
    response = web_page(mac,mensaje)
    conn.send('HTTP/1.1 200 OK\n')
    conn.send('Content-Type: text/html\n')
    conn.send('Connection: close\n\n')
    conn.sendall(response)
    conn.close()

def Connect_wifi_client(ssid,password):
  global switch_ap
  station = network.WLAN(network.STA_IF) 
  if station.isconnected() == True:
    print("Already connected")
    write_wifi_data(ssid,password)    
    return 
  station.active(True)
  station.connect(ssid, password)
  while station.isconnected() == False:
    print ("Aun no conectado")
    if switch_ap == True:
      print("Sali de cliente por interrupcion")      
      station.active(False)
      sleep(0.5)
      erase_wifi_data()
      machine.reset()
    else:    
      sleep(1)
  print ("Me conecte")
  write_wifi_data(ssid,password)
  print("Connection successful")
  print(station.ifconfig())
  return
  
def iot_hub_mqttsend(device_id, hostname,username,password,msg):
  client = MQTTClient(device_id, hostname, user=username, password=password,
                    ssl=True, port=8883)
  try:
    client.connect()
    topic = "devices/{device_id}/messages/events/".format(device_id=device_id)
    client.publish(topic, msg, qos=1)
    client.disconnect()
  except Exception as e:
    error = str(e.args[0])
    try:
      client.disconnect()
    except:
      print("No habia que desconectar el cliente")    
    print("Error en la conexion a IoT Hub")
    letter = [device_id,"MQTTException",error,str(time.time())]
    print (letter)
    try:
      send_mail(letter)
    except:
      print("No se pudo enviar el correo")    
    sleep(5)
  
def send_mail(letter):
  try:
    import main.umail as umail
  except:
    print("No se pudo importar umail")
    return
  smtp = umail.SMTP('smtp.gmail.com', 587, username='checkinwattsnimblu@gmail.com', password='Qwerty123.')
  smtp.to('checkinwattsnimblu@gmail.com')
  print("Enviando correo")
  smtp.write("Subject: Error_log\n\n")
  for i in letter:
    smtp.write(i+"\n")
  smtp.write("...\n")
  smtp.send()
  smtp.quit()
  return

def Sas_token(uri,key):
  expiry=3600*365*24
  ttl=time.time()+expiry+946684800
  sign_key = "%s\n%d" % ((quote_plus(uri)), int(ttl))
  datos=hmac_sha256(b64decode(key), sign_key.encode('utf-8'))
  signature = b64encode(hmac_sha256(b64decode(key), sign_key.encode('utf-8')))
  rawtoken={'sr':uri,'sig':signature}
  rawtoken['se']=str(int(ttl))
  password = 'SharedAccessSignature ' + urlencode(rawtoken)
  print(password)
  return password 

def Get_Client_Wifi_Parameters():
  try:
    ssid,passw = read_wifi_data()
  except:
    ssid,passw = ("","")
  return ssid,passw

def Blinky_LED(led):
  led.value(0)
  sleep(0.1)
  led.value(1)
  sleep(0.1)

def Read_PZEM(uart,seg,address):
  no_comunication_sensor=["F","F","F","FFFFF","F","F"]
  pzem='PZEM-004T-{add}'.format(add=zfill(str(address),2))
  data = read_measurement(pack("B", address).decode())
  #########Interfaces###################################
  uart.write(data)             #########################
  data = ''                    #########################
  sleep(0.1)                   #########################
  data = uart.read()           #########################
  ######################################################
  if not data:
    print('No comunicacion con '+pzem+': Segundo: '+str(seg))
    fout= "F"
    wh_out = "FFFFF"
  else:  
    print(pzem+': Segundo: '+str(seg))     
    measurent= decoded_measurement(data[3:-2])
    print(measurent)
    if measurent[1] == 0:
      fout = "0"
    else:
      fout = "1"
    wh_out = measurent[3]
  return fout,wh_out
 
def download_and_install_update_if_available(url,ssid,password):
  o = OTAUpdater(url)
  o.download_and_install_update_if_available(ssid,password)

def check_time_update_github(last_update):
  next_update = last_update+24*3600
  if next_update < time.mktime(time.localtime()):
    print("Hora de revisar actualizacion")
    return True
  else:
    return False

##############################################################
##### MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN ######
##############################################################
def main():
  global time_last_update   #variable important to OTA time update
  global switch_ap
  time_last_update = 0
  time_tick_send_message = 60 * 59
  time_sleep_across_measure = 0.9
  url='https://github.com/Yoendric/checkinwattHandleInterruptio'   #Github repository project
  o = OTAUpdater(url)
  led = Pin(14, Pin.OUT)
  led.value(1)
  wifi = Pin(4, Pin.OUT)
  pir = Pin(25, Pin.IN)
  pir.irq(trigger=Pin.IRQ_FALLING | Pin.IRQ_RISING, handler=handle_interrupt)
  uart = UART(2, baudrate=9600, tx=26,rx=27)# init with given baudrate
  uart.init(9600, bits=8, parity=None, stop=1) # init with given parameters
  # Azure IoT-hub settings
  hostname = "checkinwattsiothub.azure-devices.net"
  device_id = ubinascii.hexlify(network.WLAN().config('mac'),':').decode()
  device_id = device_id.upper()
  uri = "{hostname}/devices/{device_id}".format(hostname=hostname, device_id=device_id)
  username_fmt = "{}/{}/?api-version=2018-06-30"
  key="XxXK7Pun5XQa/NqUsGBmXBKI4euLUcU/72bjxuPr+jE="
  username = username_fmt.format(hostname, device_id)
  switch_ap = False
  ssid,passw=Get_Client_Wifi_Parameters()
  if pir.value() == 1:
    switch_ap = True
  while True:
    if switch_ap:
      print('Interrupt AP detected!')
      wifi.value(0)
      led.value(1)
      ssid , passw = ap_mode()
      while switch_ap:
        Blinky_LED(wifi)
    else:
      print('Modo cliente')
      wifi.value(1)
      if (ssid and passw):
        Connect_wifi_client(ssid,passw)
        download_and_install_update_if_available(url,ssid,passw)
        Adjustment_Time_RTC(-6)
        Reset_Energy(uart,1)
        password = Sas_token(uri,key)
        f0 = ""
        f1 = ""
        while (not switch_ap):
          if check_time_update_github(time_last_update):
            try:
              o.check_for_update_to_install_during_next_reboot()
              time_last_update=time.mktime(time.localtime())
            except:
              print("NO SE PUEDE CONECTAR PARA VER SI HAY ACTUALIZACION")
          sleep(time_sleep_across_measure)
          wh = ""
          MSG_TXT = '{{"ID": "010008","status": "{f0}","consumo":"{wh}"}}'
          seg = 1
          while (seg <= time_tick_send_message) and (f1 == f0) and (not switch_ap):
            led.value(seg%2)
            f1 , wh = Read_PZEM(uart,seg,1) 
            sleep(time_sleep_across_measure)   
            seg = seg + 1
          f0 = f1
          Reset_Energy(uart,1)
          if (not switch_ap):
            msg_txt_formatted = MSG_TXT.format(f0=f0,wh=wh) 
            print ("Message ready to ship to IoT Hub Azure") 
            print (msg_txt_formatted)
            iot_hub_mqttsend(device_id, hostname,username,password,msg_txt_formatted)
      else:
        sleep(1)

main()


