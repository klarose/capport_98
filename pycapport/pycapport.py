import json
import requests
import fcntl, socket, struct
from netifaces import AF_INET
import netifaces as ni
import argparse

def find_if_with_ip(ip):
	for interface in ni.interfaces():
		addrs = ni.ifaddresses(interface)
		if AF_INET in addrs:
			for check_ip in addrs[AF_INET]:
				if check_ip["addr"] == ip:
					return interface
	raise Exception("No interface found for ip", ip)

# found at http://stackoverflow.com/questions/159137/getting-mac-address. 
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytearray(ifname[:15], 'utf-8')))
    return '-'.join(['%02X' % char for char in info[18:24]])

parser = argparse.ArgumentParser(description='Log in to a captive portal')
parser.add_argument('ip', help='the ip address which has been captivated')
args = parser.parse_args()


api_ip="10.1.0.1"
api_port=":5000"

headers = {'Accept': 'application/json'}

uri_result_json=requests.get("http://" + api_ip + api_port + "/capport", headers = headers)
#uri_s{"browse_href": "http://10.1.0.1:5000/", "create_href": "http://10.1.0.1:5000/capport/sessions"}
uri_result=json.loads(uri_result_json.text)
create_href=uri_result['create_href']
print(create_href)

session_request={}
# curl -H'Accept: application/json' http://10.1.0.1:5000/capport/sessions -d '{"identity": "08-00-27-92-C9-EA", "id_type": "mac"}'
ifName=find_if_with_ip(args.ip)
mac_address=getHwAddr(ifName)
session_request['identity'] = mac_address
session_request['id_type'] = "mac"

r=requests.post(create_href, data=json.dumps(session_request), headers = headers)

print(r.text)
