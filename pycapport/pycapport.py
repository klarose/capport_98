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
# could use netifaces
def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytearray(ifname[:15], 'utf-8')))
    return '-'.join(['%02X' % char for char in info[18:24]])

parser = argparse.ArgumentParser(description='Log in to a captive portal')
parser.add_argument('ip', help='the ip address which has been captivated')
parser.add_argument('--logout', action="store_true", help='True to logout of an already authenticated session')
args = parser.parse_args()

def login(ip):
	api_ip="10.1.0.1"
	api_port=":5000"

	headers = {'Accept': 'application/json'}

	uri_result_json=requests.get("http://" + api_ip + api_port + "/capport", headers = headers)
	uri_result=json.loads(uri_result_json.text)
	create_href=uri_result['create_href']

	session_request={}
	ifName=find_if_with_ip(ip)
	mac_address=getHwAddr(ifName)
	session_request['identity'] = mac_address
	session_request['id_type'] = "mac"

	r=requests.post(create_href, data=json.dumps(session_request), headers = headers)

	print(r.text)

	return json.loads(r.text)['id']

def logout(id_json):
	r=requests.delete(id_json['href'])
	print("Logout result:", r.text)

if args.logout:
	logout(login(args.ip))
else:
	login(args.ip)
