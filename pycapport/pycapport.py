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
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15].encode('utf-8')))
    return '-'.join(['%02x' % ord(char) for char in info[18:24]])

parser = argparse.ArgumentParser(description='Log in to a captive portal')
parser.add_argument('ip', help='the ip address which has been captivated')
parser.add_argument('--logout', action="store_true", help='True to logout of an already authenticated session')
args = parser.parse_args()

def get_session(ip):
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
	return json.loads(r.text)

def login(ip):
	session_json=get_session(ip)
	login_href=session_json["cred_api_url"]	
	login_json={}
	login_json["username"] = "radar"
	login_json["password"] = "radar"
	headers = {'Accept': 'application/json'}
	r=requests.post(login_href, data=json.dumps(login_json), headers=headers)
	print(r.text)
	
def logout(id_json):
	r=requests.delete(id_json['href'])
	print("Logout result:", r.text)

if args.logout:
	logout(get_session(args.ip)['id'])
else:
	login(args.ip)
