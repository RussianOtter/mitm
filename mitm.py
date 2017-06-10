"""mitm.py: A regular-expression based DNS MITM Server by Crypt0s.
Extended Mod for Pythonista 3 by RussianOtter"""

import pdb, socket, re, sys, os, SocketServer, signal, argparse, logging

try:
	import console
	console.set_color(1,0,0)
	print """       __  __ ___ _____ __  __  
      |  \/  |_ _|_   _|  \/  | 
      | |\/| || |  | | | |\/| | 
      | |  | || |  | | | |  | | 
      |_|  |_|___| |_| |_|  |_| 
      """
	console.set_color()
except:
	print """       __  __ ___ _____ __  __  
      |  \/  |_ _|_   _|  \/  | 
      | |\/| || |  | | | |\/| | 
      | |  | || |  | | | |  | | 
      |_|  |_|___| |_| |_|  |_| 
      """
	pass

class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
	def __init__(self, server_address, request_handler):
		self.address_family = socket.AF_INET
		SocketServer.UDPServer.__init__(
			self, server_address, request_handler)

class UDPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		(data, s) = self.request
		respond(data, self.client_address, s)

class DNSQuery:
	def __init__(self, data):
		self.data = data
		self.domain = ''
		tipo = (ord(data[2]) >> 3) & 15
		if tipo == 0:
			ini = 12
			lon = ord(data[ini])
			while lon != 0:
				self.domain += data[ini + 1:ini + lon + 1] + '.'
				ini += lon + 1
				lon = ord(data[ini])
			self.type = data[ini:][1:3]
		else:
			self.type = data[-4:-2]

def nf_count():
	global a
	try:
		a = a + 1
	except:
		a = 0
	return str(a)

TYPE = {
	"\x00\x01": "A",
	"\x00\x1c": "AAAA",
	"\x00\x05": "CNAME",
	"\x00\x0c": "PTR",
	"\x00\x10": "TXT",
	"\x00\x0f": "MX",
	"\x00\x06": "SOA"
}

def _is_shorthand_ip(ip_str):
	"""
	Returns:
		A boolean, True if the address is shortened.
	"""
	if ip_str.count('::') == 1:
		return True
	if any(len(x) < 4 for x in ip_str.split(':')):
		return True
	return False

def _explode_shorthand_ip_string(ip_str):
	"""
	Returns:
		A string, the expanded IPv6 address.
	"""
	if not _is_shorthand_ip(ip_str):
		return ip_str

	hextet = ip_str.split('::')
	if '.' in ip_str.split(':')[-1]:
		fill_to = 7
	else:
		fill_to = 8

	if len(hextet) > 1:
		sep = len(hextet[0].split(':')) + len(hextet[1].split(':'))
		new_ip = hextet[0].split(':')

		for _ in xrange(fill_to - sep):
			new_ip.append('0000')
		new_ip += hextet[1].split(':')

	else:
		new_ip = ip_str.split(':')

	ret_ip = []
	for hextet in new_ip:
		ret_ip.append(('0' * (4 - len(hextet)) + hextet).lower())
	return ':'.join(ret_ip)


def _get_question_section(query):
	start_idx = 12
	end_idx = start_idx

	num_questions = (ord(query.data[4]) << 8) | ord(query.data[5])

	while num_questions > 0:
		while query.data[end_idx] != '\0':
			end_idx += ord(query.data[end_idx]) + 1
		end_idx += 5
		num_questions -= 1

	return query.data[start_idx:end_idx]

class DNSResponse(object):
	def __init__(self, query):
		self.id = query.data[:2]
		self.flags = "\x81\x80"
		self.questions = query.data[4:6]
		self.rranswers = "\x00\x01"
		self.rrauthority = "\x00\x00"
		self.rradditional = "\x00\x00"
		self.query = _get_question_section(query)
		self.pointer = "\xc0\x0c"
		self.type = None
		self.dnsclass = "\x00\x01"
		self.ttl = "\x00\x00\x00\x01"
		self.length = None
		self.data = None

	def make_packet(self):
		try:
			return self.id + self.flags + self.questions + self.rranswers + \
				self.rrauthority + self.rradditional + self.query + \
				self.pointer + self.type + self.dnsclass + self.ttl + \
				self.length + self.data
		except (TypeError, ValueError):
			pass

class A(DNSResponse):
	def __init__(self, query, record):
		super(A, self).__init__(query)
		self.type = "\x00\x01"
		self.length = "\x00\x04"
		self.data = self.get_ip(record)

	@staticmethod
	def get_ip(dns_record):
		ip = dns_record
		return ''.join(chr(int(x)) for x in ip.split('.'))

class AAAA(DNSResponse):
	def __init__(self, query, address):
		super(AAAA, self).__init__(query)
		self.type = "\x00\x1c"
		self.length = "\x00\x10"
		self.data = address

	def get_ip_6(host, port=0):
		result = socket.getaddrinfo(host, port, socket.AF_INET6)
		ip = result[0][4][0]

class CNAME(DNSResponse):
	def __init__(self, query):
		super(CNAME, self).__init__(query)
		self.type = "\x00\x05"

class PTR(DNSResponse):
	def __init__(self, query, ptr_entry):
		super(PTR, self).__init__(query)
		self.type = "\x00\x0c"
		self.ttl = "\x00\x00\x00\x00"
		ptr_split = ptr_entry.split('.')
		ptr_entry = "\x07".join(ptr_split)

		self.data = "\x09" + ptr_entry + "\x00"
		self.length = chr(len(ptr_entry) + 2)
		if self.length < '\xff':
			self.length = "\x00" + self.length

class TXT(DNSResponse):
	def __init__(self, query, txt_record):
		super(TXT, self).__init__(query)
		self.type = "\x00\x10"
		self.data = txt_record
		self.length = chr(len(txt_record) + 1)
		if self.length < '\xff':
			self.length = "\x00" + self.length
		self.length += chr(len(txt_record))

CASE = {
	"\x00\x01": A,
	"\x00\x1c": AAAA,
	"\x00\x05": CNAME,
	"\x00\x0c": PTR,
	"\x00\x10": TXT
}

class NONEFOUND(DNSResponse):
	def __init__(self, query):
		super(NONEFOUND, self).__init__(query)
		self.type = query.type
		self.flags = "\x81\x83"
		self.rranswers = "\x00\x00"
		self.length = "\x00\x00"
		self.data = "\x00"
		sys.stdout.write("\r\rNONEFOUND Response %s     " %(nf_count()))

class Rule (object):
	def __init__(self, rule_type, domain, ips, rebinds, threshold):
		self.type = rule_type
		self.domain = domain
		self.ips = ips
		self.rebinds = rebinds
		self.rebind_threshold = threshold
		if self.rebinds is not None:
			self.match_history = {}
			self.rebinds = self._round_robin(rebinds)
		self.ips = self._round_robin(ips)

	def _round_robin(self, ip_list):
		"""
		Creates a generator over a list modulo list length to equally move between all elements in the list each request.
		"""
		if len(ip_list) == 1:
			ip_list.append(ip_list[0])

		index = 0
		while 1:
			yield ip_list[index]
			index += 1
			index = index % len(ip_list)

	def match(self, req_type, domain, addr):

		try:
			req_type = TYPE[req_type]
		except KeyError:
			return None

		try:
			assert self.type == req_type
		except AssertionError:
			return None

		try:
			assert self.domain.match(domain)
		except AssertionError:
			return None

		if self.rebinds:
			if self.match_history.has_key(addr):

				if self.match_history[addr] >= self.rebind_threshold:
					return self.rebinds.next()
				else:
					self.match_history[addr] += 1
			else:
				self.match_history[addr] = 1

		return self.ips.next()

class RuleError_BadRegularExpression(Exception):
	def __init__(self,lineno):
		logging.error("\n!! Malformed Regular Expression on rulefile line #%d\n\n" % lineno)
		sys.exit()

class RuleError_BadRuleType(Exception):
	def __init__(self,lineno):
		logging.error("\n!! Rule type unsupported on rulefile line #%d\n\n" % lineno)
		sys.exit()

class RuleError_BadFormat(Exception):
	def __init__(self,lineno):
		logging.error("\n!! Not Enough Parameters for rule on rulefile line #%d\n\n" % lineno)
		sys.exit()


class RuleEngine2:
	def _replace_self(self, ips):
		for ip in ips:
			if ip.lower() == 'self':
				try:
					self_ip = socket.gethostbyname(socket.gethostname())
				except socket.error:
					print "Could not get your IP address for mitm."
					self_ip = '127.0.0.1'
				ips[ips.index(ip)] = self_ip
		return ips

	def __init__(self, file_):
		"""
		Parses the DNS Rulefile, validates the rules, replaces keywords
		"""
		self.match_history = {}
		self.rule_list = []
		with open(file_, 'r') as rulefile:
			rules = rulefile.readlines()
			lineno = 0
			for rule in rules:
				if rule == "" or rule.lstrip()[0] == "#" or rule == '\n':
					continue
				if len(rule.split()) < 3:
					raise RuleError_BadFormat(lineno)
				s_rule = rule.split()
				rule_type = s_rule[0].upper()
				domain = s_rule[1]
				ips = s_rule[2].split(',')
				if len(s_rule) == 4:
					rebinds = s_rule[3]
					if '%' in rebinds:
						rebind_threshold,rebinds = rebinds.split('%')
						rebinds = rebinds.split(',')
						rebind_threshold = int(rebind_threshold)
					else:
						rebind_threshold = 1
				else:
					rebinds = None
					rebind_threshold = None
				if rule_type not in TYPE.values():
					raise RuleError_BadRuleType(lineno)
				try:
					domain = re.compile(domain)
				except:
					raise RuleError_BadRegularExpression(lineno)
				ips = self._replace_self(ips)
				if rebinds is not None:
					rebinds = self._replace_self(rebinds)
				if rule_type.upper() == "AAAA":
					tmp_ip_array = []
					for ip in ips:
						if _is_shorthand_ip(ip):
							ip = _explode_shorthand_ip_string(ip)
						ip = ip.replace(":", "").decode('hex')
						tmp_ip_array.append(ip)
					ips = tmp_ip_array
				self.rule_list.append(Rule(rule_type, domain, ips, rebinds, rebind_threshold))
				lineno += 1
			
			data = str(path)+" Parsed "+str(len(self.rule_list))+" Rules"
			print data

	def match(self, query, addr):
		"""
		See if the request matches any rules in the rule list by calling the
		match function of each rule in the list.
		"""
		for rule in self.rule_list:
			result = rule.match(query.type, query.domain, addr)
			if result is not None:
				response_data = result

				if response_data.lower() == 'none':
					return NONEFOUND(query).make_packet()

				response = CASE[query.type](query, response_data)

				print "\r\rMR - " + query.domain
				return response.make_packet()

		if args.noforward:
			print "\r\rDF %s" % query.domain
			return NONEFOUND(query).make_packet()
		try:
			s = socket.socket(type=socket.SOCK_DGRAM)
			s.settimeout(3.0)
			addr = ('%s' % (args.dns), 53)
			s.sendto(query.data, addr)
			data = s.recv(1024)
			s.close()
			print "\r\rUR " + query.domain
			return data
		except socket.error, e:
			return NONEFOUND(query).make_packet()

def respond(data, addr, s):
	p = DNSQuery(data)
	response = rules.match(p, addr[0])
	s.sendto(response, addr)
	return response

def signal_handler(signal, frame):
	sys.exit()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='A Python DNS Server')
	parser.add_argument(
		'-c', dest='path', action='store', required=True,
		help='Path to configuration file')
	parser.add_argument(
		'-i', dest='iface', action='store', default='0.0.0.0', required=False,
		help='IP address you wish to run mitm with - default all')
	parser.add_argument(
		'-p', dest='port', action='store', default=53, required=False,
		help='Port number you wish to run mitm')
	parser.add_argument(
		'--rebind', dest='rebind', action='store_true', required=False,
		default=False, help="Enable DNS rebinding attacks - responds with one "
		"result the first request, and another result on subsequent requests")
	parser.add_argument(
		'--dns', dest='dns', action='store', default='8.8.8.8', required=False,
		help='IP address of the upstream dns server - default 8.8.8.8'
	)
	parser.add_argument(
		'--noforward', dest='noforward', action='store_true', default=False, required=False,
		help='Sets if mitm should forward any non-matching requests'
	)

	args = parser.parse_args()

	path = args.path
	if not os.path.isfile(path):
		print "FILE\n Please create a \"dns.conf\" file or specify a config path: \nmitm.py -c [configfile]"
		exit()

	rules = RuleEngine2(path)
	rule_list = rules.rule_list

	interface = args.iface
	port = args.port

	try:
		server = ThreadedUDPServer((interface, int(port)), UDPHandler)
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			s.connect(("8.8.8.8",80))
			ip = s.getsockname()[0]
		except:
			ip = "0.0.0.0"
			print "No Connection"
		try:
			from objc_util import *
			CNCopyCurrentNetworkInfo = c.CNCopyCurrentNetworkInfo
			CNCopyCurrentNetworkInfo.restype = c_void_p
			CNCopyCurrentNetworkInfo.argtypes = [c_void_p]
			wifiid = ObjCInstance(CNCopyCurrentNetworkInfo(ns('en0')))
			wifiid = wifiid["SSID"]
		except:
			wifiid = "[Your WiFi]"
		try:
			ips = ip.split(".")
			opt = []
			ips[3] = "1"
			opt.append(".".join(ips))
			ips[3] = "254"
			opt.append(".".join(ips))
			for srv in opt:
				try:
					s.connect((srv,53))
					dns = srv
					break
				except:
					dns = "[Main DNS]"
		except:
			dns = "[Main DNS]"
		print "MITM DNS",ip,port
		print "\nFor Self Logging:"
		print "Settings>WiFi>%s\nChange DNS To:\n%s, %s\n" %(wifiid,ip,dns)
		print "For WiFi Logging:"
		print "Access your WiFi Control Pannel, make DNS1: %s and make DNS2: %s" %(ip,dns)
	except socket.error:
		print "Port {0} Taken.\n!Toggle Port!".format(port)
		exit(1)

	server.daemon = True
	signal.signal(signal.SIGINT, signal_handler)
	server.serve_forever()
	server_thread.join()
