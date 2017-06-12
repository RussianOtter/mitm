import string

def bytetypes():
	val = []
	for u in string.digits+string.ascii_lowercase:
		c = "\\x"+u.encode("hex")
		val.append((u,c))

def txt_bytes(word):
	msg = list(word)
	s = 0
	for i in msg:
		t = i.encode("hex")
		t = "\\x"+t
		msg[s] = t
		s = s + 1
	return "".join(msg)

def byte_pbyte(data):
	# check if there are multiple bytes
	if len(str(data)) > 1:
		# make list all bytes given
		msg = list(data)
		# mark which item is being converted
		s = 0
		for u in msg:
			# convert byte to ascii, then encode ascii to get byte number
			u = str(u).encode("hex")
			# make byte printable by canceling \x
			u = "\\x"+u
			# apply coverted byte to byte list
			msg[s] = u
			s = s + 1
		msg = "".join(msg)
	else:
		msg = data
		# convert byte to ascii, then encode ascii to get byte number
		msg = str(msg).encode("hex")
		# make byte printable by canceling \x
		msg = "\\x"+msg
	# return printable byte
	return msg
