#!/usr/bin/python
import sys, os
import time
import unicodedata

print "importing zmq"
import zmq

print "importing socket"
import socket

print "importing cpyckle"
import cPickle

print "importing threading"
import threading

print "importing renadom"
from random import choice

print "finished importing"

sys.path.index(0, '.')
import status

dbPath           = status.dbPath
pycklerext       = status.pycklerext
myName           = status.getName()
PING_PORT_NUMBER = 9999
PING_MSG_SIZE    = 1
PING_INTERVAL    = 1  # Once per second

print "  name:", myName



class UDP(object):
	"""simple UDP ping class"""
	handle = None   # Socket for send/recv
	port = 0        # UDP port we work on
	address = ''    # Own address
	broadcast = ''  # Broadcast address

	def __init__(self, port, address=None, broadcast=None):
		if address is None:
			local_addrs = socket.gethostbyname_ex(socket.gethostname())[-1]
			for addr in local_addrs:
				if not addr.startswith('127'):
					address = addr
		if broadcast is None:
			broadcast = '255.255.255.255'

		self.address = address
		self.broadcast = broadcast
		self.port = port
		# Create UDP socket
		self.handle = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

		# Ask operating system to let us do broadcasts from socket
		self.handle.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

		# Bind UDP socket to local port so we can receive pings
		self.handle.bind(('', port))

	def send(self, buf):
		self.handle.sendto(buf, 0, (self.broadcast, self.port))

	def recv(self, n):
		buf, addrinfo = self.handle.recvfrom(n)
		if addrinfo[0] != self.address:
			print("Found peer %s:%d" % addrinfo)

def broadcaster():
	udp    = UDP(PING_PORT_NUMBER)
	poller = zmq.Poller()
	poller.register(udp.handle, zmq.POLLIN)

	# Send first ping right away
	ping_at = time.time()

	while True:
		timeout = ping_at - time.time()
		if timeout  < 0:
			timeout = 0
		try:
			events = dict(poller.poll(1000* timeout))
		except KeyboardInterrupt:
			print("interrupted")
			break

		# Someone answered our ping
		if udp.handle.fileno() in events:
			udp.recv(PING_MSG_SIZE)

		if time.time() >= ping_at:
			# Broadcast our beacon
			print ("Pinging peers...")
			udp.send('!')
			ping_at = time.time() + PING_INTERVAL




class ClientTask(threading.Thread):
	"""ClientTask"""
	def __init__(self):
		threading.Thread.__init__ (self)

	def run(self):
		context = zmq.Context()
		socket = context.socket(zmq.DEALER)
		identity = 'worker-%d' % (choice([0,1,2,3,4,5,6,7,8,9]))
		socket.setsockopt(zmq.IDENTITY, identity )
		socket.connect('tcp://localhost:5570')
		print 'Client %s started' % (identity)
		poll = zmq.Poller()
		poll.register(socket, zmq.POLLIN)
		reqs = 0
		while True:
			for i in xrange(5):
				sockets = dict(poll.poll(1000))
				if socket in sockets:
					if sockets[socket] == zmq.POLLIN:
						msg = socket.recv()
						print 'Client %s received: %s\n' % (identity, msg)
						del msg
			reqs = reqs + 1
			print 'Req #%d sent..' % (reqs)
			socket.send('request #%d' % (reqs))

		socket.close()
		context.term()

class ServerTask(threading.Thread):
	"""ServerTask"""
	def __init__(self):
		threading.Thread.__init__ (self)

	def run(self):
		context = zmq.Context()
		frontend = context.socket(zmq.ROUTER)
		frontend.bind('tcp://*:5570')

		backend = context.socket(zmq.DEALER)
		backend.bind('inproc://backend')

		workers = []
		for i in xrange(5):
			worker = ServerWorker(context)
			worker.start()
			workers.append(worker)

		poll = zmq.Poller()
		poll.register(frontend, zmq.POLLIN)
		poll.register(backend,  zmq.POLLIN)

		while True:
			sockets = dict(poll.poll())
			if frontend in sockets:
				if sockets[frontend] == zmq.POLLIN:
					_id = frontend.recv()
					msg = frontend.recv()
					print 'Server received %s id %s\n' % (msg, _id)
					backend.send(_id, zmq.SNDMORE)
					backend.send(msg)
			if backend in sockets:
				if sockets[backend] == zmq.POLLIN:
					_id = backend.recv()
					msg = backend.recv()
					print 'Sending to frontend %s id %s\n' % (msg, _id)
					frontend.send(_id, zmq.SNDMORE)
					frontend.send(msg)

		frontend.close()
		backend.close()
		context.term()

class ServerWorker(threading.Thread):
	"""ServerWorker"""
	def __init__(self, context):
		threading.Thread.__init__ (self)
		self.context = context

	def run(self):
		worker = self.context.socket(zmq.DEALER)
		worker.connect('inproc://backend')
		print 'Worker started'
		while True:
			_id = worker.recv()
			msg = worker.recv()
			print 'Worker received %s from %s' % (msg, _id)
			replies = choice(xrange(5))
			for i in xrange(replies):
				time.sleep(1/choice(range(1,10)))
				worker.send(_id, zmq.SNDMORE)
				worker.send(msg)

			del msg

		worker.close()

def server_start():
	"""main function
	Here's how it works:

	Clients connect to the server and send requests.
	For each request, the server sends 0 or more replies.
	Clients can send multiple requests without waiting for a reply.
	Servers can send multiple replies without waiting for new requests.

	The example runs in one process, with multiple threads simulating a 
	real multiprocess architecture. When you run the example, you'll 
	see three clients (each with a random ID), printing out the 
	replies they get from the server. Look carefully and you'll see 
	each client task gets 0 or more replies per request.

	Some comments on this code:

	The clients send a request once per second, and get zero or more 
	replies back. To make this work using zmq_poll(), we can't simply 
	poll with a 1-second timeout, or we'd end up sending a new request 
	only one second after we received the last reply. So we poll at a 
	high frequency (100 times at 1/100th of a second per poll), which 
	is approximately accurate.

	The server uses a pool of worker threads, each processing one 
	request synchronously. It connects these to its frontend socket 
	using an internal queue. It connects the frontend and backend 
	sockets using a zmq_proxy() call.
	"""
	server = ServerTask()
	server.start()
	server.join()


	
	
	
	
	
	
	
	
	
def msreader():
	# encoding: utf-8
	#
	#   Reading from multiple sockets
	#   This version uses a simple recv loop
	#
	#   Author: Jeremy Avnet (brainsik) <spork(dash)zmq(at)theory(dot)org>
	#

	# Prepare our context and sockets
	context = zmq.Context()

	# Connect to task ventilator
	receiver = context.socket(zmq.PULL)
	receiver.connect("tcp://localhost:5557")

	# Connect to weather server
	subscriber = context.socket(zmq.SUB)
	subscriber.connect("tcp://localhost:5556")
	subscriber.setsockopt(zmq.SUBSCRIBE, "10001")

	# Process messages from both sockets
	# We prioritize traffic from the task ventilator
	while True:

		# Process any waiting tasks
		while True:
			try:
				rc = receiver.recv(zmq.DONTWAIT)
			except zmq.ZMQError:
				break
			# process task

		# Process any waiting weather updates
		while True:
			try:
				rc = subscriber.recv(zmq.DONTWAIT)
			except zmq.ZMQError:
				break
			# process weather update

		# No activity, so sleep for 1 msec
		time.sleep(0.001)

def mspooler():
	# encoding: utf-8
	#
	#   Reading from multiple sockets
	#   This version uses zmq.Poller()
	#
	#   Author: Jeremy Avnet (brainsik) <spork(dash)zmq(at)theory(dot)org>
	#

	# Prepare our context and sockets
	context = zmq.Context()

	# Connect to task ventilator
	receiver = context.socket(zmq.PULL)
	receiver.connect("tcp://localhost:5557")

	# Connect to weather server
	subscriber = context.socket(zmq.SUB)
	subscriber.connect("tcp://localhost:5556")
	subscriber.setsockopt(zmq.SUBSCRIBE, "10001")

	# Initialize poll set
	poller = zmq.Poller()
	poller.register(receiver, zmq.POLLIN)
	poller.register(subscriber, zmq.POLLIN)

	# Process messages from both sockets
	while True:
		socks = dict(poller.poll())

		if receiver in socks and socks[receiver] == zmq.POLLIN:
			message = receiver.recv()
			# process task

		if subscriber in socks and socks[subscriber] == zmq.POLLIN:
			message = subscriber.recv()
			# process weather update

def sink():
	# Task sink
	# Binds PULL socket to tcp://localhost:5558
	# Collects results from workers via that socket
	#
	# Author: Lev Givon <lev(at)columbia(dot)edu>


	context = zmq.Context()

	# Socket to receive messages on
	receiver = context.socket(zmq.PULL)
	receiver.bind("tcp://*:5558")

	# Wait for start of batch
	s = receiver.recv(zmq.DONTWAIT)

	# Start our clock now
	tstart = time.time()

	# Process 100 confirmations
	total_msec = 0
	for task_nbr in range(100):
		s = receiver.recv()
		if task_nbr % 10 == 0:
			sys.stdout.write(':')
		else:
			sys.stdout.write('.')

	# Calculate and report duration of batch
	tend = time.time()
	print "Total elapsed time: %d msec" % ((tend-tstart)*1000)

def worker():
	# Task worker
	# Connects PULL socket to tcp://localhost:5557
	# Collects workloads from ventilator via that socket
	# Connects PUSH socket to tcp://localhost:5558
	# Sends results to sink via that socket
	#
	# Author: Lev Givon <lev(at)columbia(dot)edu>


	context = zmq.Context()

	# Socket to receive messages on
	receiver = context.socket(zmq.PULL)
	receiver.connect("tcp://localhost:5557")

	# Socket to send messages to
	sender = context.socket(zmq.PUSH)
	sender.connect("tcp://localhost:5558")

	# Process tasks forever
	while True:
		s = receiver.recv(zmq.DONTWAIT)

		# Simple progress indicator for the viewer
		sys.stdout.write('.')
		sys.stdout.flush()

		# Do the work
		time.sleep(int(s)*0.001)

		# Send results to sink
		sender.send('')






#psutil.get_pid_list()
# psutil.get_users()
# [user(name='giampaolo', terminal='pts/2', host='localhost', started=1340737536.0),
# user(name='giampaolo', terminal='pts/3', host='localhost', started=1340737792.0)]
#psutil.get_boot_time()
#used	  = Column(String(50))
#'sqlite:///foo.db'
#'sqlite:////absolute/path/to/foo.db'
#Session.add_all( [] )
#our_user = session.query(User).filter_by(name='ed').first()
#session.query(User).filter(User.name.in_(['Edwardo', 'fakeuser'])).all() 
#for name, fullname in session.query(User.name, User.fullname): 
#	 print name, fullname
#for row in session.query(User, User.name).all(): 
#	 print row.User, row.name
#for row in session.query(User.name.label('name_label')).all(): 
#	 print(row.name_label)
#for u in session.query(User).order_by(User.id)[1:3]: 
#	 print u
#session.query(User).filter(User.name.like('%ed')).count()
#session.query(func.count(User.name), User.name).group_by(User.name).all()
#for u, a in session.query(User, Address).\
#			 filter(User.id==Address.user_id).\
#			 filter(Address.email_address=='jack@google.com').\
#			 all():	  
#	 print u, a
#<User('jack','Jack Bean', 'gjffdd')> <Address('jack@google.com')>
#session.query(User).\
#		 join(Address).\
#		 filter(Address.email_address=='jack@google.com').\
#		 all() 
#for u, count in session.query(User, stmt.c.address_count).\
#	  outerjoin(stmt, User.id==stmt.c.user_id).order_by(User.id): 
#	  print u, count
#<User('ed','Ed Jones', 'f8s7ccs')> None
#session.dirty # prints changes to be made


def main_server():
	broadcaster()
	server_start()

def main_client():
	data   = status.DataManager(db_path=dbPath, ext=pycklerext)
	client = ClientTask()
	client.start()


if __name__ == '__main__':
	print __file__
	
	#http://zguide.zeromq.org/py:all
	#http://zguide.zeromq.org/py:taskwork
	#http://zguide.zeromq.org/py:tasksink
	#https://github.com/imatix/zguide/tree/master/examples/Python

	if  os.path.basename( __file__ ) in [ 'server.py' ]:
		main_server()
	
	elif os.path.basename( __file__ ) in [ 'client.py' ]:
		main_client()
