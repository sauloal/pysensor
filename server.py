#!/usr/bin/python
import sys, os
import time

#easy_install requests
#easy_install jsonpickle
#easy_install simplejson


print "importing socket"
import socket

print "importing threading"
import threading

print "importing queue"
import Queue


print "importing select"
import select

print "importing requests"
import requests

print "importing simple json"
import simplejson

print "importing jsonpickle"
import jsonpickle


print "importing hashlib"
import hashlib


print "importing status"
sys.path.insert(0, '.')
import status

print "finished importing"




setupfile    = 'setup.conf'

if not os.path.exists(setupfile):
    print "count not find setup file %s" % setupfile
    sys.exit(1)

exec( open(setupfile, 'r').read() )


jsonpickle.set_preferred_backend('simplejson')
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=1)


class broadcast_server(threading.Thread):
	def __init__(self, message):
		threading.Thread.__init__ (self)
		self.kill_received = False
		self.message       = message

	def run(self):
		my_socket = socket.socket(socket.AF_INET   , socket.SOCK_DGRAM     )
		my_socket.setsockopt(     socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		my_socket.setsockopt(     socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		my_socket.setblocking(0)
		my_socket.bind(('<broadcast>' ,PING_PORT_NUMBER))
		
		print 'starting UDP SERVER ...'
		
		while not self.kill_received:
			if self.message is not None:
				#print " sending to UDP client", self.message
				my_socket.sendto(self.message, ('<broadcast>' ,PING_PORT_NUMBER))
				#my_socket.close()
			
			time.sleep( PING_INTERVAL )
		
		print 'ending UDP SERVER'


class broadcast_client(threading.Thread):
	def __init__(self, reqs):
		threading.Thread.__init__ (self)
		self.kill_received = False
		self.reqs          = reqs

	def run(self):
		my_socket = socket.socket(socket.AF_INET   , socket.SOCK_DGRAM     )
		my_socket.setsockopt(     socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		my_socket.setsockopt(     socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		my_socket.setblocking(0)
		my_socket.bind(('',PING_PORT_NUMBER))
	
		print 'starting UDP CLIENT ...'
	
		while not self.kill_received:
			ready = select.select([my_socket], [], [], PING_INTERVAL)
			
			if ready[0]:
				port , address = my_socket.recvfrom( PING_MESSAGE_SIZE )
				#data = my_socket.recv(PING_MESSAGE_SIZE)
				#print " UDP client received port %s from ip %s port %d" % ( port, address[0], address[1] )
				
				self.reqs.put( [ address[0], int(port) ] )
				
		print "ending UDP CLIENT"


class data_client(threading.Thread):
	def __init__(self, reqs, dbPath, pycklerext, myName):
		threading.Thread.__init__ (self)
		self.kill_received = False
		self.reqs          = reqs
		
		self.dbPath        = dbPath
		self.pycklerext    = pycklerext
		self.myName        = myName
		self.data          = status.DataManager(db_path=dbPath, ext=pycklerext)
		
		self.last_ip       = None
		self.last_port     = None

	def run(self):
		print 'starting DATA CLIENT ...'
		while not self.kill_received:
			if not self.reqs.empty():
				ip, port = self.reqs.get()
				print " data: got from UDP:"
				print "  ip     :",ip
				print "  port   :",port
				
				if ip   != self.last_ip:
					self.last_ip   = ip
				
				if port != self.last_port:
					self.last_port = port
			
			if ( self.last_ip is not None ) and ( self.last_port is not None ):
				mydata   = jsonpickle.encode( self.data.get_dict() )
				d        = hashlib.sha256(mydata).hexdigest()
				mydata   = d + ":" + mydata
				
				print " data: sending:"
				print " data:", mydata[:30]
				print ' data: to %s:%d'%(self.last_ip, self.last_port)
				
				try:
					response = requests.put("http://%s:%d/%s" % ( self.last_ip, self.last_port, DATA_URL ),
						   data=mydata,
						   #auth=('omer', 'b01ad0ce'),
						   headers={'content-type':'application/json'},
						   #params={'file': filepath}
						)
				
				except requests.exceptions.ConnectionError:
					print " data: connection error"
					self.last_ip   = None
					self.last_port = None
			
			time.sleep( DATA_INTERVAL )
		print 'ending DATA CLIENT'

	



def main_server(SERVER_PORT):
	#start broadcaster

	SERVER_MAC, SERVER_IP = status.getName()
	broadcast_message     = SERVER_PORT

	bserver        = broadcast_server( str(broadcast_message) )
	bserver.daemon = True
	bserver.start()	

	try:
		while True: time.sleep( 100 )

	except (KeyboardInterrupt, SystemExit):
		print "clear"

		bserver.kill_received  = True

		print "joining"
		bserver.join()

		print "bye"
		sys.exit(0)

		print "exit"



def main_client( dbPath, pycklerext, myName ):
	#start broadcaster client
	qclient        = Queue.Queue()	

	bclient        = broadcast_client( qclient )
	bclient.daemon = True
	bclient.start()

	dclient        = data_client( qclient, dbPath, pycklerext, myName )
	dclient.daemon = True
	dclient.start()

	try:
		while True: time.sleep( 100 )

	except (KeyboardInterrupt, SystemExit):
		print "clear"

		bclient.kill_received  = True
		dclient.kill_received  = True

		print "joining"
		print "joining broadcast client"
		bclient.join()
		print "joining data client"
		dclient.join()

		print "bye"
		sys.exit(0)

		print "exit"



if __name__ == '__main__':
	print __file__
	
	#http://zguide.zeromq.org/py:all
	#http://zguide.zeromq.org/py:taskwork
	#http://zguide.zeromq.org/py:tasksink
	#https://github.com/imatix/zguide/tree/master/examples/Python


	if   os.path.basename( __file__ ) in [ 'server.py' ]:
		print "server mode"
		main_server(SERVER_PORT)
	
	
	elif os.path.basename( __file__ ) in [ 'client.py' ]:
		print "client mode"
		print " - importing urllib2"
		import urllib2
	
		dbPath            = status.dbPath
		pycklerext        = status.pycklerext
		myName            = status.getName()
	
		print "  name:", myName
		main_client( dbPath, pycklerext, myName )





	
	
	
	
	
	
#class ServerTask(threading.Thread):
#	"""ServerTask"""
#	def __init__(self):
#		threading.Thread.__init__ (self)
#		self.kill_received = False
#
#	def run(self):
#		context  = zmq.Context()
#		frontend = context.socket(zmq.ROUTER)
#		frontend.bind('tcp://*:5570')
#
#		socket.setsockopt(zmq.LINGER  , 1        )
#
#		backend  = context.socket(zmq.DEALER)
#		backend.bind('inproc://backend')
#
#		workers = []
#		for i in xrange(5):
#			worker = ServerWorker(context)
#			worker.start()
#			workers.append(worker)
#
#		poll = zmq.Poller()
#		poll.register(frontend, zmq.POLLIN)
#		poll.register(backend,  zmq.POLLIN)
#
#		while not self.kill_received:
#			sockets = dict(poll.poll())
#			if frontend in sockets:
#				if sockets[frontend] == zmq.POLLIN:
#					_id = frontend.recv()
#					msg = frontend.recv()
#					print 'Server received %s id %s\n' % (msg, _id)
#					backend.send(_id, zmq.SNDMORE)
#					backend.send(msg)
#			if backend in sockets:
#				if sockets[backend] == zmq.POLLIN:
#					_id = backend.recv()
#					msg = backend.recv()
#					print 'Sending to frontend %s id %s\n' % (msg, _id)
#					frontend.send(_id, zmq.SNDMORE)
#					frontend.send(msg)
#
#		frontend.close()
#		backend.close()
#		context.term()
	
	
	
#def msreader():
#	# encoding: utf-8
#	#
#	#   Reading from multiple sockets
#	#   This version uses a simple recv loop
#	#
#	#   Author: Jeremy Avnet (brainsik) <spork(dash)zmq(at)theory(dot)org>
#	#
#
#	# Prepare our context and sockets
#	context = zmq.Context()
#
#	# Connect to task ventilator
#	receiver = context.socket(zmq.PULL)
#	receiver.connect("tcp://localhost:5557")
#
#	# Connect to weather server
#	subscriber = context.socket(zmq.SUB)
#	subscriber.connect("tcp://localhost:5556")
#	subscriber.setsockopt(zmq.SUBSCRIBE, "10001")
#
#	# Process messages from both sockets
#	# We prioritize traffic from the task ventilator
#	while True:
#
#		# Process any waiting tasks
#		while True:
#			try:
#				rc = receiver.recv(zmq.DONTWAIT)
#			except zmq.ZMQError:
#				break
#			# process task
#
#		# Process any waiting weather updates
#		while True:
#			try:
#				rc = subscriber.recv(zmq.DONTWAIT)
#			except zmq.ZMQError:
#				break
#			# process weather update
#
#		# No activity, so sleep for 1 msec
#		time.sleep(0.001)
#
#def mspooler():
#	# encoding: utf-8
#	#
#	#   Reading from multiple sockets
#	#   This version uses zmq.Poller()
#	#
#	#   Author: Jeremy Avnet (brainsik) <spork(dash)zmq(at)theory(dot)org>
#	#
#
#	# Prepare our context and sockets
#	context = zmq.Context()
#
#	# Connect to task ventilator
#	receiver = context.socket(zmq.PULL)
#	receiver.connect("tcp://localhost:5557")
#
#	# Connect to weather server
#	subscriber = context.socket(zmq.SUB)
#	subscriber.connect("tcp://localhost:5556")
#	subscriber.setsockopt(zmq.SUBSCRIBE, "10001")
#
#	# Initialize poll set
#	poller = zmq.Poller()
#	poller.register(receiver, zmq.POLLIN)
#	poller.register(subscriber, zmq.POLLIN)
#
#	# Process messages from both sockets
#	while True:
#		socks = dict(poller.poll())
#
#		if receiver in socks and socks[receiver] == zmq.POLLIN:
#			message = receiver.recv()
#			# process task
#
#		if subscriber in socks and socks[subscriber] == zmq.POLLIN:
#			message = subscriber.recv()
#			# process weather update
#
#def sink():
#	# Task sink
#	# Binds PULL socket to tcp://localhost:5558
#	# Collects results from workers via that socket
#	#
#	# Author: Lev Givon <lev(at)columbia(dot)edu>
#
#
#	context = zmq.Context()
#
#	# Socket to receive messages on
#	receiver = context.socket(zmq.PULL)
#	receiver.bind("tcp://*:5558")
#
#	# Wait for start of batch
#	s = receiver.recv(zmq.DONTWAIT)
#
#	# Start our clock now
#	tstart = time.time()
#
#	# Process 100 confirmations
#	total_msec = 0
#	for task_nbr in range(100):
#		s = receiver.recv()
#		if task_nbr % 10 == 0:
#			sys.stdout.write(':')
#		else:
#			sys.stdout.write('.')
#
#	# Calculate and report duration of batch
#	tend = time.time()
#	print "Total elapsed time: %d msec" % ((tend-tstart)*1000)
#
#def worker():
#	# Task worker
#	# Connects PULL socket to tcp://localhost:5557
#	# Collects workloads from ventilator via that socket
#	# Connects PUSH socket to tcp://localhost:5558
#	# Sends results to sink via that socket
#	#
#	# Author: Lev Givon <lev(at)columbia(dot)edu>
#
#
#	context = zmq.Context()
#
#	# Socket to receive messages on
#	receiver = context.socket(zmq.PULL)
#	receiver.connect("tcp://localhost:5557")
#
#	# Socket to send messages to
#	sender = context.socket(zmq.PUSH)
#	sender.connect("tcp://localhost:5558")
#
#	# Process tasks forever
#	while True:
#		s = receiver.recv(zmq.DONTWAIT)
#
#		# Simple progress indicator for the viewer
#		sys.stdout.write('.')
#		sys.stdout.flush()
#
#		# Do the work
#		time.sleep(int(s)*0.001)
#
#		# Send results to sink
#		sender.send('')






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

