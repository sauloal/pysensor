#!/usr/bin/python
import sys, os
import time
import unicodedata
import shutil
from pprint  import pprint     as pp
from inspect import isfunction

print "importing psutil"
import psutil
print "importing netifaces"
import netifaces

print "importing cpyckle"
import cPickle
pycklerext = '.cpyc'
print "finished importing"

test           = False
numReport      = 2
myNameFile     = '.status'

dbPath         = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "status.cdb")
deleteoldest   = False # delete files older than the max age
deleteoldfiles = False # delete files or move them
def_min        = 60
def_hour       = 60 * def_min  # 1 hour
def_day        = 24 * def_hour # 1 day
# at a rate of 1 per minute: 60 * 24 = 1440
maxages      = { # 842 in total
	'1h' : [ 1 * def_hour,   2 * def_min ], # older than  1 hour, saves every  2 min
	'2h' : [ 2 * def_hour,   2 * def_min ], # older than  1 hour, saves every  2 min
	'4h' : [ 4 * def_hour,   3 * def_min ], # older than  1 hour, saves every  2 min
	'1d' : [ 1 * def_day ,   5 * def_min ], # older than  1 day , saves every  5 min   (288 per day *  1 = 288)
	'3d' : [ 3 * def_day ,  10 * def_min ], # older than  3 days, saves every 10 min   (144 per day *  2 = 288)
	'5d' : [ 5 * def_day ,  50 * def_min ], # older than  5 days, saves every 30 min   ( 48 per day *  2 =  96)
	'10d': [10 * def_day ,       def_hour], # older than 10 days, saves every  1 hour  ( 24 per day *  5 = 120)
	'20d': [20 * def_day ,   4 * def_hour], # older than 20 days, saves every  4 hours (  5 per day * 10 =  50)
} # number of minutes: time
# 1440 + 842 = 2282
# 2282 * 28k = 60.4Mb

#apt-get install python-pip
#apt-get install python-dev
#apt-get install libzmq-dev

#easy_install psutil
#easy_install netifaces
#easy_install pyzmq


utime     = time.time()
myName    = None
forbidden = []

class pickler(object):
	def __init__(self, db_path, ext):
		self.db_path = db_path
		self.ext     = ext
	
	def getFn(self, key):
		if not key.endswith(self.ext):
			key += self.ext
		if not key.startswith(self.db_path):
			key = os.path.join( self.db_path, key)
		return key
	
	def save(self, key, data):
		fn = self.getFn(key)
		print "       Pickler. saving to:",fn
		with open(fn, 'wb') as fhd:
			cPickle.dump(data, fhd)
	
	def load(self, key):
		fn = self.getFn(key)
		print "       Pickler. loading from:",fn
		data = None
		with open(fn, 'rb') as fhd:
			data = cPickle.load(fhd)
		return data

class Base(object):
	def get_fields(self):
		# print "table name", self.__table__
		keys = []
		for x in dir( self ):
			if x[0] == '_'                : continue
			if x in forbidden             : continue
			y = getattr(self, x)
			if hasattr(y, '__call__')     : continue
			if isfunction(y)              : continue
			if '__main__.' in str(type(y)): continue
	
			keys.append(x)
			
		return keys
	
	def get_dict(self):
		res = {}

		for key in self.get_fields():
			val     = getattr( self, key )
			valtype = str(type( val ))
			#print "key",key,"val",val,"type",str(type( val ))
	
			if valtype.startswith("<class "):
				#print "getting dict",valtype
				val  = val.get_dict()
	
			elif valtype == "<type 'unicode'>":
				#print "fixing unicode"
				val  = unicodedata.normalize('NFKD', val).encode('ascii','ignore')
	
			elif valtype == "<type 'list'>":
				#print "getting dict list"
				for p in range( len(val) ):
					valp     = val[p]
					valtypep = str(type(valp))
					if valtypep.startswith("<class "):
						valp   = valp.get_dict()
					elif valtype == "<type 'unicode'>":
						#print "fixing unicode"
						valp = unicodedata.normalize('NFKD', valp).encode('ascii','ignore')
					
					val[p]   = valp
	
			else:
				#print "passing through"
				pass
	
			res[ key ] = val
	
		return res
	
		pass

class Memory(Base):
	def __init__(self, *args):
		if	 len(args) == 9:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
		# print "init_self"
		vmem           = psutil.virtual_memory()
		#vmem(total=392007680L, available=129564672L, percent=66.9, used=381054976L, 
		#free=10952704L, active=171753472, inactive=182312960, buffers=23056384L, cached=95555584)
		self.total     = vmem.total
		self.available = vmem.available
		self.percent   = vmem.percent
		self.used      = vmem.used
		self.free      = vmem.free
		self.active    = vmem.active
		self.inactive  = vmem.inactive
		self.buffers   = vmem.buffers
		self.cached    = vmem.cached

	def init_base(self, total, available, percent, used, free, active, inactive, buffers, cached):
		# print "init_base %f %d %d" % (ltime, free, used)
		self.total     = total
		self.available = available
		self.percent   = percent
		self.used      = used
		self.free      = free
		self.active    = active
		self.inactive  = inactive
		self.buffers   = buffers
		self.cached		= cached

	def __repr__(self):
		return "<Memory('%d', '%d', '%f', '%d', '%d', '%d', '%d', '%d', '%d')>" % ( self.total, self.available, self.percent, self.used, self.free, self.active, self.inactive, self.buffers, self.cached )

class Cpu(Base):
	def __init__(self, *args):
		if	 len(args) == 10:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
		# print "init_self"
		cputimes      = psutil.cpu_times()
		numCpu        = psutil.NUM_CPUS
		cpuPerc       = psutil.cpu_percent(percpu=True)
		cpuPerc       = ",".join([str(x) for x in cpuPerc])
		#cputimes(user=3961.46, nice=169.729, system=2150.659, idle=16900.540, iowait=629.509, irq=0.0, softirq=19.422)
		
		self.user      = cputimes.user
		self.nice      = cputimes.nice
		self.system    = cputimes.system
		self.idle      = cputimes.idle
		self.iowait    = cputimes.iowait
		self.irq       = cputimes.irq
		self.softirq   = cputimes.softirq
		self.numCpu    = numCpu
		self.cpuPerc   = cpuPerc

	def init_base(self, user, nice, system, idle, iowait, irq, softirq, numCpu, cpuPerc):
		# print "init_base %f %f %f %f %f %f %f %f %d" % (ltime, user, nice, system, idle, iowait, irq, softirq, numCpu, cpuPerc)
		self.user      = user
		self.nice      = nice
		self.system    = system
		self.idle      = idle
		self.iowait    = iowait
		self.irq       = irq
		self.softirq   = softirq
		self.numCpu    = numCpu
		self.cpuPerc   = cpuPerc

	def __repr__(self):
		return "<CPU('%f', '%f', '%f', '%f', '%f', '%f', '%f', '%d', '%s')>" % ( self.user, self.nice, self.system, self.idle, self.iowait, self.irq, self.softirq, self.numCpu, self.cpuPerc )

class Disk(Base):
	def __init__(self, *args):
		if	 len(args) == 7:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
		# print "init_self"
		
		partitions = psutil.disk_partitions()
		self.partitions = []
		for partition in sorted(partitions, key=lambda x:x.device):
			#partition(device='/dev/sda1', mountpoint='/', fstype='ext4')
			usage = psutil.disk_usage(partition.mountpoint)
			#usage(total=21378641920, used=4809781248, free=15482871808, percent=22.5)

			self.partitions.append( Disk_partition(	partition.device,		partition.mountpoint,
													partition.fstype,		usage.total,
													usage.used,				usage.free,
													usage.percent) )
		
		diskio			    = psutil.disk_io_counters()
		#iostat(read_count=719566, write_count=1082197, read_bytes=18626220032, write_bytes=24081764352, read_time=5023392, write_time=63199568)
		self.read_count    = diskio.read_count
		self.write_count   = diskio.write_count
		self.read_bytes    = diskio.read_bytes
		self.write_bytes   = diskio.write_bytes
		self.read_time     = diskio.read_time
		self.write_time    = diskio.write_time
		
		#print "GET FIELDS", self.get_dict()

	def init_base(self, read_count, write_count, read_bytes, write_bytes, read_time, write_time, partitions):
		# print "init_base %f " % (ltime)
		self.read_count    = read_count
		self.write_count   = write_count
		self.read_bytes    = read_bytes
		self.write_bytes   = write_bytes
		self.read_time     = read_time
		self.write_time    = write_time
		self.partitions    = partitions

	def __repr__(self):
		return "<DISK('%d', '%d', '%d', '%d', '%d', '%d', '%s')>" % ( self.read_count, self.write_count, self.read_bytes, self.write_bytes, self.read_time, self.write_time, str(self.partitions) )

class Disk_partition(Base):
	def __init__(self, device, mountpoint, fstype, total, used, free, percent):
		# print "init_base %f " % (ltime)
		self.device        = device
		self.mountpoint    = mountpoint
		self.fstype        = fstype
		self.total         = total
		self.used          = used
		self.free          = free
		self.percent       = percent

	def __repr__(self):
		# print ( self.id, self.ltime, self.device, self.mountpoint, self.fstype, self.total, self.used, self.free, self.percent )
		return "<DISKPARTITION('%s', '%s', '%s', '%d', '%d', '%d', '%f')>" % ( \
				self.device, self.mountpoint, self.fstype, self.total, self.used, self.free, self.percent )

class Network_devices(Base):
	def __init__(self, 	dev_name, 
						bytes_sent, 	bytes_recv, 
						packets_sent, 	packets_recv, 
						errin, 			errout, 
						dropin, 		dropout,
						mac,			ip):
		# {'lo' : iostat(bytes_sent=799953745, bytes_recv=799953745 , packets_sent=453698 , packets_recv=453698 , errin=0, errout=0, dropin=0, dropout=0), 
		# print "init_base %f " % (ltime)
		self.dev_name     = dev_name
		self.bytes_sent   = bytes_sent
		self.bytes_recv   = bytes_recv
		self.packets_sent = packets_sent
		self.packets_recv = packets_recv
		self.errin        = errin
		self.errout       = errout
		self.dropin       = dropin
		self.dropout      = dropout
		self.mac          = mac
		self.ip           = ip

	def __repr__(self):
		return "<NETWORKDEVICES('%s', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s')>" % ( self.dev_name, self.bytes_sent, self.bytes_recv, self.packets_sent, self.packets_recv, self.errin, self.errout, self.dropin, self.dropout, self.mac, self.ip )

class Process_info(Base):
	def __init__(self,	procnum,
						name,						exe,						cwd,
						cmdline,					status,						username,
						create_time,				uids_real,					uids_effective,
						uids_saved,					gids_real,					gids_effective,
						gids_saved,					cpu_times_user,				cpu_times_system,
						cpu_affinity,				memory_percent,				mem_info_rss,
						mem_info_vms,				mem_info_shared,			mem_info_text,
						mem_info_lib,				mem_info_data,				mem_info_dirty,
						io_counters_read_count,		io_counters_write_count,	io_counters_read_bytes,
						io_counters_write_bytes,	nice,						num_threads,
						num_fds
						):

		self.procnum                 = procnum
		self.name                    = name
		self.exe                     = exe
		self.cwd                     = cwd
		self.cmdline                 = cmdline
		self.status                  = status
		self.username                = username
		self.create_time             = create_time
		self.uids_real               = uids_real
		self.uids_effective          = uids_effective
		self.uids_saved              = uids_saved
		self.gids_real               = gids_real
		self.gids_effective          = gids_effective
		self.gids_saved              = gids_saved
		self.cpu_times_user          = cpu_times_user
		self.cpu_times_system        = cpu_times_system
		self.cpu_affinity            = cpu_affinity
		self.memory_percent          = memory_percent
		self.mem_info_rss            = mem_info_rss
		self.mem_info_vms            = mem_info_vms 
		self.mem_info_shared         = mem_info_shared
		self.mem_info_text           = mem_info_text
		self.mem_info_lib            = mem_info_lib
		self.mem_info_data           = mem_info_data
		self.mem_info_dirty          = mem_info_dirty
		self.io_counters_read_count  = io_counters_read_count
		self.io_counters_write_count = io_counters_write_count
		self.io_counters_read_bytes  = io_counters_read_bytes
		self.io_counters_write_bytes = io_counters_write_bytes
		self.nice                    = nice
		self.num_threads             = num_threads
		self.num_fds                 = num_fds

	def __repr__(self):
		res_str = []
		for val in 	self.procnum,\
					self.name,						self.exe,						self.cwd,\
					self.cmdline,					self.status,					self.username,\
					self.create_time,				self.uids_real,					self.uids_effective,\
					self.uids_saved,				self.gids_real,					self.gids_effective,\
					self.gids_saved,				self.cpu_times_user,			self.cpu_times_system,\
					self.cpu_affinity,				self.memory_percent,			self.mem_info_rss,\
					self.mem_info_vms,				self.mem_info_shared,			self.mem_info_text,\
					self.mem_info_lib,				self.mem_info_data,				self.mem_info_dirty,\
					self.io_counters_read_count,	self.io_counters_write_count,	self.io_counters_read_bytes,\
					self.io_counters_write_bytes,	self.nice,						self.num_threads,\
					self.num_fds:
			try:
				res_str.append( "'%s'" % val )
			except:
				try:
					res_str.append( "'%f'" % val )
				except:
					res_str.append( "'%d'" % val )
			
		return "<PROCESSINFO(%s)>" % ( " ".join( res_str ) )

class Data_structure(Base):
	def __init__(self, *args):
		if	 len(args) == 5:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
		self.memories = Memory()
		self.cpus     = Cpu()
		self.disks    = Disk()
		# self.networks.append(  Network() )
		# self.processes.append( Process() )
		self.Network()
		self.Process()
		
	def init_base(self, memories, cpus, disks, net_devices, process_info):
		# print "init_base %f %s" % (ltime, net_devices)
		self.memories     = memories
		self.cpus         = cpus
		self.disks        = disks
		self.net_devices  = net_devices
		self.process_info = process_info

	def get_fields(self):
		# return self.__dict__.keys()
		# return ['ltime', 'my_name', 'memories', 'cpus', 'disks', 'networks', 'processes']
		return ['memories', 'cpus', 'disks', 'net_devices', 'process_info']
	
	def Network(self):
		# print "init_self"

		nets   = psutil.network_io_counters(pernic=True)
		# {'lo' : iostat(bytes_sent=799953745, bytes_recv=799953745 , packets_sent=453698 , packets_recv=453698 , errin=0, errout=0, dropin=0, dropout=0), 
		# 'eth0': iostat(bytes_sent=734324837, bytes_recv=4163935363, packets_sent=3605828, packets_recv=4096685, errin=0, errout=0, dropin=0, dropout=0)}
		
		self.net_devices = []
		for net in sorted(nets):
			netdata = nets[ net ]
			
			ifdata  = netifaces.ifaddresses(net)
			mac     = ifdata[netifaces.AF_LINK][0]['addr']
			ip      = ifdata[2                ][0]['addr']
			
			nd = Network_devices( 	net,
									netdata.bytes_sent  , netdata.bytes_recv, 
									netdata.packets_sent, netdata.packets_recv, 
									netdata.errin       , netdata.errout, 
									netdata.dropin      , netdata.dropout,
									mac					, ip)
			self.net_devices.append( nd )
	
	def Process(self):
		# print "init_self"
		pces   = psutil.get_pid_list()
		# [1, 2, 3, 4, 5, 6, 7, 46
		
		self.process_info = []
		
		for procnum in sorted(pces):
			try:
				procinfo            = psutil.Process(procnum)
			except:
				continue
			
			name                    = procinfo.name
			
			try:
				exe                 = procinfo.exe
			except:
				exe                 = ""
				
			try:
				cwd                 = procinfo.getcwd()
			except:
				cwd                 = ""
				
			cmdline                 = procinfo.cmdline
			cmdline                 = " ".join( cmdline )
			status                  = str(procinfo.status)
			username                = procinfo.username
			create_time             = procinfo.create_time
			uids                    = procinfo.uids
			uids_real               = uids.real
			uids_effective          = uids.effective
			uids_saved              = uids.saved
			gids                    = procinfo.gids
			gids_real               = gids.real
			gids_effective          = gids.effective
			gids_saved              = gids.saved
			cpu_times               = procinfo.get_cpu_times()
			cpu_times_user          = cpu_times.user
			cpu_times_system        = cpu_times.system
			cpu_affinity            = procinfo.get_cpu_affinity()
			cpu_affinity            = ",".join([ str(x) for x in cpu_affinity])
			memory_percent          = procinfo.get_memory_percent()
			mem_info                = procinfo.get_ext_memory_info()
			mem_info_rss            = mem_info.rss
			mem_info_vms            = mem_info.vms
			mem_info_shared         = mem_info.shared
			mem_info_text           = mem_info.text
			mem_info_lib            = mem_info.lib
			mem_info_data           = mem_info.data
			mem_info_dirty          = mem_info.dirty
			
			try:
				io_counters              = procinfo.get_io_counters()
				io_counters_read_count   = io_counters.read_count
				io_counters_write_count  = io_counters.write_count
				io_counters_read_bytes   = io_counters.read_bytes
				io_counters_write_bytes  = io_counters.write_bytes
				
			except:
				io_counters_read_count   = 0
				io_counters_write_count  = 0
				io_counters_read_bytes   = 0
				io_counters_write_bytes  = 0
			
			nice                         = procinfo.get_nice()
			num_threads                  = procinfo.get_num_threads()
			
			try:
				num_fds                  = procinfo.get_num_fds()
			except:
				num_fds                  = 0

			# num_ctx_switches             = procinfo.get_num_ctx_switches()
			# num_ctx_switches_voluntary   = num_ctx_switches.voluntary
			# num_ctx_switches_involuntary = num_ctx_switches.involuntary

			# try:
				# open_files               = procinfo.get_open_files()
				# open_files_path          = open_files.path
				# open_files_fd            = open_files.fd
			# except:
				# open_files_path          = ""
				# open_files_fd            = ""

			# p.get_connections()
			# [connection(fd=115, family=2, type=1, local_address=('10.0.0.1', 48776),
			# remote_address=('93.186.135.91', 80), status='ESTABLISHED'),

			# threads             = procinfo.get_threads()
			# threads_id          = thread
			# threads_user_time   = user_time
			# threads_system_time = system_time
			
			
			pi = Process_info(	procnum,
								name,						exe,						cwd,
								cmdline,					status,						username,
								create_time,				uids_real,					uids_effective,
								uids_saved,					gids_real,					gids_effective,
								gids_saved,					cpu_times_user,				cpu_times_system,
								cpu_affinity,				memory_percent,				mem_info_rss,
								mem_info_vms,				mem_info_shared,			mem_info_text,
								mem_info_lib,				mem_info_data,				mem_info_dirty,
								io_counters_read_count,		io_counters_write_count,	io_counters_read_bytes,
								io_counters_write_bytes,	nice,						num_threads,
								num_fds
								)
			self.process_info.append(pi)
	
	def __repr__(self):
		return "<DATASTRUCT('%s', '%s', '%s', '%s', '%s')>" % ( self.memories, self.cpus, self.disks, self.networks, self.processes )

class DataManager(object):
	def __init__(self, db_path=dbPath, ext=pycklerext, echo=False):
		print "      DataManager: loading engine"
		
		self.db_path   = db_path
		self.ext       = ext
		self.pickler   = pickler(self.db_path, ext)
		self.data      = None
		self.qry       = None
		
		print "      DataManager: creating database", self.db_path
		
		if not os.path.exists( self.db_path ):
			os.makedirs( self.db_path )

	def clean(self):
		files      = self.list()
		subfiles   = []
		
		maxage     = 0
		minage     = 99999999999
		maxagename = None
		minagename = None
		
		for sincename in maxages:
			since = maxages[sincename][0]
			if since > maxage:
				maxage     = since
				maxagename = sincename
				
			if since < minage:
				minage     = since
				minagename = sincename
		
		now       = time.time()
		mintime   = now - minage
		maxtime   = now - maxage
		groupings = {}
		count     = 0
		
		print 	'  minage',minage,'minagename',minagename,\
				'maxage',maxage,'maxagename',maxagename,\
				'now',now,'mintime',mintime,'maxtime',maxtime
		
		for data in files:
			count += 1
			fn, utime, my_name = data
			#print '  ',count,'fn',fn,'utime',utime,'my_name',my_name
		
			if utime > mintime:
				#print '    ',count,'utime',utime,'> mintime',mintime,'newer than mintime',minagename,'. skipping\n'
				continue
			
			if utime < maxtime:
				#print '    ',count,'utime',utime,'< maxtime',maxtime,'older than maxtime',maxagename,'.compulsory deleting'
				if deleteoldest:
					subfiles.append( data )
				continue
			
			for sincename in sorted(maxages, reverse=True, key=lambda x: maxages[x][0]):
				since = maxages[sincename][0]
				dtime = now - since
				#print '    ',count,'dtime',dtime,'sincename',sincename
				
				if utime < dtime:
					#print '      ',count,'utime',utime,'< dtime',dtime,'sincename',sincename,'appending',sincename,'\n'
					if sincename not in groupings:
						groupings[sincename] = []
					groupings[sincename].append(data)
					break
		
		for sincename in groupings:
			datas = groupings[sincename]
			since = maxages[  sincename][0]
			every = maxages[  sincename][1]
			print '    since name',sincename,'since',since,'every',every#,'datas',datas,'\n'
			
			lastdata      = datas[0]
			lastdatautime = lastdata[1]
			
			for data in sorted( datas[1:], key=lambda x: x[1], reverse=True ):
				utime = data[1]
				diff  = lastdatautime - utime
				
				if diff < every:
					#print '      data utime %.2f < lastdatautime %.2f diff %5d - deleting' % (utime, lastdatautime, diff)
					subfiles.append( data )
					
				else:
					#print '      data utime %.2f > lastdatautime %.2f diff %5d - keeping'  % (utime, lastdatautime, diff)
					lastdata      = data
					lastdatautime = data[1]
		
		dcount = 0
		scount = len(subfiles)
		for filedata in subfiles:
			filename = filedata[0]
			dcount  += 1
			#print "      %4d/%4d/%4d - moving %s to %s" % ( dcount, scount, count, filename[0], filename[0]+'.bkp' )
			srfile   = os.path.join(self.db_path, filename)
			if deleteoldfiles:
				os.remove( srfile )
			else:
				dstfile = srcfile + '.bkp'
				shutil.move( srfile, dstfile )
		
		print "      moved %4d/%4d files" % ( scount, count )

	def update(self):
		self.clean()
		
		global utime
		utime     = time.time()
		
		print "      DataManager: utime", utime, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
		print "      DataManager: creating data structure"
		
		self.data = Data_structure()
		
		print "      DataManager: adding data"

		key = "%.2f@%s" % ( utime, myName )
		#key = (myName, utime)
		#key = utime
		
		print "      DataManager: key",key
		
		dic = self.data.get_dict()
		self.pickler.save(key, dic)

		print "      DataManager: done"

	def list(self):
		files = []
		if not os.path.exists(self.db_path):
			return None
		else:
			for fn in os.listdir(self.db_path):
				if not fn.endswith( pycklerext ): continue
				utime, my_name = os.path.basename(fn).replace( pycklerext , '').split( '@' )
				files.append( [ fn, float(utime), my_name ])
		
		files.sort( key=lambda x: x[1], reverse=True)
		
		return files
	
	def count(self):
		return len(self.list())

	def loadlast(self, reps=None):
		print "      DataManager: querying. length:", reps

		count  = self.count()
		offset = 0
		
		if reps > 0:
			if  count > reps:
				#limit  = reps
				offset = count - reps
				print "      DataManager: length:", reps,"count:",count,"offset:",offset
	
			else:
				print "      DataManager: length:", reps,"count:",count


		files    = self.list()
		subfiles = files[offset:]
		return self.loadfiles( subfiles )
	
	def loadtime(self, begin=None, end=None):
		files    = self.list()
		if begin is None and end is None: return self.loadfiles( files )
		
		subfiles = []
		
		for data in files:
			fn, utime, my_name = data
			
			if begin is not None:
				if utime < begin:
					continue
				
			if end is not None:
				if utime > end  :
					continue
				
			subfiles.append( data )
			
		return self.loadfiles( subfiles )

	def loadfiles(self, files):
		currs = {}
		for fn,utime,my_name in files:
			print "        DataManager: loading fn:",fn,"time:",utime,"name:",my_name
			if utime not in currs: currs[ utime ] = {}
			currs[ utime ][ my_name ] = self.pickler.load( fn )

		print "      DataManager: done. length:", len(currs)

		return currs

	def get_dict(self, reps=None, begin=None, end=None):
		if reps is not None:
			return self.loadlast(reps=reps)
		
		else:
			return self.loadtime(begin=begin, end=end)

def getName():
	if not os.path.exists(myNameFile):
		nets   = psutil.network_io_counters(pernic=True)
		# {'lo' : iostat(bytes_sent=799953745, bytes_recv=799953745 , packets_sent=453698 , packets_recv=453698 , errin=0, errout=0, dropin=0, dropout=0), 
		# 'eth0': iostat(bytes_sent=734324837, bytes_recv=4163935363, packets_sent=3605828, packets_recv=4096685, errin=0, errout=0, dropin=0, dropout=0)}
		
		mac = None
		for net in sorted(nets):
			netdata = nets[ net ]
			
			ifdata = netifaces.ifaddresses(net)
			mac    = ifdata[netifaces.AF_LINK][0]['addr']
			if mac != '00:00:00:00:00:00':
				break
		
		if mac is None:
			print "NO MAC FOUND"
			sys.exit( 1 )
		
		with open(myNameFile, 'w') as fhd:
			fhd.write(mac)
	
	mac = None
	with open(myNameFile, 'r') as fhd:
		mac = fhd.read()
	
	if mac is None or len(mac) != 17:
		print "not able to get MAC", mac
		sys.exit(1)
		
	return mac

def main_client():
	#http://docs.sqlalchemy.org/en/rel_0_8/orm/tutorial.html
	
	global myName
	print "  getting name"
	myName = getName()
	print "  name:", myName
	
	print "  initializing"
	data   = DataManager()
	
	print "  gathering data"
	
	if test:
		for i in range(4):
			print "    adding",i
			data.update()
			
	else:
		print "    adding"
		data.update()


	if test:
		print "    loading"
		res = data.get_dict(reps=numReport)
		print "    length:", data.count(), "res:",len(res)
		print "    printing"
		#pp( res )
	
	print "  done\n"


if __name__ == "__main__":
	main_client()

