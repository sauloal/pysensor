#!/usr/bin/python
import sys, os
import time

print "importing unicodedata"
import unicodedata

print "importing psutil"
import psutil

print "importing netifaces"
import netifaces

print "importing inpect"
from inspect import isfunction

forbidden = []

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


class Network(Base):
	def __init__(self, *args):
		if	 len(args) == 1:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
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
			
			nd      = Network_devices(	net,
										netdata.bytes_sent  , netdata.bytes_recv, 
										netdata.packets_sent, netdata.packets_recv, 
										netdata.errin       , netdata.errout, 
										netdata.dropin      , netdata.dropout,
										mac					, ip
										)
			
			self.net_devices.append( nd )	

	def init_base(self, net_devices):
		self.net_devices = net_devices

	def __repr__(self):
		# print ( self.id, self.ltime, self.device, self.mountpoint, self.fstype, self.total, self.used, self.free, self.percent )
		return "<NETWORK('%s')>" % ( str( self.net_devices ) )


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


class Process(Base):
	def __init__(self, *args):
		if	 len(args) == 1:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
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

		def init_base(self, process_info):
			self.process_info = process_info


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


