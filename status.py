#!/usr/bin/python
import sys, os
import time
import shutil
from pprint  import pprint     as pp


print "importing netifaces"
import netifaces

print "importing cpickle"
import cPickle

print "importing simple json"
import simplejson

print "importing jsonpickle"
import jsonpickle

print "finished importing"

#apt-get install python-pip
#apt-get install python-dev

#easy_install psutil
#easy_install netifaces


# NOT NECESSARY ANYMORE
#apt-get install libzmq-dev
#easy_install pyzmq

setupfile    = 'setup.json'

if not os.path.exists(setupfile):
    print "count not find setup file %s" % setupfile
    sys.exit(1)

for k,v in jsonpickle.decode(open(setupfile, 'r').read()).items():
    print "SETUP K %s V %s" % (k, v)
    globals()[k] = v


dbPath         = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), dbname)
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


utime     = time.time()
myName    = None



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


class Data_structure(object):
	def __init__(self, *args):
		if	 len(args) == 5:
			self.init_base(*args)

		elif len(args) == 0:
			self.init_self(*args)

		else:
			print "wrong number of arguments: %d" % len(args)
			sys.exit( 1 )

	def init_self(self):
		if __name__ == '__main__':
			import ps
			self.memories  = ps.Memory().get_dict()
			self.cpus      = ps.Cpu().get_dict()
			self.disks     = ps.Disk().get_dict()
			self.networks  = ps.Network().get_dict()
			self.processes = ps.Process().get_dict()
		else:
			self.memories  = None
			self.cpus      = None
			self.disks     = None
			self.networks  = None
			self.processes = None
		
	def init_base(self, memories, cpus, disks, networks, processes):
		# print "init_base %f %s" % (ltime, net_devices)
		self.memories  = memories
		self.cpus      = cpus
		self.disks     = disks
		self.networks  = networks
		self.processes = processes

	def get_fields(self):
		# return self.__dict__.keys()
		# return ['ltime', 'my_name', 'memories', 'cpus', 'disks', 'networks', 'processes']
		return ['memories', 'cpus', 'disks', 'networks', 'processes']
	
	def get_dict(self):
		res = {}
		
		for key in self.get_fields():
			val      = getattr( self, key )
			res[key] = val

		return res

	def __repr__(self):
		return "<DATASTRUCT('%s', '%s', '%s', '%s', '%s')>" % ( self.memories, self.cpus, self.disks, self.networks, self.processes )


class DataManager(object):
	def __init__(self, db_path=dbPath, ext=pycklerext, echo=False):
		print "      DataManager: loading engine"
		
		self.db_path   = db_path
		self.ext       = ext
		self.pickler   = pickler(self.db_path, ext)
		self.data      = None
		self.db        = {}
		self.qry       = None
		
		if not os.path.exists( self.db_path ):
			print "      DataManager: creating database", self.db_path
			os.makedirs( self.db_path )
		else:
			print "      DataManager: database exists", self.db_path

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
			srcfile  = os.path.join(self.db_path, filename)
			if deleteoldfiles:
				os.remove( srcfile )
				
			else:
				dstfile = srcfile + '.bkp'
				shutil.move( srcfile, dstfile )
		
		print "      moved %4d/%4d files" % ( scount, count )

	def gen_key(self, utime, myName):
		key = "%.2f@%s" % ( utime, myName )
		return key

	def update(self):
		#TODO: FIX UTIME
		#      ONLY RELOAD WHAT YOU DONT ALREADY HAVE
		#      DELETE FROM MEMORY WHAT DOES NOT EXISTS ANYMORE
		self.clean()
		
		global utime
		utime     = time.time()
		
		print "      DataManager: utime", utime, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
		print "      DataManager: creating data structure"
		
		self.data = Data_structure()
		
		print "      DataManager: adding data"

		key = self.gen_key( utime, myName )
		#key = (myName, utime)
		#key = utime
		
		print "      DataManager: key",key
		
		dic = self.data.get_dict()
		self.pickler.save( key, dic )

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
		
		files.sort( key=lambda x: x[1], reverse=True )
		
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
		#TODO: ONLY LOAD IF NOT IN MEMORY
		for fn,utime,my_name in files:
			if utime not in self.db: self.db[ utime ] = {}
			
			if ( utime in self.db ) and ( my_name in self.db[ utime ] ):
					continue
				
			else:
				print "        DataManager: loading fn:",fn,"time:",utime,"name:",my_name
			
				try:
					self.db[ utime ][ my_name ] = self.pickler.load( fn )
	
				except EOFError:
					try:
						shutil.move(fn, fn + '.err')
						
					except IOError:
						pass

		for utime in self.db.keys():
			for my_name in self.db[ utime ].keys():
				key = self.gen_key( utime, my_name )
				
				fn  = self.pickler.getFn( key )
				
				if not os.path.exists( fn ):
					self.db[ utime ].pop( my_name )
			
			if len( self.db[ utime ] ) == 0:
				self.db.pop( utime )

		print "      DataManager: done. length:", len(self.db)

		return self.db

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
		ip  = None
		for net in sorted(nets):
			netdata = nets[ net ]
			
			ifdata = netifaces.ifaddresses(net)
			mac    = ifdata[netifaces.AF_LINK][0]['addr']
			ip     = ifdata[2                ][0]['addr']

			if mac != '00:00:00:00:00:00':
				break
		
		if mac is None:
			print "NO MAC FOUND"
			sys.exit( 1 )
		
		with open(myNameFile, 'w') as fhd:
			fhd.write("%s\n%s" % (mac, ip))
	
	mac = None
	ip  = None
	with open(myNameFile, 'r') as fhd:
		mac = fhd.readline().strip()
		ip  = fhd.readline().strip()
	
	if mac is None or len(mac) != 17:
		print "not able to get MAC", mac
		sys.exit(1)
		
	return [mac, ip]


def main_client():
	#http://docs.sqlalchemy.org/en/rel_0_8/orm/tutorial.html
	
	global myName
	print "  getting name"
	myName = getName()[0]
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

