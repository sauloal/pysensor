#!/usr/bin/python
import sys, os
import time

#easy_install flask
#easy_install jsonpickle
#easy_install simplejson

print "importing signal"
import signal

print "importing cpickle"
import cPickle

print "importing simple json"
import simplejson

print "importing jsonpickle"
import jsonpickle

print "importing hashlib"
import hashlib

print "importing flask"
from flask       import Flask, request, session, g, redirect, url_for, abort, render_template, flash, make_response, jsonify, Markup, Response, send_from_directory, Blueprint
from jinja2      import TemplateNotFound

print "importing status"
sys.path.insert(0, '.')
import status


setupfile    = 'setup.conf'

if not os.path.exists(setupfile):
    print "count not find setup file %s" % setupfile
    sys.exit(1)

exec( open(setupfile, 'r').read() )

DATA_URL_PATH = "/%s" % DATA_URL
dbPath         = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), SERVER_DB)

#VARIABLES
app                = Flask(__name__)
app.config.from_object(__name__)
app.jinja_env.globals['trim_blocks'       ] = True
app.jinja_env.add_extension('jinja2.ext.do')


jsonpickle.set_preferred_backend('simplejson')
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=1)


data = None

@app.before_request
def before_request():
	"""
	before each request, add global variables to the global G variable.
	If using WSGI (eg. apache), this won't work
	"""

	init_classes()


def init_classes():
	"""
	reads the data from the disk, parses and loads it to global variables.
	has to be changed if using WSGI servers aroung it (eg. apache) once global variables
	are not shared.
	"""

	global data

	if data is None:
		with app.app_context():
			print "initializing db"

			data = status.DataManager( db_path=dbPath, ext=pycklerext )
	
			print "db loaded"



# ===== API TO SLAVE =====
@app.route(DATA_URL_PATH, methods=['PUT'])
def master_register_node():
	print "registering node"

	begin       = request.data.find( ':' )
	if begin == -1:
		print "no hash found"
		abort(404)
		
	mydata      = request.data[begin+1:     ]
	sent_hash   = request.data[       :begin]
	got_hash    = hashlib.sha256(mydata).hexdigest()

	if sent_hash == got_hash:
		print "hashs are the same"
		
	else:
		print "different hashes. error in transmission"
		print "'%s'" % sent_hash
		print "'%s'" % got_hash
		print "mydata"
		print mydata
		abort(404)

	print mydata[:100]
	client_info = jsonpickle.decode( mydata )
	
	for k in client_info:
		nfo = client_info.pop( k )
		client_info[ float(k) ] = nfo
	
	data.add( client_info )
	
	return 'OK'

@app.route("/options", methods=['OPTIONS'])
def master_get_options():
	return jsonpickle.encode(	{
									DATA_URL_PATH : "Add data to the database"
								}
							)


def main():
	app.debug = True
	app.run(port=SERVER_PORT, host='0.0.0.0')



if __name__ == '__main__':
	main()
