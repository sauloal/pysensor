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


print "importing flask"
from flask       import Flask, request, session, g, redirect, url_for, abort, render_template, flash, make_response, jsonify, Markup, Response, send_from_directory, Blueprint
from jinja2      import TemplateNotFound

print "importing status"
sys.path.insert(0, '.')
import status


setupfile    = 'setup.json'

if not os.path.exists(setupfile):
    print "count not find setup file %s" % setupfile
    sys.exit(1)

for k,v in jsonpickle.decode(open(setupfile, 'r').read()).items():
    print "SETUP K %s V %s" % (k, v)
    globals()[k] = v


#VARIABLES
app                = Flask(__name__)
app.config.from_object(__name__)
app.jinja_env.globals['trim_blocks'       ] = True
app.jinja_env.add_extension('jinja2.ext.do')


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

	if requester is None or server is None:
		with app.app_context():
			print "initializing db"

			data = status.DataManager( db_path=dbPath, ext=pycklerext )
	
			print "db loaded"



# ===== API TO SLAVE =====
@app.route("/%s"%DATA_URL, methods=['PUT'])
def master_register_node():
    print "registering node"
    client_info = jsonpickle.decode( request.data )
    data.add( client_info )
    return 'OK'

@app.route("/options", methods=['OPTIONS'])
def master_get_options():
    return jsonpickle.encode(	{
									"/%s" % DATA_URL : "Add data to the database"
								}
							)


def main():
    app.run(port=SERVER_PORT)
   


if __name__ == '__main__':
    main()