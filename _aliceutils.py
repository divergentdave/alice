# Copyright (c) 2014 Thanumalayan Sankaranarayana Pillai. All Rights Reserved.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import argparse
import subprocess
import re
import stat

__author__ = "Thanumalayan Sankaranarayana Pillai"
__copyright__ = "Copyright 2014, Thanumalayan Sankaranarayana Pillai"
__credits__ = ["Thanumalayan Sankaranarayana Pillai", "Vijay Chidambaram",
	"Ramnatthan Alagappan", "Samer Al-Kiswany"]
__license__ = "MIT"

__aliceconfig = None
def init_aliceconfig(args):
	global current_original_path, __aliceconfig
	parser = argparse.ArgumentParser()
	parser.add_argument('--strace_file_prefix', dest = 'strace_file_prefix', type = str, default = False)
	parser.add_argument('--initial_snapshot', dest = 'initial_snapshot', type = str, default = False)
	parser.add_argument('--checker_tool', dest = 'checker_tool', type = str, default = False)
	parser.add_argument('--base_path', dest = 'base_path', type = str, default = False)
	parser.add_argument('--starting_cwd', dest = 'starting_cwd', type = str, default = False)
	parser.add_argument('--interesting_path_string', dest = 'interesting_path_string', type = str, default = False)
	parser.add_argument('--scratchpad_dir', dest = 'scratchpad_dir', type = str, default = '/tmp')
	parser.add_argument('--debug_level', dest = 'debug_level', type = int, default = 0)
	parser.add_argument('--ignore_ioctl', dest = 'ignore_ioctl', type = list, default = [])
	parser.add_argument('--ignore_mmap', dest = 'ignore_mmap', type = bool, default = False)
	parser.add_argument('--ignore_stacktrace', dest = 'ignore_stacktrace', type = bool, default = False)

	__aliceconfig = parser.parse_args('')
	for key in __aliceconfig.__dict__:
		if key in args:
			__aliceconfig.__dict__[key] = args[key]
		

	assert __aliceconfig.strace_file_prefix != False
	assert __aliceconfig.initial_snapshot != False
	assert __aliceconfig.base_path != False and __aliceconfig.base_path.startswith('/')
	if __aliceconfig.base_path.endswith('/'):
		__aliceconfig.base_path = __aliceconfig.base_path[0 : -1]

	if __aliceconfig.interesting_path_string == False:
		__aliceconfig.interesting_path_string = r'^' + __aliceconfig.base_path

	if 'starting_cwd' not in __aliceconfig.__dict__ or __aliceconfig.starting_cwd == False:
		__aliceconfig.starting_cwd = __aliceconfig.base_path
	
	assert __aliceconfig.scratchpad_dir != False

def aliceconfig():
	return __aliceconfig


def get_path_inode_map(directory):
	result = {}
	directory = directory.rstrip("/")
	top_stat = os.lstat(directory)
	result[directory] = (top_stat.st_ino, 'd')
	for dirpath, dirnames, filenames in os.walk(directory):
		for dirname in dirnames:
			path = os.path.join(dirpath, dirname)
			dir_stat = os.lstat(path)
			result[path] = (dir_stat.st_ino, 'd')
		for filename in filenames:
			path = os.path.join(dirpath, filename)
			file_stat = os.lstat(path)
			assert stat.S_ISREG(file_stat.st_mode)
			result[path] = (file_stat.st_ino, 'f')
	return result


def colorize(s, i):
	return '\033[00;' + str(30 + i) + 'm' + s + '\033[0m'

def coded_colorize(s, s2 = None):
	colors=[1,3,5,6,11,12,14,15]
	if s2 == None:
		s2 = s
	return colorize(s, colors[hash(s2) % len(colors)])

def colors_test(fname):
	f = open(fname, 'w')
	for i in range(0, 30):
		f.write(colorize(str(i), i) + '\n')
	f.close()

def short_path(name):
	if not __aliceconfig or not name.startswith(__aliceconfig.base_path):
		return name
	return name.replace(re.sub(r'//', r'/', __aliceconfig.base_path + '/'), '', 1)

# The input parameter must already have gone through original_path()
def initial_path(name):
	if not name.startswith(__aliceconfig.base_path):
		return False
	toret = name.replace(__aliceconfig.base_path, __aliceconfig.initial_snapshot + '/', 1)
	return re.sub(r'//', r'/', toret)

# The input parameter must already have gone through original_path()
def replayed_path(name):
	if not name.startswith(__aliceconfig.base_path):
		return False
	toret = name.replace(__aliceconfig.base_path, __aliceconfig.scratchpad_dir + '/', 1)
	return re.sub(r'//', r'/', toret)

def safe_string_to_int(s):
	try:
		if len(s) >= 2 and s[0:2] == "0x":
			return int(s, 16)
		elif s[0] == '0':
			return int(s, 8)
		return int(s)
	except ValueError as err:
		print s
		raise err

def is_interesting(path):
	return re.search(aliceconfig().interesting_path_string, path)

def writeable_toggle(path, mode = None):
	if mode == 'UNTOGGLED':
		return
	elif mode != None:
		os.chmod(path, mode)
	if os.access(path, os.W_OK):
		return 'UNTOGGLED'
	if not os.access(path, os.W_OK):
		old_mode = os.stat(path).st_mode
		os.chmod(path, 0777)
		return old_mode
