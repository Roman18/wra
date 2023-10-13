#!/usr/bin/env python3

import sys
import os
import socket

import argparse

import re
import json
from subprocess import Popen, PIPE



class Whois_Action:

	"""
	Class serves as container of methods
	"""

	@staticmethod
	def get_item_by_pattern(regex: str, output: str) -> str:
		return re.search(f"{regex}(.+)", output).group(1)

	@staticmethod
	def get_domains_list(domain_list: str) -> list:

		if not os.path.isfile(domain_list):
			raise FileExistsError("Domain list file does not exist")
		
		ds = list()
		with open(domain_list, 'r') as f:
			ds = f.readlines()
		return ds
	
	@staticmethod
	def write_to_dest(whois_info: dict, args: argparse.Namespace) -> None:

		file = sys.stdout

		if args.output:
			file = open(args.output, "a")
		
		if args.format == "json":
			print(json.dumps(whois_info), file=file)

		elif args.format == "txt":
			for k, v in whois_info.items():
				if v != "":
					print(f'{k} {v}', file=file)
		
		if file != sys.stdout:
			file.close()

	@staticmethod
	def get_whois_info(domain: str) -> dict:
		ip = Whois_Action.get_ip_by_name(domain)

		p = Popen(['whois', ip], stdin=PIPE, stdout=PIPE, stderr=PIPE)

		output, err = p.communicate()

		if p.returncode != 0:
			raise Exception(f"Could not make whois request. {err.decode()}")
		
		res = {"domain:": domain, "ip:": ip, "inetnum:":"", "route:": "", "origin:": "", 
				"netname:":"", "country:":"","netrange:": "", 
				"cidr:":"", "originas:": "", "organization:":""}
		
		output = output.decode().lower()
		for key in res.keys():
			try:
				val = Whois_Action.get_item_by_pattern(key, output).strip()
				if val:
					res[key] = val
			except:
				continue

		res = dict(filter(lambda item: item[1] != '', res.items()))
		return res
	
	@staticmethod
	def get_ip_by_name(domain: str) -> str:
		try:
			return socket.gethostbyname(domain)
		except Exception as e:
			raise Exception(f"Domain not known: {domain}")
		
def usage() -> None:
	sys.stderr.write(f"Wrong argument\nTo get help: {sys.argv[0]} -h\n")
	sys.exit(-1)

def parse_args() -> argparse.Namespace:
	args = argparse.ArgumentParser(description='Make WHOIS requests and then output the result in the different formats')
	args.add_argument('-d', '--domain', help='domain name')
	args.add_argument('-D', '--domains', help='domains of list where each domain separated by newline')
	args.add_argument('-o', '--output', help='Output filename')
	args.add_argument('-f', '--format', default='txt', choices=['txt', 'json'], help='Output format')

	return args.parse_args()
	
def main(args: argparse.Namespace):
	domains = []

	if args.domain:
		domains.append(args.domain)
	elif args.domains:
		domains.extend(Whois_Action.get_domains_list(args.domains))
	else:
		usage()
	
	domains = list(map(lambda x: x.strip(), domains))
	for domain in domains:
		whois_info = Whois_Action.get_whois_info(domain)
		Whois_Action.write_to_dest(whois_info, args)
	

if __name__ == '__main__':
	args = parse_args()

	try:
		main(args)
	except Exception as e:
		sys.stderr.write(f'{str(e)}\n')
		sys.exit(-1)
	else:
		sys.exit(0)