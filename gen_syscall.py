#! /usr/bin/python

with open("syscall.txt", "r") as f:
	syscalls = list()
	for line in f.readlines():
		syscalls.append('"' + line.lower().strip() + '"')
	print(','.join(syscalls))