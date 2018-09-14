#! /usr/bin/python

import os

def refactor(filepath):
	content = None
	with open(filepath, "r") as f:
		content = f.read()
	content = content.replace("github.com/google/syzkaller", "github.com/CvvT/syzkaller")
	with open(filepath, "w") as f:
		f.write(content)

if __name__ == '__main__':
	cur_path = os.path.dirname(os.path.realpath(__file__))
	for dirName, subdirList, fileList in os.walk(cur_path):
		for fileName in fileList:
			if fileName.endswith(".go"):
				real_path = os.path.join(dirName, fileName)
				refactor(real_path)

	real_path = os.path.join(cur_path, "Makefile")
	refactor(real_path)
