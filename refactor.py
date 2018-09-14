#! /usr/bin/python

import os

if __name__ == '__main__':
	cur_path = os.path.dirname(os.path.realpath(__file__))
	for dirName, subdirList, fileList in os.walk(cur_path):
		for fileName in fileList:
			if fileName.endswith(".go"):
				real_path = os.path.join(dirName, fileName)
				content = None
				with open(real_path, "r") as f:
					content = f.read()
				content = content.replace("github.com/google/syzkaller", "github.com/CvvT/syzkaller")
				with open(real_path, "w") as f:
					f.write(content)
